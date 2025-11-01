import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { OAuth2Client } from 'google-auth-library';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { EmailService } from '../email/email.service';
import {
  RegisterDto,
  LoginDto,
  GoogleAuthDto,
  ForgotPasswordDto,
  ResetPasswordDto,
} from './dto/auth.dto';

@Injectable()
export class AuthService {
  private googleClient: OAuth2Client;

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly emailService: EmailService,
    private readonly configService: ConfigService,
  ) {
    this.googleClient = new OAuth2Client(
      this.configService.get('GOOGLE_CLIENT_ID'),
    );
  }

  async register(registerDto: RegisterDto, session: any) {
    const { nombreCompleto, correoElectronico, telefono, contrasena } = registerDto;

    // Verificar si el correo ya está registrado
    const existingUser = await this.usersService.findByEmail(correoElectronico);
    if (existingUser) {
      throw new BadRequestException('El correo electrónico ya está registrado');
    }

    // Cifrar la contraseña
    const hashedPassword = await bcrypt.hash(contrasena, 10);

    // Generar código de verificación
    const verificationCode = Math.floor(100000 + Math.random() * 900000);

    // Guardar en sesión
    session.tempUserData = {
      nombreCompleto,
      correoElectronico,
      telefono,
      contrasena: hashedPassword,
      verificationCode,
      createdAt: Date.now(),
    };

    // Enviar email
    await this.emailService.sendVerificationEmail(
      correoElectronico,
      nombreCompleto,
      verificationCode,
    );

    return {
      message: 'Código de verificación enviado. Revisa tu correo.',
    };
  }

  async verifyEmail(code: string, session: any) {
    const tempUserData = session.tempUserData;

    if (!tempUserData) {
      throw new BadRequestException('No hay sesión activa para verificar');
    }

    // Verificar expiración (4 minutos)
    const EXPIRATION_TIME = 4 * 60 * 1000;
    if (Date.now() - tempUserData.createdAt > EXPIRATION_TIME) {
      delete session.tempUserData;
      throw new BadRequestException('El código de verificación ha expirado');
    }

    // Verificar código
    if (parseInt(code) !== tempUserData.verificationCode) {
      throw new BadRequestException('Código incorrecto');
    }

    // Verificar nuevamente que el email no se haya registrado
    const existing = await this.usersService.findByEmail(
      tempUserData.correoElectronico,
    );

    if (existing) {
      delete session.tempUserData;
      throw new BadRequestException('El correo ya está registrado');
    }

    // Crear el usuario usando el método existente
    const newUser = await this.usersService.create({
      nombreCompleto: tempUserData.nombreCompleto,
      correoElectronico: tempUserData.correoElectronico,
      telefono: tempUserData.telefono,
      contrasena: tempUserData.contrasena,
    });

    // Limpiar sesión
    delete session.tempUserData;

    return {
      message: 'Correo verificado exitosamente. Tu cuenta ha sido creada.',
      user: {
        id: newUser.id,
        nombreCompleto: newUser.nombreCompleto,
        correoElectronico: newUser.correoElectronico,
      },
    };
  }

  async resendCode(session: any) {
    const tempUserData = session.tempUserData;

    if (!tempUserData) {
      throw new BadRequestException(
        'No hay registro pendiente de verificación',
      );
    }

    // Generar nuevo código
    const verificationCode = Math.floor(100000 + Math.random() * 900000);

    // Actualizar sesión
    session.tempUserData.verificationCode = verificationCode;
    session.tempUserData.createdAt = Date.now();

    // Enviar email
    await this.emailService.sendVerificationEmail(
      tempUserData.correoElectronico,
      tempUserData.nombreCompleto,
      verificationCode,
    );

    return { message: 'Nuevo código enviado. Revisa tu correo.' };
  }

  async login(loginDto: LoginDto, session: any) {
    const { correoElectronico, contrasena } = loginDto;

    // Buscar usuario
    const user = await this.usersService.findByEmail(correoElectronico);

    if (!user) {
      throw new UnauthorizedException('Credenciales incorrectas');
    }

    // Validar contraseña usando el método del servicio
    const isMatch = await this.usersService.validatePassword(
      contrasena,
      user.contrasena,
    );

    if (!isMatch) {
      throw new UnauthorizedException('Credenciales incorrectas');
    }

    // Generar token
    const token = this.createToken(user);

    // Guardar sesión
    session.user = {
      id: user.id,
      nombreCompleto: user.nombreCompleto,
      correoElectronico: user.correoElectronico,
    };

    return {
      message: 'Inicio de sesión exitoso',
      token,
      user: {
        id: user.id,
        nombreCompleto: user.nombreCompleto,
        correoElectronico: user.correoElectronico,
      },
    };
  }

  async googleAuth(googleAuthDto: GoogleAuthDto, session: any) {
    const { googleToken } = googleAuthDto;

    try {
      // Verificar token de Google
      const ticket = await this.googleClient.verifyIdToken({
        idToken: googleToken,
        audience: this.configService.get('GOOGLE_CLIENT_ID'),
      });

      const payload = ticket.getPayload();
      
      if (!payload || !payload.email) {
        throw new BadRequestException('Token de Google inválido');
      }

      const { email, name, sub } = payload;

      // Buscar usuario existente
      let user = await this.usersService.findByEmail(email);

      if (!user) {
        // Crear nuevo usuario
        const hashedPassword = await bcrypt.hash(sub, 10);
        user = await this.usersService.create({
          nombreCompleto: name || 'Usuario',
          correoElectronico: email,
          telefono: '',
          contrasena: hashedPassword,
        });
      }

      // Generar token
      const token = this.createToken(user);

      // Guardar sesión
      session.user = {
        id: user.id,
        nombreCompleto: user.nombreCompleto,
        correoElectronico: user.correoElectronico,
      };

      return {
        message: 'Inicio de sesión con Google exitoso',
        token,
        user: {
          id: user.id,
          nombreCompleto: user.nombreCompleto,
          correoElectronico: user.correoElectronico,
        },
      };
    } catch (error) {
      throw new BadRequestException('Error en autenticación con Google');
    }
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto, session: any) {
    const { correoElectronico } = forgotPasswordDto;

    // Buscar usuario
    const user = await this.usersService.findByEmail(correoElectronico);

    if (!user) {
      throw new NotFoundException('No existe una cuenta con ese correo');
    }

    // Generar código
    const recoveryCode = Math.floor(100000 + Math.random() * 900000);

    // Guardar en sesión
    session.passwordRecovery = {
      correoElectronico,
      userId: user.id,
      recoveryCode,
      createdAt: Date.now(),
      verified: false,
    };

    // Enviar email
    await this.emailService.sendPasswordRecoveryEmail(
      correoElectronico,
      user.nombreCompleto,
      recoveryCode,
    );

    return { message: 'Código de recuperación enviado. Revisa tu correo.' };
  }

  async verifyRecoveryCode(code: string, session: any) {
    const passwordRecovery = session.passwordRecovery;

    if (!passwordRecovery) {
      throw new BadRequestException(
        'No hay solicitud de recuperación activa',
      );
    }

    // Verificar expiración (10 minutos)
    const EXPIRATION_TIME = 10 * 60 * 1000;
    if (Date.now() - passwordRecovery.createdAt > EXPIRATION_TIME) {
      delete session.passwordRecovery;
      throw new BadRequestException('El código de recuperación ha expirado');
    }

    if (parseInt(code) !== passwordRecovery.recoveryCode) {
      throw new BadRequestException('Código incorrecto');
    }

    // Marcar como verificado
    session.passwordRecovery.verified = true;

    return { message: 'Código verificado correctamente' };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto, session: any) {
    const { newPassword } = resetPasswordDto;
    const passwordRecovery = session.passwordRecovery;

    if (!passwordRecovery) {
      throw new BadRequestException(
        'No hay solicitud de recuperación activa',
      );
    }

    if (!passwordRecovery.verified) {
      throw new BadRequestException('Debes verificar el código primero');
    }

    // Verificar expiración
    const EXPIRATION_TIME = 10 * 60 * 1000;
    if (Date.now() - passwordRecovery.createdAt > EXPIRATION_TIME) {
      delete session.passwordRecovery;
      throw new BadRequestException('La sesión ha expirado');
    }

    // Hash de nueva contraseña
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Actualizar en BD usando el método del servicio
    await this.usersService.update(passwordRecovery.userId, {
      contrasena: hashedPassword,
    });

    // Obtener usuario para enviar email
    const user = await this.usersService.findOne(passwordRecovery.userId);

    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    // Enviar email de confirmación
    await this.emailService.sendPasswordChangedEmail(
      passwordRecovery.correoElectronico,
      user.nombreCompleto,
    );

    // Limpiar sesión
    delete session.passwordRecovery;

    return { message: 'Contraseña actualizada exitosamente' };
  }

  async resendRecoveryCode(session: any) {
    const passwordRecovery = session.passwordRecovery;

    if (!passwordRecovery) {
      throw new BadRequestException(
        'No hay solicitud de recuperación activa',
      );
    }

    // Generar nuevo código
    const recoveryCode = Math.floor(100000 + Math.random() * 900000);

    // Actualizar sesión
    session.passwordRecovery.recoveryCode = recoveryCode;
    session.passwordRecovery.createdAt = Date.now();
    session.passwordRecovery.verified = false;

    // Obtener usuario
    const user = await this.usersService.findOne(passwordRecovery.userId);

    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    // Enviar email
    await this.emailService.sendPasswordRecoveryEmail(
      passwordRecovery.correoElectronico,
      user.nombreCompleto,
      recoveryCode,
    );

    return { message: 'Nuevo código enviado. Revisa tu correo.' };
  }

  private createToken(user: any) {
    const payload = {
      sub: user.id,
      correoElectronico: user.correoElectronico,
    };
    return this.jwtService.sign(payload);
  }
}