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
  
  // Map temporal para almacenar datos de registro
  private tempRegistrations = new Map<string, {
    nombreCompleto: string;
    correoElectronico: string;
    telefono: string;
    contrasena: string;
    verificationCode: number;
    createdAt: number;
  }>();

  // Map para recuperación de contraseña
  private passwordRecovery = new Map<string, {
    userId: number;
    recoveryCode: number;
    createdAt: number;
    verified: boolean;
  }>();

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

    const existingUser = await this.usersService.findByEmail(correoElectronico);
    if (existingUser) {
      throw new BadRequestException('El correo electrónico ya está registrado');
    }

    const hashedPassword = await bcrypt.hash(contrasena, 10);
    const verificationCode = Math.floor(100000 + Math.random() * 900000);

    this.tempRegistrations.set(correoElectronico, {
      nombreCompleto,
      correoElectronico,
      telefono,
      contrasena: hashedPassword,
      verificationCode,
      createdAt: Date.now(),
    });

    console.log('Registro guardado:', correoElectronico, '- Código:', verificationCode);
    this.cleanOldRegistrations();

    await this.emailService.sendVerificationEmail(
      correoElectronico,
      nombreCompleto,
      verificationCode,
    );

    return {
      message: 'Código de verificación enviado. Revisa tu correo.',
    };
  }

  async verifyEmail(code: string, correoElectronico: string) {
    console.log('🔍 Verificando:', correoElectronico);
    
    const tempUserData = this.tempRegistrations.get(correoElectronico);

    if (!tempUserData) {
      console.error('No se encontró registro para:', correoElectronico);
      throw new BadRequestException('No hay registro pendiente de verificación');
    }

    const EXPIRATION_TIME = 4 * 60 * 1000;
    if (Date.now() - tempUserData.createdAt > EXPIRATION_TIME) {
      this.tempRegistrations.delete(correoElectronico);
      throw new BadRequestException('El código de verificación ha expirado');
    }

    if (parseInt(code) !== tempUserData.verificationCode) {
      throw new BadRequestException('Código incorrecto');
    }

    const existing = await this.usersService.findByEmail(correoElectronico);
    if (existing) {
      this.tempRegistrations.delete(correoElectronico);
      throw new BadRequestException('El correo ya está registrado');
    }

    const newUser = await this.usersService.create({
      nombreCompleto: tempUserData.nombreCompleto,
      correoElectronico: tempUserData.correoElectronico,
      telefono: tempUserData.telefono,
      contrasena: tempUserData.contrasena,
    });

    this.tempRegistrations.delete(correoElectronico);

    return {
      message: 'Correo verificado exitosamente. Tu cuenta ha sido creada.',
      user: {
        id: newUser.id,
        nombreCompleto: newUser.nombreCompleto,
        correoElectronico: newUser.correoElectronico,
      },
    };
  }

  async resendCode(correoElectronico: string) {
    const tempUserData = this.tempRegistrations.get(correoElectronico);

    if (!tempUserData) {
      throw new BadRequestException('No hay registro pendiente de verificación');
    }

    const verificationCode = Math.floor(100000 + Math.random() * 900000);

    this.tempRegistrations.set(correoElectronico, {
      ...tempUserData,
      verificationCode,
      createdAt: Date.now(),
    });

    console.log('🔄 Código reenviado:', correoElectronico, '- Nuevo código:', verificationCode);

    await this.emailService.sendVerificationEmail(
      correoElectronico,
      tempUserData.nombreCompleto,
      verificationCode,
    );

    return { message: 'Nuevo código enviado. Revisa tu correo.' };
  }

  private cleanOldRegistrations() {
    const TEN_MINUTES = 10 * 60 * 1000;
    const now = Date.now();

    for (const [email, data] of this.tempRegistrations.entries()) {
      if (now - data.createdAt > TEN_MINUTES) {
        this.tempRegistrations.delete(email);
      }
    }
  }

  // ========== LOGIN ==========
  async login(loginDto: LoginDto, session: any) {
    const { correoElectronico, contrasena } = loginDto;

    const user = await this.usersService.findByEmail(correoElectronico);
    if (!user) {
      throw new UnauthorizedException('Credenciales incorrectas');
    }

    const isMatch = await this.usersService.validatePassword(contrasena, user.contrasena);
    if (!isMatch) {
      throw new UnauthorizedException('Credenciales incorrectas');
    }

    const token = this.createToken(user);

    if (session) {
      session.user = {
        id: user.id,
        nombreCompleto: user.nombreCompleto,
        correoElectronico: user.correoElectronico,
      };
    }

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

  // ========== LOGIN CON GOOGLE ==========
  async googleAuth(googleAuthDto: GoogleAuthDto, session: any) {
    const { googleToken } = googleAuthDto;

    try {
      const ticket = await this.googleClient.verifyIdToken({
        idToken: googleToken,
        audience: this.configService.get('GOOGLE_CLIENT_ID'),
      });

      const payload = ticket.getPayload();
      
      if (!payload || !payload.email) {
        throw new BadRequestException('Token de Google inválido');
      }

      const { email, name, sub } = payload;

      let user = await this.usersService.findByEmail(email);

      if (!user) {
        const hashedPassword = await bcrypt.hash(sub, 10);
        user = await this.usersService.create({
          nombreCompleto: name || 'Usuario',
          correoElectronico: email,
          telefono: '',
          contrasena: hashedPassword,
        });
      }

      const token = this.createToken(user);

      if (session) {
        session.user = {
          id: user.id,
          nombreCompleto: user.nombreCompleto,
          correoElectronico: user.correoElectronico,
        };
      }

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

  // ========== RECUPERACIÓN DE CONTRASEÑA ==========
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const { correoElectronico } = forgotPasswordDto;

    const user = await this.usersService.findByEmail(correoElectronico);
    if (!user) {
      throw new NotFoundException('No existe una cuenta con ese correo');
    }

    const recoveryCode = Math.floor(100000 + Math.random() * 900000);

    this.passwordRecovery.set(correoElectronico, {
      userId: user.id,
      recoveryCode,
      createdAt: Date.now(),
      verified: false,
    });

    console.log('🔑 Código de recuperación generado:', correoElectronico, '- Código:', recoveryCode);

    await this.emailService.sendPasswordRecoveryEmail(
      correoElectronico,
      user.nombreCompleto,
      recoveryCode,
    );

    return { message: 'Código de recuperación enviado. Revisa tu correo.' };
  }

  async verifyRecoveryCode(code: string, correoElectronico: string) {
    const recovery = this.passwordRecovery.get(correoElectronico);

    if (!recovery) {
      throw new BadRequestException('No hay solicitud de recuperación activa');
    }

    const EXPIRATION_TIME = 10 * 60 * 1000;
    if (Date.now() - recovery.createdAt > EXPIRATION_TIME) {
      this.passwordRecovery.delete(correoElectronico);
      throw new BadRequestException('El código de recuperación ha expirado');
    }

    if (parseInt(code) !== recovery.recoveryCode) {
      throw new BadRequestException('Código incorrecto');
    }

    this.passwordRecovery.set(correoElectronico, {
      ...recovery,
      verified: true,
    });

    return { message: 'Código verificado correctamente' };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto, correoElectronico: string) {
    const { newPassword } = resetPasswordDto;
    const recovery = this.passwordRecovery.get(correoElectronico);

    if (!recovery) {
      throw new BadRequestException('No hay solicitud de recuperación activa');
    }

    if (!recovery.verified) {
      throw new BadRequestException('Debes verificar el código primero');
    }

    const EXPIRATION_TIME = 10 * 60 * 1000;
    if (Date.now() - recovery.createdAt > EXPIRATION_TIME) {
      this.passwordRecovery.delete(correoElectronico);
      throw new BadRequestException('La sesión ha expirado');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.usersService.update(recovery.userId, {
      contrasena: hashedPassword,
    });

    const user = await this.usersService.findOne(recovery.userId);
    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    await this.emailService.sendPasswordChangedEmail(
      correoElectronico,
      user.nombreCompleto,
    );

    this.passwordRecovery.delete(correoElectronico);

    return { message: 'Contraseña actualizada exitosamente' };
  }

  async resendRecoveryCode(correoElectronico: string) {
    const recovery = this.passwordRecovery.get(correoElectronico);

    if (!recovery) {
      throw new BadRequestException('No hay solicitud de recuperación activa');
    }

    const recoveryCode = Math.floor(100000 + Math.random() * 900000);

    this.passwordRecovery.set(correoElectronico, {
      ...recovery,
      recoveryCode,
      createdAt: Date.now(),
      verified: false,
    });

    console.log('🔄 Código de recuperación reenviado:', correoElectronico, '- Nuevo código:', recoveryCode);

    const user = await this.usersService.findOne(recovery.userId);
    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    await this.emailService.sendPasswordRecoveryEmail(
      correoElectronico,
      user.nombreCompleto,
      recoveryCode,
    );

    return { message: 'Nuevo código enviado. Revisa tu correo.' };
  }

  // ========== UTILIDADES ==========
  private createToken(user: any) {
    const payload = {
      sub: user.id,
      correoElectronico: user.correoElectronico,
    };
    return this.jwtService.sign(payload);
  }
}