
import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  NotFoundException,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { OAuth2Client } from 'google-auth-library';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { EmailService } from '../email/email.service';
import { VerificationTemp } from './enty/verification.entity';
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
    @InjectRepository(VerificationTemp)
    private verificationRepository: Repository<VerificationTemp>,
  ) {
    this.googleClient = new OAuth2Client(
      this.configService.get('GOOGLE_CLIENT_ID'),
    );
  }

  // ========== REGISTRO ==========
  async register(registerDto: RegisterDto, session: any) {
    const { nombreCompleto, correoElectronico, telefono, contrasena } = registerDto;

    const existingUser = await this.usersService.findByEmail(correoElectronico);
    if (existingUser) {
      throw new BadRequestException('Error al registrarse');
    }

    // Eliminar verificaciones anteriores del mismo correo
    await this.verificationRepository.delete({
      correoElectronico,
      tipo: 'registro',
    });

    const hashedPassword = await bcrypt.hash(contrasena, 10);
    const verificationCode = Math.floor(100000 + Math.random() * 900000);

    // Guardar en la tabla temporal
    await this.verificationRepository.save({
      correoElectronico,
      nombreCompleto,
      telefono,
      contrasena: hashedPassword,
      codigoVerificacion: verificationCode,
      tipo: 'registro',
    });

    console.log('Registro guardado:', correoElectronico, '- Código:', verificationCode);

    // Limpiar registros antiguos
    await this.cleanOldVerifications();

    await this.emailService.sendVerificationEmail(
      correoElectronico,
      nombreCompleto,
      verificationCode,
    );

    return {
      message: 'Código de verificación enviado. Revisa tu correo.',
    };
  }

  // ========== VERIFICAR EMAIL ==========
  async verifyEmail(code: string, correoElectronico: string) {
    console.log('🔍 Verificando:', correoElectronico);

    const verification = await this.verificationRepository.findOne({
      where: {
        correoElectronico,
        tipo: 'registro',
      },
    });

    if (!verification) {
      throw new BadRequestException('No hay registro pendiente de verificación');
    }

    // Verificar expiración (4 minutos)
    const EXPIRATION_TIME = 4 * 60 * 1000;
    const createdAt = new Date(verification.createdAt).getTime();
    if (Date.now() - createdAt > EXPIRATION_TIME) {
      await this.verificationRepository.delete({ id: verification.id });
      throw new BadRequestException('El código de verificación ha expirado');
    }

    if (parseInt(code) !== verification.codigoVerificacion) {
      throw new BadRequestException('Código incorrecto');
    }

    const existing = await this.usersService.findByEmail(correoElectronico);
    if (existing) {
      await this.verificationRepository.delete({ id: verification.id });
      throw new BadRequestException('El correo ya está registrado');
    }

    // Crear el usuario real
    const newUser = await this.usersService.create({
      nombreCompleto: verification.nombreCompleto,
      correoElectronico: verification.correoElectronico,
      telefono: verification.telefono,
      contrasena: verification.contrasena,
    });

    // Eliminar de la tabla temporal
    await this.verificationRepository.delete({ id: verification.id });

    return {
      message: 'Correo verificado exitosamente. Tu cuenta ha sido creada.',
      user: {
        id: newUser.id,
        nombreCompleto: newUser.nombreCompleto,
        correoElectronico: newUser.correoElectronico,
      },
    };
  }

  // ========== REENVIAR CÓDIGO ==========
  async resendCode(correoElectronico: string) {
    // Verificar límites de reenvío
    await this.checkResendLimit(correoElectronico);

    const verification = await this.verificationRepository.findOne({
      where: {
        correoElectronico,
        tipo: 'registro',
      },
    });

    if (!verification) {
      throw new BadRequestException('Error al registrarse');
    }

    const verificationCode = Math.floor(100000 + Math.random() * 900000);

    // Actualizar código y fecha
    verification.codigoVerificacion = verificationCode;
    verification.createdAt = new Date();
    await this.verificationRepository.save(verification);

    // Registrar intento de reenvío
    await this.recordResendAttempt(correoElectronico);

    console.log('🔄 Código reenviado:', correoElectronico, '- Nuevo código:', verificationCode);

    await this.emailService.sendVerificationEmail(
      correoElectronico,
      verification.nombreCompleto,
      verificationCode,
    );

    return { message: 'Nuevo código enviado. Revisa tu correo.' };
  }

  // ========== RECUPERACIÓN DE CONTRASEÑA ==========
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const { correoElectronico } = forgotPasswordDto;

    const user = await this.usersService.findByEmail(correoElectronico);
    if (!user) {
      throw new NotFoundException('No existe una cuenta con ese correo');
    }

    // Eliminar recuperaciones anteriores
    await this.verificationRepository.delete({
      correoElectronico,
      tipo: 'recuperacion',
    });

    const recoveryCode = Math.floor(100000 + Math.random() * 900000);

    // Guardar en tabla temporal
    await this.verificationRepository.save({
      correoElectronico,
      nombreCompleto: user.nombreCompleto,
      telefono: '',
      contrasena: '',
      codigoVerificacion: recoveryCode,
      tipo: 'recuperacion',
      userId: user.id,
      verificado: false,
    });

    console.log('🔑 Código de recuperación generado:', correoElectronico, '- Código:', recoveryCode);

    await this.emailService.sendPasswordRecoveryEmail(
      correoElectronico,
      user.nombreCompleto,
      recoveryCode,
    );

    return { message: 'Código de recuperación enviado. Revisa tu correo.' };
  }

  // ========== VERIFICAR CÓDIGO DE RECUPERACIÓN ==========
  async verifyRecoveryCode(code: string, correoElectronico: string) {
    const verification = await this.verificationRepository.findOne({
      where: {
        correoElectronico,
        tipo: 'recuperacion',
      },
    });

    if (!verification) {
      throw new BadRequestException('No hay solicitud de recuperación activa');
    }

    // Verificar expiración (10 minutos)
    const EXPIRATION_TIME = 10 * 60 * 1000;
    const createdAt = new Date(verification.createdAt).getTime();
    if (Date.now() - createdAt > EXPIRATION_TIME) {
      await this.verificationRepository.delete({ id: verification.id });
      throw new BadRequestException('El código de recuperación ha expirado');
    }

    if (parseInt(code) !== verification.codigoVerificacion) {
      throw new BadRequestException('Código incorrecto');
    }

    // Marcar como verificado
    verification.verificado = true;
    await this.verificationRepository.save(verification);

    return { message: 'Código verificado correctamente' };
  }

  // ========== RESETEAR CONTRASEÑA ==========
  async resetPassword(resetPasswordDto: ResetPasswordDto, correoElectronico: string) {
    const { newPassword } = resetPasswordDto;

    const verification = await this.verificationRepository.findOne({
      where: {
        correoElectronico,
        tipo: 'recuperacion',
        verificado: true,
      },
    });

    if (!verification) {
      throw new BadRequestException('No hay solicitud de recuperación activa');
    }

    // Verificar expiración
    const EXPIRATION_TIME = 10 * 60 * 1000;
    const createdAt = new Date(verification.createdAt).getTime();
    if (Date.now() - createdAt > EXPIRATION_TIME) {
      await this.verificationRepository.delete({ id: verification.id });
      throw new BadRequestException('La sesión ha expirado');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.usersService.update(verification.userId, {
      contrasena: hashedPassword,
    });

    const user = await this.usersService.findOne(verification.userId);
    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    await this.emailService.sendPasswordChangedEmail(
      correoElectronico,
      user.nombreCompleto,
    );

    // Eliminar de la tabla temporal
    await this.verificationRepository.delete({ id: verification.id });

    return { message: 'Contraseña actualizada exitosamente' };
  }

  // ========== REENVIAR CÓDIGO DE RECUPERACIÓN ==========
  async resendRecoveryCode(correoElectronico: string) {
    await this.checkResendLimit(correoElectronico);

    const verification = await this.verificationRepository.findOne({
      where: {
        correoElectronico,
        tipo: 'recuperacion',
      },
    });

    if (!verification) {
      throw new BadRequestException('No hay solicitud de recuperación activa');
    }

    const recoveryCode = Math.floor(100000 + Math.random() * 900000);

    // Actualizar código
    verification.codigoVerificacion = recoveryCode;
    verification.createdAt = new Date();
    verification.verificado = false;
    await this.verificationRepository.save(verification);

    await this.recordResendAttempt(correoElectronico);

    console.log('🔄 Código de recuperación reenviado:', correoElectronico, '- Nuevo código:', recoveryCode);

    const user = await this.usersService.findOne(verification.userId);
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

  // ========== CONTROL DE INTENTOS DE LOGIN ==========
  private loginAttempts = new Map<string, { attempts: number; blockedUntil: number | null }>();

  private checkIfBlocked(identifier: string): void {
    const attemptData = this.loginAttempts.get(identifier);
    if (!attemptData) return;

    if (attemptData.blockedUntil && Date.now() < attemptData.blockedUntil) {
      const remainingTime = Math.ceil((attemptData.blockedUntil - Date.now()) / 1000);
      throw new HttpException(
        `Demasiados intentos fallidos. Intenta de nuevo en ${remainingTime} segundos`,
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    if (attemptData.blockedUntil && Date.now() >= attemptData.blockedUntil) {
      this.loginAttempts.delete(identifier);
    }
  }

  private recordFailedAttempt(identifier: string): void {
    const attemptData = this.loginAttempts.get(identifier) || { attempts: 0, blockedUntil: null };
    attemptData.attempts += 1;

    if (attemptData.attempts >= 3) {
      attemptData.blockedUntil = Date.now() + 2 * 60 * 1000;
      console.log(`🔒 Usuario bloqueado: ${identifier} por 2 minutos`);
    }

    this.loginAttempts.set(identifier, attemptData);
  }

  private clearFailedAttempts(identifier: string): void {
    this.loginAttempts.delete(identifier);
  }

  // ========== CONTROL DE REENVÍOS ==========
  private resendAttempts = new Map<string, { attempts: number; lastAttempt: number; blockedUntil: number | null }>();

  private async checkResendLimit(correoElectronico: string): Promise<void> {
    const resendData = this.resendAttempts.get(correoElectronico);
    if (!resendData) return;

    if (resendData.blockedUntil && Date.now() < resendData.blockedUntil) {
      const remainingTime = Math.ceil((resendData.blockedUntil - Date.now()) / 1000);
      throw new HttpException(
        `Demasiados reenvíos. Espera ${remainingTime} segundos antes de intentar nuevamente`,
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const COOLDOWN = 30 * 1000;
    if (Date.now() - resendData.lastAttempt < COOLDOWN) {
      const remainingTime = Math.ceil((COOLDOWN - (Date.now() - resendData.lastAttempt)) / 1000);
      throw new HttpException(
        `Debes esperar ${remainingTime} segundos antes de solicitar otro código`,
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    if (resendData.blockedUntil && Date.now() >= resendData.blockedUntil) {
      this.resendAttempts.delete(correoElectronico);
    }
  }

  private async recordResendAttempt(correoElectronico: string): Promise<void> {
    const resendData = this.resendAttempts.get(correoElectronico) || {
      attempts: 0,
      lastAttempt: 0,
      blockedUntil: null,
    };

    resendData.attempts += 1;
    resendData.lastAttempt = Date.now();

    if (resendData.attempts >= 5) {
      resendData.blockedUntil = Date.now() + 10 * 60 * 1000;
      console.log(`🔒 Reenvíos bloqueados para: ${correoElectronico} por 10 minutos`);
    }

    this.resendAttempts.set(correoElectronico, resendData);
  }

  // ========== LOGIN ==========
  async login(loginDto: LoginDto, session: any) {
    const { correoElectronico, contrasena } = loginDto;

    this.checkIfBlocked(correoElectronico);

    const user = await this.usersService.findByEmail(correoElectronico);
    if (!user) {
      this.recordFailedAttempt(correoElectronico);
      throw new UnauthorizedException('Credenciales incorrectas');
    }

    const isMatch = await this.usersService.validatePassword(contrasena, user.contrasena);
    if (!isMatch) {
      this.recordFailedAttempt(correoElectronico);
      throw new UnauthorizedException('Credenciales incorrectas');
    }

    this.clearFailedAttempts(correoElectronico);

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

      this.clearFailedAttempts(email);

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

  // ========== LIMPIAR VERIFICACIONES ANTIGUAS ==========
  private async cleanOldVerifications() {
    const TEN_MINUTES_AGO = new Date(Date.now() - 10 * 60 * 1000);

    await this.verificationRepository.delete({
      createdAt: LessThan(TEN_MINUTES_AGO),
    });
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