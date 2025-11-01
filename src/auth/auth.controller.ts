import { Controller, Post, Body, UseGuards, Get, Request } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { Session } from '../common/decorators/session.decorator';

import {
  RegisterDto,
  LoginDto,
  VerifyEmailDto,
  GoogleAuthDto,
  ForgotPasswordDto,
  VerifyRecoveryCodeDto,
  ResetPasswordDto,
} from './dto/auth.dto';

@Controller('api/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}


  @Post('register')
  async register(@Body() registerDto: RegisterDto, @Session() session: any) {
    return this.authService.register(registerDto, session);
  }

  @Post('verify-email')
  async verifyEmail(
    @Body() verifyEmailDto: VerifyEmailDto,
    @Session() session: any,
  ) {
    return this.authService.verifyEmail(verifyEmailDto.code, session);
  }

  @Post('resend-code')
  async resendCode(@Session() session: any) {
    return this.authService.resendCode(session);
  }

  // 🔐 LOGIN
  @Post('login')
  async login(@Body() loginDto: LoginDto, @Session() session: any) {
    return this.authService.login(loginDto, session);
  }

  // 🔑 LOGIN CON GOOGLE
  @Post('google')
  async googleAuth(
    @Body() googleAuthDto: GoogleAuthDto,
    @Session() session: any,
  ) {
    return this.authService.googleAuth(googleAuthDto, session);
  }

  // 🔄 RECUPERACIÓN DE CONTRASEÑA
  @Post('forgot-password')
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
    @Session() session: any,
  ) {
    return this.authService.forgotPassword(forgotPasswordDto, session);
  }

  @Post('verify-recovery-code')
  async verifyRecoveryCode(
    @Body() verifyRecoveryCodeDto: VerifyRecoveryCodeDto,
    @Session() session: any,
  ) {
    return this.authService.verifyRecoveryCode(
      verifyRecoveryCodeDto.code,
      session,
    );
  }

  @Post('reset-password')
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
    @Session() session: any,
  ) {
    return this.authService.resetPassword(resetPasswordDto, session);
  }

  @Post('resend-recovery-code')
  async resendRecoveryCode(@Session() session: any) {
    return this.authService.resendRecoveryCode(session);
  }

  // 👤 PERFIL (RUTA PROTEGIDA)
  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  getProfile(@Request() req) {
    return {
      message: 'Perfil obtenido exitosamente',
      user: req.user,
    };
  }
}