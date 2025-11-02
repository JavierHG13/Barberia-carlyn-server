import { Controller, Post, Body, UseGuards, Get, Request } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { Session } from '../common/decorators/session.decorator';
import {
  RegisterDto,
  LoginDto,
  VerifyEmailDto,
  ResendCodeDto,
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
  async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto) {
    return this.authService.verifyEmail(
      verifyEmailDto.code,
      verifyEmailDto.correoElectronico,
    );
  }

  @Post('resend-code')
  async resendCode(@Body() resendCodeDto: ResendCodeDto) {
    return this.authService.resendCode(resendCodeDto.correoElectronico);
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto, @Session() session: any) {
    return this.authService.login(loginDto, session);
  }


  @Post('google')
  async googleAuth(@Body() googleAuthDto: GoogleAuthDto, @Session() session: any) {
    return this.authService.googleAuth(googleAuthDto, session);
  }

  // 🔄 RECUPERACIÓN DE CONTRASEÑA
  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto);
  }

  @Post('verify-recovery-code')
  async verifyRecoveryCode(@Body() verifyRecoveryCodeDto: VerifyRecoveryCodeDto) {
    return this.authService.verifyRecoveryCode(
      verifyRecoveryCodeDto.code,
      verifyRecoveryCodeDto.correoElectronico,
    );
  }

  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(
      resetPasswordDto,
      resetPasswordDto.correoElectronico,
    );
  }

  @Post('resend-recovery-code')
  async resendRecoveryCode(@Body() body: { correoElectronico: string }) {
    return this.authService.resendRecoveryCode(body.correoElectronico);
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