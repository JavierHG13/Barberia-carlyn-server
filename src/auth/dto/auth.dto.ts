import { IsEmail, IsString, MinLength, IsNotEmpty, Length, IsNumberString } from 'class-validator';

export class RegisterDto {
  @IsNotEmpty({ message: 'El nombre es requerido' })
  @IsString()
  nombreCompleto: string;

  @IsEmail({}, { message: 'Correo electrónico inválido' })
  correoElectronico: string;

  @IsNotEmpty({ message: 'El teléfono es requerido' })
  @Length(10, 20, { message: 'El teléfono debe tener entre 10 y 20 caracteres' })
  telefono: string;

  @IsString()
  @MinLength(6, { message: 'La contraseña debe tener al menos 6 caracteres' })
  contrasena: string;
}

export class LoginDto {
  @IsEmail({}, { message: 'Correo electrónico inválido' })
  correoElectronico: string;

  @IsString()
  @IsNotEmpty({ message: 'La contraseña es requerida' })
  contrasena: string;
}

export class VerifyEmailDto {
  @IsNumberString({}, { message: 'El código debe ser numérico' })
  @Length(6, 6, { message: 'El código debe tener 6 dígitos' })
  code: string;

  @IsEmail({}, { message: 'Correo electrónico inválido' })
  correoElectronico: string;
}

export class ResendCodeDto {
  @IsEmail({}, { message: 'Correo electrónico inválido' })
  correoElectronico: string;
}

export class GoogleAuthDto {
  @IsString()
  @IsNotEmpty({ message: 'El token de Google es requerido' })
  googleToken: string;
}

export class ForgotPasswordDto {
  @IsEmail({}, { message: 'Correo electrónico inválido' })
  correoElectronico: string;
}

export class VerifyRecoveryCodeDto {
  @IsNumberString({}, { message: 'El código debe ser numérico' })
  @Length(6, 6, { message: 'El código debe tener 6 dígitos' })
  code: string;

  @IsEmail({}, { message: 'Correo electrónico inválido' })
  correoElectronico: string;
}

export class ResetPasswordDto {
  @IsString()
  @MinLength(6, { message: 'La contraseña debe tener al menos 6 caracteres' })
  newPassword: string;

  @IsEmail({}, { message: 'Correo electrónico inválido' })
  correoElectronico: string;
}