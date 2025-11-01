import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private transporter: nodemailer.Transporter;

  constructor(private configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      service: 'gmail',
      secure: false,
      auth: {
        user: this.configService.get('EMAIL_USER'),
        pass: this.configService.get('EMAIL_PASS'),
      },
    });
  }

  async sendVerificationEmail(email: string, name: string, code: number) {
    await this.transporter.sendMail({
      from: `"Soporte" <${this.configService.get('EMAIL_USER')}>`,
      to: email,
      subject: 'Verificación de correo electrónico',
      html: `
        <h2>Hola ${name}</h2>
        <p>Tu código de verificación es:</p>
        <h3>${code}</h3>
        <p>Ingresa este código en la aplicación para activar tu cuenta.</p>
      `,
    });
  }

  async sendPasswordRecoveryEmail(email: string, name: string, code: number) {
    await this.transporter.sendMail({
      from: `"Soporte" <${this.configService.get('EMAIL_USER')}>`,
      to: email,
      subject: 'Recuperación de contraseña',
      html: `
        <h2>Hola ${name}</h2>
        <p>Has solicitado recuperar tu contraseña.</p>
        <p>Tu código de recuperación es:</p>
        <h3>${code}</h3>
        <p>Ingresa este código en la aplicación para restablecer tu contraseña.</p>
        <p><small>Este código expira en 10 minutos.</small></p>
        <p><small>Si no solicitaste esto, ignora este mensaje.</small></p>
      `,
    });
  }

  async sendPasswordChangedEmail(email: string, name: string) {
    await this.transporter.sendMail({
      from: `"Soporte" <${this.configService.get('EMAIL_USER')}>`,
      to: email,
      subject: 'Contraseña actualizada',
      html: `
        <h2>Hola ${name}</h2>
        <p>Tu contraseña ha sido actualizada exitosamente.</p>
        <p>Si no realizaste este cambio, contacta inmediatamente con soporte.</p>
      `,
    });
  }
}