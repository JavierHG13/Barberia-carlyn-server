import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import session from 'express-session';
import morgan from 'morgan';

import { AppModule } from './app.module';

async function bootstrap() {
  //const app = await NestFactory.create(AppModule);
  const app = await NestFactory.create(AppModule);

  app.use(morgan('dev'));

  // Configurar sesiones
  app.use(
    session({
      secret: process.env.SESSION_SECRET || 'mi-secreto-super-seguro',
      resave: false,
      saveUninitialized: false,
      cookie: {
        maxAge: 3600000, // 1 hora
        secure: process.env.NODE_ENV === 'production',
      },
    }),
  );

  // Habilitar CORS
  app.enableCors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  });

  // Validación global
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  await app.listen(3000);
  console.log('Servidor corriendo');
}
bootstrap();