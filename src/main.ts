import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import session from 'express-session';
import morgan from 'morgan';
import * as fs from 'fs';

import { AppModule } from './app.module';

async function bootstrap() {

  const httpsOptions = {
    key: fs.readFileSync('C:/mkcert/localhost-key.pem'),
    cert: fs.readFileSync('C:/mkcert/localhost.pem'),
  };

  const app = await NestFactory.create(AppModule, {
    httpsOptions,
  });

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


  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  await app.listen(3000);
  console.log('Servidor en https://localhost:3000');
}
bootstrap();
