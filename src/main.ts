import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import * as fs from 'fs';
import { AppModule } from './app.module';

async function bootstrap() {
  let httpsOptions: { key: Buffer; cert: Buffer } | undefined;

  if (process.env.NODE_ENV !== 'production') {
    httpsOptions = {
      key: fs.readFileSync('C:/mkcert/localhost-key.pem'),
      cert: fs.readFileSync('C:/mkcert/localhost.pem'),
    };
  }

  const app = await NestFactory.create(AppModule, { httpsOptions });

  app.enableCors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
    }),
  );

  if (process.env.NODE_ENV !== 'production') {
    await app.listen(3000);
    console.log('Servidor local en https://localhost:3000');
  } else {
    await app.init();
  }

  return app;
}

bootstrap();
