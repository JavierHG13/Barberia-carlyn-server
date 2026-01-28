import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from '../src/app.module';

let cachedApp;

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: process.env.FRONTEND_URL || '*',
    credentials: true,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
    }),
  );

  await app.init();

  return app.getHttpAdapter().getInstance();
}

export default async function handler(req, res) {
  if (!cachedApp) {
    cachedApp = await bootstrap();
  }
  return cachedApp(req, res);
}
