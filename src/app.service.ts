import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {

  getHello() {
    return {
      mensaje: 'Servidor corriendo...',
      status: 200,
      fecha: new Date(),
    };
  }
}
