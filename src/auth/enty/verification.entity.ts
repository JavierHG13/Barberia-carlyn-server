import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
} from 'typeorm';

@Entity('tbl_verificaciones_temporales')
export class VerificationTemp {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  correoElectronico: string;

  @Column()
  nombreCompleto: string;

  @Column({ nullable: true })
  telefono: string;

  @Column()
  contrasena: string;

  @Column()
  codigoVerificacion: number;

  @Column({ default: 'registro' }) // 'registro' o 'recuperacion'
  tipo: string;

  @Column({ nullable: true })
  userId: number; // Solo para recuperación de contraseña

  @Column({ default: false })
  verificado: boolean;

  @CreateDateColumn({ type: 'datetime', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;
}
