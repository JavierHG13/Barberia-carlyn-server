import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('tbl_usuarios')
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ length: 100 })
  nombreCompleto: string;

  @Column({ unique: true })
  correoElectronico: string;

  @Column({ length: 20 })
  telefono: string;

  @Column()
  contrasena: string;
}
