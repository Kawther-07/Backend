import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Admin } from './entities/admin';
import { Doctor } from './entities/doctor';
import { Patient } from './entities/patient';
import { AdminController } from './Controllers/admin.controller';
import { DoctorController } from './Controllers/doctor.controller';
import { PatientController } from './Controllers/patient.controller';
import { AdminService } from './Services/admin.service';
import { DoctorService } from './Services/doctor.service';
import { PatientService } from './Services/patient.service';

import { AdminModule } from './Modules/admin.module';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: 'localhost',
      port: 5432,
      username: 'postgres',
      password: 'kawther1234',
      database: 'DFUNestTesting',
      entities: [Admin, Doctor, Patient],
      synchronize: true, // Only use this option in development mode
    }),
    TypeOrmModule.forFeature([Admin, Doctor, Patient]),
  ],
  controllers: [AdminController, DoctorController, PatientController],
  providers: [AdminService, DoctorService, PatientService],
})
export class AppModule {}