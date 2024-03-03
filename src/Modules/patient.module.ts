import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Patient } from '../Entities/patient';
import { PatientController } from '../Controllers/patient.controller';
import { PatientService } from '../Services/patient.service';
import { PatientRepository } from '../repositories/patient.repository';

@Module({
  imports: [TypeOrmModule.forFeature([Patient, PatientRepository])],
  controllers: [PatientController],
  providers: [PatientService],
  exports: [PatientService],
})
export class PatientModule {}