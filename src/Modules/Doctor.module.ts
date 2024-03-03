import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Doctor } from '../Entities/doctor';
import { DoctorController } from '../Controllers/doctor.controller';
import { DoctorService } from '../Services/doctor.service';
import { DoctorRepository } from '../repositories/doctor.repository';

@Module({
  imports: [TypeOrmModule.forFeature([Doctor])],
  controllers: [DoctorController],
  providers: [DoctorService],
  exports: [DoctorService],
})
export class DoctorModule {}