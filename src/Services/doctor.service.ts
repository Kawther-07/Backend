import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import * as bcrypt from 'bcrypt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Doctor } from '../entities/doctor';
import { DoctorRepository } from '../repositories/doctor.repository';

@Injectable()
export class DoctorService {
  constructor(
    @InjectRepository(Doctor)
    private readonly doctorRepository: Repository<Doctor>,
  ) {}

  async signIn(email: string, password: string): Promise<Doctor | null> {
    const doctor = await this.doctorRepository.findOne({ where: { email } });
    if (doctor && await bcrypt.compare(password, doctor.password)) {
      return doctor;
    }
    return null;
  }

  async registerDoctor(email: string, password: string, first_name: string, last_name: string, phone: string, role: string): Promise<Doctor> {
    try {
      const duplicate = await this.doctorRepository.findOne({ where: { email } });
      if (duplicate) {
        throw new HttpException(`This email ${email} is already used.`, HttpStatus.BAD_REQUEST);
      }
      
      const doctor: Doctor = this.doctorRepository.create({ email, password, first_name, last_name, phone, role});
      return await this.doctorRepository.save(doctor);
    } catch (error) {
      throw new HttpException('Failed to register doctor.', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
  

  async getDoctorByEmail(email: string): Promise<Doctor | undefined> {
    try {
      return await this.doctorRepository.findOne({ where: { email } });
    } catch (error) {
      console.error('Error:', error);
      return undefined; 
    }
  }

  async checkDoctor(email: string): Promise<Doctor | undefined> {
    try {
      return await this.doctorRepository.findOne({ where: { email } });
    } catch (error) {
      throw new HttpException('Failed to check doctor.', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async generateAccessToken(tokenData: any, JWTSecret_Key: string, JWT_EXPIRE: string): Promise<string> {
    try {
      return jwt.sign(tokenData, JWTSecret_Key, { expiresIn: JWT_EXPIRE });
    } catch (error) {
      throw new HttpException('Failed to generate access token.', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async comparePassword(email: string, password: string): Promise<boolean> {
    try {
      const doctor = await this.doctorRepository.findOne({ where: { email } });
      if (!doctor) {
        return false; // doctor not found
      }
      return await bcrypt.compare(password, doctor.password);
    } catch (error) {
      console.error('Error:', error);
      return false;
    }
  }

}