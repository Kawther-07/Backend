import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import * as bcrypt from 'bcrypt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Patient } from '../entities/patient';
import { PatientRepository } from '../repositories/patient.repository';
//Repositories act as an intermediary between your application code and the database (create, update, delete...)

@Injectable()
export class PatientService {
  constructor(
    @InjectRepository(Patient)
    private readonly patientRepository: Repository<Patient>,
  ) {}

  async signIn(email: string, password: string): Promise<Patient | null> {
    const patient = await this.patientRepository.findOne({ where: { email } });
    if (patient && await bcrypt.compare(password, patient.password)) {
      return patient;
    }
    return null;
  }

  async registerPatient(email: string, password: string, first_name: string, last_name: string, phone: string, age: number, gender: string, height: number, weight: number, role: string): Promise<Patient> {
    try {
      const duplicate = await this.patientRepository.findOne({ where: { email } });
      if (duplicate) {
        throw new HttpException(`This email ${email} is already used.`, HttpStatus.BAD_REQUEST);
      }
      
      const patient: Patient = this.patientRepository.create({ email, password, first_name, last_name, phone, age, gender, height, weight, role });
      return await this.patientRepository.save(patient);
    } catch (error) {
      throw new HttpException('Failed to register patient.', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
  

  async getPatientByEmail(email: string): Promise<Patient | undefined> {
    try {
      return await this.patientRepository.findOne({ where: { email } });
    } catch (error) {
      console.error('Error:', error);
      return undefined; 
    }
  }

  async checkPatient(email: string): Promise<Patient | undefined> {
    try {
      return await this.patientRepository.findOne({ where: { email } });
    } catch (error) {
      throw new HttpException('Failed to check patient.', HttpStatus.INTERNAL_SERVER_ERROR);
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
      const patient = await this.patientRepository.findOne({ where: { email } });
      if (!patient) {
        return false; // patient not found
      }
      return await bcrypt.compare(password, patient.password);
    } catch (error) {
      console.error('Error:', error);
      return false;
    }
  }

}

