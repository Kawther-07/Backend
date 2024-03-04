import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import * as bcrypt from 'bcrypt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Admin } from '../entities/admin';
import { AdminRepository } from '../repositories/admin.repository';
//Repositories act as an intermediary between your application code and the database (create, update, delete...)

@Injectable()
export class AdminService {
  constructor(
    @InjectRepository(Admin)
    private readonly adminRepository: Repository<Admin>,
  ) {}

  async signIn(email: string, password: string): Promise<Admin | null> {
    const admin = await this.adminRepository.findOne({ where: { email } });
    if (admin && await bcrypt.compare(password, admin.password)) {
      return admin;
    }
    return null;
  }

  async registerAdmin(email: string, password: string, first_name: string, last_name: string, phone: string, role: string): Promise<Admin> {
    try {
      const duplicate = await this.adminRepository.findOne({ where: { email } });
      if (duplicate) {
        throw new HttpException(`This email ${email} is already used.`, HttpStatus.BAD_REQUEST);
      }
      
      const admin: Admin = this.adminRepository.create({ email, password, first_name, last_name, phone, role });
      return await this.adminRepository.save(admin);
    } catch (error) {
      throw new HttpException('Failed to register admin.', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
  

  async getAdminByEmail(email: string): Promise<Admin | undefined> {
    try {
      return await this.adminRepository.findOne({ where: { email } });
    } catch (error) {
      console.error('Error:', error);
      return undefined; 
    }
  }

  async checkAdmin(email: string): Promise<Admin | undefined> {
    try {
      return await this.adminRepository.findOne({ where: { email } });
    } catch (error) {
      throw new HttpException('Failed to check admin.', HttpStatus.INTERNAL_SERVER_ERROR);
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
      const admin = await this.adminRepository.findOne({ where: { email } });
      if (!admin) {
        return false; // Admin not found
      }
      return await bcrypt.compare(password, admin.password);
    } catch (error) {
      console.error('Error:', error);
      return false;
    }
  }

  // Me:
  // private readonly tokens: Set<string> = new Set<string>();

  // async logout(token: string): Promise<void> {
  //   // Remove the token 
  //   this.tokens.delete(token);
  // }

  // async isTokenValid(token: string): Promise<boolean> {
  //   // Check if the token exists 
  //   return this.tokens.has(token);
  // }

  // Ikram:
  async validateToken(token: string, JWTSecret_Key: string): Promise<boolean> {
    try {
      // Verify the token using the provided secret key
      jwt.verify(token, JWTSecret_Key);
      return true;
    } catch (error) {
      // Token is invalid
      return false;
    }
  }

}

