import { Controller, Post, Body, Res, HttpStatus, HttpException, Get } from '@nestjs/common';
import { DoctorService } from '../Services/doctor.service';

@Controller('doctors')
export class DoctorController {
  constructor(private readonly doctorService: DoctorService) {}
  
  @Post('register')
  async createDoctor(@Body() body: any, @Res() res): Promise<any> {
    try {
      const { email, password, first_name, last_name, phone, role } = body;
      
      // Check if doctor with the same email already exists
      const duplicate = await this.doctorService.getDoctorByEmail(email);
      if (duplicate) {
        throw new HttpException(`This email ${email} is already used.`, HttpStatus.BAD_REQUEST);
      }

      // Register the new doctor
      const response = await this.doctorService.registerDoctor(email, password, first_name, last_name, phone, role);

      // Generate JWT token
      const tokenData = { _id: response.id, email };
      const token = await this.doctorService.generateAccessToken(tokenData, "secret", "1h");

      // Return response
      return res.status(HttpStatus.OK).json({ status: true, message: 'Doctor account is successfully created.', token, id: response.id });
    } catch (err) {
      console.error("---> err -->", err);
      if (err instanceof HttpException) {
        throw err;
      } else {
        throw new HttpException('Error when creating the doctor account.', HttpStatus.INTERNAL_SERVER_ERROR);
      }
    }
  }

  @Get('login')
  async loginDoctor(@Body() body: any, @Res() res): Promise<any> {
    try {
      const { email, password } = body;

      if (!email || !password) {
        throw new HttpException('Parameters are incorrect.', HttpStatus.BAD_REQUEST);
      }

      let doctor = await this.doctorService.checkDoctor(email);
      if (!doctor) {
        throw new HttpException('This doctor doesn\'t exist.', HttpStatus.NOT_FOUND);
      }

      //They were using doctor and password.
      const ispasswordCorrect = await this.doctorService.comparePassword(email, password);

      if (!ispasswordCorrect) {
        throw new HttpException('Incorrect email or password.', HttpStatus.UNAUTHORIZED);
      }

      // Creating Token
      const tokenData = { _id: doctor.id, email: doctor.email };
      const token = await this.doctorService.generateAccessToken(tokenData, "secret", "1h");

      res.status(HttpStatus.OK).json({ status: true, success: "Connected!", token, data :doctor });
    } catch (error) {
      console.error('Error:', error);
      if (error instanceof HttpException) {
        throw error;
      } else {
        throw new HttpException('Error while logging in.', HttpStatus.INTERNAL_SERVER_ERROR);
      }
    }
  }


}