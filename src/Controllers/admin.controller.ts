import { Controller, Post, Body, Res, HttpStatus, HttpException, Get} from '@nestjs/common';

import { AdminService } from '../Services/admin.service';

@Controller('admins')
export class AdminController {
  constructor(private readonly adminService: AdminService) {}
  
  @Post('register')
  async createAdmin(@Body() body: any, @Res() res): Promise<any> {
    try {
      const { email, password, first_name, last_name, phone, role } = body;
      
      // Check if admin with the same email already exists
      const duplicate = await this.adminService.getAdminByEmail(email);
      if (duplicate) {
        throw new HttpException(`This email ${email} is already used.`, HttpStatus.BAD_REQUEST);
      }

      // Register the new admin
      const response = await this.adminService.registerAdmin(email, password, first_name, last_name, phone, role);

      // Generate JWT token
      const tokenData = { _id: response.id, email };
      const token = await this.adminService.generateAccessToken(tokenData, "secret", "1h");

      // Return response
      return res.status(HttpStatus.OK).json({ status: true, message: 'Admin account is successfully created.', token, id: response.id });
    } catch (err) {
      console.error("---> err -->", err);
      if (err instanceof HttpException) {
        throw err;
      } else {
        throw new HttpException('Error when creating the admin account.', HttpStatus.INTERNAL_SERVER_ERROR);
      }
    }
  }

  @Get('login')
  async loginAdmin(@Body() body: any, @Res() res): Promise<any> {
    try {
      const { email, password } = body;

      if (!email || !password) {
        throw new HttpException('Parameters are incorrect.', HttpStatus.BAD_REQUEST);
      }

      let admin = await this.adminService.checkAdmin(email);
      if (!admin) {
        throw new HttpException('This admin doesn\'t exist.', HttpStatus.NOT_FOUND);
      }

      //They were using admin and password.
      const ispasswordCorrect = await this.adminService.comparePassword(email, password);

      if (!ispasswordCorrect) {
        throw new HttpException('Incorrect email or password.', HttpStatus.UNAUTHORIZED);
      }

      // Creating Token
      const tokenData = { _id: admin.id, email: admin.email };
      const token = await this.adminService.generateAccessToken(tokenData, "secret", "1h");

      res.status(HttpStatus.OK).json({ status: true, success: "Connected!", token, data :admin });
    } catch (error) {
      console.error('Error:', error);
      if (error instanceof HttpException) {
        throw error;
      } else {
        throw new HttpException('Error while logging in.', HttpStatus.INTERNAL_SERVER_ERROR);
      }
    }
  }

 // Me:
  @Post('logout')
  async logoutAdmin(@Res() res, @Body('adminId') adminId: string): Promise<void> {
    try {
      await this.adminService.logout(adminId);
      res.status(HttpStatus.OK).json({ status: true, message: 'Logout successful' });
    } catch (error) {
      console.error('Error:', error);
      throw new HttpException('Failed to logout admin.', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }


  // Ikram:
  // @Post('logout')
  // async logout(@Body() body: any, @Res() res): Promise<any> {
  //   try {
  //     const { token } = body;

  //     // Validate the token
  //     const isValidToken = await this.adminService.validateToken(token, 'secret');

  //     if (!isValidToken) {
  //       throw new HttpException('Invalid token.', HttpStatus.UNAUTHORIZED);
  //     }

  //     // Optionally, you might want to perform some additional validation here

  //     // Return success response
  //     return res.status(HttpStatus.OK).json({ status: true, message: 'Logout successful' });
  //   } catch (error) {
  //     console.error('Error:', error);
  //     if (error instanceof HttpException) {
  //       throw error;
  //     } else {
  //       throw new HttpException('Error during logout.', HttpStatus.INTERNAL_SERVER_ERROR);
  //     }
  //   }
  // }


}