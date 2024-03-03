import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Admin } from '../Entities/admin';
import { AdminController } from '../Controllers/admin.controller';
import { AdminService } from '../Services/admin.service';
import { AdminRepository } from '../repositories/admin.repository';

@Module({
  imports: [TypeOrmModule.forFeature([Admin, AdminRepository])],
  controllers: [AdminController],
  providers: [AdminService],
  exports: [AdminService],
})
export class AdminModule {}