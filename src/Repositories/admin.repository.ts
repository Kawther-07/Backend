import { EntityRepository, Repository } from 'typeorm';
import { Admin } from '../entities/admin';

@EntityRepository(Admin)
export class AdminRepository extends Repository<Admin> {
}