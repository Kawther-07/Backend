import { EntityRepository, Repository } from 'typeorm';
import { Doctor } from '../entities/doctor';

@EntityRepository(Doctor)
export class DoctorRepository extends Repository<Doctor> {
}