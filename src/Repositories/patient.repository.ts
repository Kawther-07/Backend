import { EntityRepository, Repository } from 'typeorm';
import { Patient } from '../entities/patient';

@EntityRepository(Patient)
export class PatientRepository extends Repository<Patient> {
}