import type { AssessmentRepository } from './AssessmentRepository';

export interface TransactionalAssessmentRepository extends AssessmentRepository {
  /**
   * Executes a block of repository operations within a single transaction boundary.
   * If the callback throws an error (e.g. StaleStateError or a custom error),
   * all operations within the callback are rolled back atomically.
   * 
   * Nested transactions are unsupported and behavior is undefined for Milestone 20.
   */
  withTransaction<T>(
    work: (repository: AssessmentRepository) => Promise<T>
  ): Promise<T>;
}

export function isTransactionalAssessmentRepository(
  repository: AssessmentRepository
): repository is TransactionalAssessmentRepository {
  return typeof (repository as Partial<TransactionalAssessmentRepository>).withTransaction === 'function';
}
