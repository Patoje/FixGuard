import type { ParrotImportedObservation } from './ParrotImportContracts.js';
import type { ParrotImportRepository } from './ParrotImportRepository.js';

/**
 * In-memory ParrotImportRepository (ADR-011: DB-free first). Defensive deep
 * cloning on write and read prevents shared-reference mutation of stored
 * observations.
 */
export class InMemoryParrotImportRepository implements ParrotImportRepository {
  private readonly byAssessment = new Map<string, ParrotImportedObservation[]>();

  private clone<T>(value: T): T {
    return JSON.parse(JSON.stringify(value));
  }

  async appendObservations(
    assessmentId: string,
    observations: readonly ParrotImportedObservation[]
  ): Promise<void> {
    const existing = this.byAssessment.get(assessmentId) ?? [];
    const cloned = observations.map((o) => this.clone(o));
    this.byAssessment.set(assessmentId, [...existing, ...cloned]);
  }

  async listByAssessmentId(
    assessmentId: string
  ): Promise<readonly ParrotImportedObservation[]> {
    const existing = this.byAssessment.get(assessmentId) ?? [];
    return Object.freeze(existing.map((o) => this.clone(o)));
  }
}
