/**
 * FixGuard V2 — In-Memory Orchestrated Assessment Repository
 *
 * Provides isolated, thread-safe in-memory persistence for orchestrated assessment records
 * ensuring mutation safety via deep cloning.
 */

import type {
  OrchestratedAssessmentRecord,
  OrchestratedAssessmentRepository,
} from '../application/OrchestratedAssessmentContracts.js';

export class InMemoryOrchestratedAssessmentRepository
  implements OrchestratedAssessmentRepository
{
  private readonly records = new Map<string, OrchestratedAssessmentRecord>();

  private clone<T>(value: T): T {
    return JSON.parse(JSON.stringify(value));
  }

  public async save(record: OrchestratedAssessmentRecord): Promise<void> {
    this.records.set(record.assessmentId, this.clone(record));
  }

  public async findById(assessmentId: string): Promise<OrchestratedAssessmentRecord | null> {
    const record = this.records.get(assessmentId);
    if (!record) {
      return null;
    }
    return this.clone(record);
  }

  public async update(
    assessmentId: string,
    updater: (prev: OrchestratedAssessmentRecord) => OrchestratedAssessmentRecord
  ): Promise<OrchestratedAssessmentRecord> {
    const existing = this.records.get(assessmentId);
    if (!existing) {
      throw new Error(`Orchestrated assessment '${assessmentId}' not found`);
    }

    const updated = updater(this.clone(existing));
    this.records.set(assessmentId, this.clone(updated));
    return this.clone(updated);
  }
}
