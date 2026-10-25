import type { ParrotImportedObservation } from './ParrotImportContracts.js';
import type { ParrotImportRepository } from './ParrotImportRepository.js';
import { loadDevCacheArray, saveDevCacheArray } from '../storage/DevCachePersistence.js';

const OBSERVATIONS_CACHE_FILE = 'parrot_import_observations.json';

/**
 * In-memory ParrotImportRepository (ADR-011: DB-free first). Defensive deep
 * cloning on write and read prevents shared-reference mutation of stored
 * observations. Dev-cache persistence (same gate as InMemoryAttackPlanRepository
 * / InMemoryOrchestratedAssessmentRepository) survives a local dev-server
 * restart — without it, observations pending human review were lost on every
 * restart, a gap the R4 import-boundary milestone left open.
 */
export class InMemoryParrotImportRepository implements ParrotImportRepository {
  private readonly byAssessment = new Map<string, ParrotImportedObservation[]>();

  constructor() {
    for (const observation of loadDevCacheArray<ParrotImportedObservation>(OBSERVATIONS_CACHE_FILE)) {
      const existing = this.byAssessment.get(observation.assessmentId) ?? [];
      existing.push(observation);
      this.byAssessment.set(observation.assessmentId, existing);
    }
  }

  private clone<T>(value: T): T {
    return JSON.parse(JSON.stringify(value));
  }

  private persistDevCache(): void {
    saveDevCacheArray(OBSERVATIONS_CACHE_FILE, [...this.byAssessment.values()].flat());
  }

  async appendObservations(
    assessmentId: string,
    observations: readonly ParrotImportedObservation[]
  ): Promise<void> {
    const existing = this.byAssessment.get(assessmentId) ?? [];
    const cloned = observations.map((o) => this.clone(o));
    this.byAssessment.set(assessmentId, [...existing, ...cloned]);
    this.persistDevCache();
  }

  async listByAssessmentId(
    assessmentId: string
  ): Promise<readonly ParrotImportedObservation[]> {
    const existing = this.byAssessment.get(assessmentId) ?? [];
    return Object.freeze(existing.map((o) => this.clone(o)));
  }

  async getObservation(
    assessmentId: string,
    observationId: string
  ): Promise<ParrotImportedObservation | null> {
    const existing = this.byAssessment.get(assessmentId) ?? [];
    const found = existing.find((o) => o.observationId === observationId);
    return found ? this.clone(found) : null;
  }

  async recordReview(
    assessmentId: string,
    observationId: string,
    review: NonNullable<ParrotImportedObservation['review']>
  ): Promise<ParrotImportedObservation> {
    const existing = this.byAssessment.get(assessmentId) ?? [];
    const index = existing.findIndex((o) => o.observationId === observationId);
    if (index === -1) {
      throw new Error(`Parrot import observation '${observationId}' was not found`);
    }
    const current = existing[index];
    if (!current) {
      throw new Error(`Parrot import observation '${observationId}' was not found`);
    }
    if (current.review) {
      throw new Error(`Parrot import observation '${observationId}' was already reviewed`);
    }
    const updated: ParrotImportedObservation = { ...current, review };
    const next = [...existing];
    next[index] = updated;
    this.byAssessment.set(assessmentId, next);
    this.persistDevCache();
    return this.clone(updated);
  }
}
