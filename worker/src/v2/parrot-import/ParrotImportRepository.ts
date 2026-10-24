import type { ParrotImportedObservation } from './ParrotImportContracts.js';

/**
 * Port for persisting validated (already-accepted) Parrot import
 * observations, keyed by assessment. These are never Findings — just
 * provenance-tagged, human-review-pending records an operator can list and
 * later triage through the normal review flow.
 */
export interface ParrotImportRepository {
  appendObservations(
    assessmentId: string,
    observations: readonly ParrotImportedObservation[]
  ): Promise<void>;

  listByAssessmentId(assessmentId: string): Promise<readonly ParrotImportedObservation[]>;

  getObservation(
    assessmentId: string,
    observationId: string
  ): Promise<ParrotImportedObservation | null>;

  /** P4 — records a human review decision on one observation (sets its
   * `review` field). Fails closed (throws) if the observation is already
   * reviewed or doesn't exist — a review decision is made once. */
  recordReview(
    assessmentId: string,
    observationId: string,
    review: NonNullable<ParrotImportedObservation['review']>
  ): Promise<ParrotImportedObservation>;
}
