import type { ReviewedEvidenceFindingCandidateDraft } from "./ReviewedEvidenceFindingCandidateDraftContracts.js";

export type EvidenceDraftListOptions = {
  readonly limit?: number;
};

/**
 * Port defining persistence operations for Reviewed Evidence Finding Candidate Drafts.
 * Resides in Layer 8 (finding-candidate-draft domain layer).
 */
export interface EvidenceDraftRepository {
  saveDraft(
    draft: ReviewedEvidenceFindingCandidateDraft
  ): Promise<ReviewedEvidenceFindingCandidateDraft>;

  getDraft(
    draftId: string
  ): Promise<ReviewedEvidenceFindingCandidateDraft | null>;

  listDraftsByScanId(
    scanId: string,
    options?: EvidenceDraftListOptions
  ): Promise<ReviewedEvidenceFindingCandidateDraft[]>;
}
