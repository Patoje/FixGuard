import type { ReviewedEvidenceFormalFindingCandidate } from "./ReviewedEvidenceFindingCandidatePromotionContracts.js";

export type FormalFindingCandidateListOptions = {
  limit?: number;
};

export interface FormalFindingCandidateRepository {
  saveCandidate(
    candidate: ReviewedEvidenceFormalFindingCandidate
  ): Promise<ReviewedEvidenceFormalFindingCandidate>;

  getCandidate(
    candidateId: string
  ): Promise<ReviewedEvidenceFormalFindingCandidate | null>;

  getCandidateByDraftId(
    draftId: string
  ): Promise<ReviewedEvidenceFormalFindingCandidate | null>;

  listCandidatesByScanId(
    scanId: string,
    options?: FormalFindingCandidateListOptions
  ): Promise<ReviewedEvidenceFormalFindingCandidate[]>;
}
