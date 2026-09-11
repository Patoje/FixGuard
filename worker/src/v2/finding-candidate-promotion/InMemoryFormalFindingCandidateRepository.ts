import type { ReviewedEvidenceFormalFindingCandidate } from "./ReviewedEvidenceFindingCandidatePromotionContracts.js";
import type {
  FormalFindingCandidateRepository,
  FormalFindingCandidateListOptions
} from "./FindingCandidatePersistenceContracts.js";
import { validateReviewedEvidenceFormalFindingCandidate } from "./ReviewedEvidenceFindingCandidatePromotionService.js";
import { PersistenceConflictError } from "../storage/StorageErrors.js";

export class InMemoryFormalFindingCandidateRepository
  implements FormalFindingCandidateRepository
{
  private candidates: Map<string, ReviewedEvidenceFormalFindingCandidate> = new Map();
  private draftIdIndex: Map<string, string> = new Map();

  private clone<T>(record: T): T {
    return JSON.parse(JSON.stringify(record));
  }

  async saveCandidate(
    candidate: ReviewedEvidenceFormalFindingCandidate
  ): Promise<ReviewedEvidenceFormalFindingCandidate> {
    if (!validateReviewedEvidenceFormalFindingCandidate(candidate)) {
      throw new Error("Invalid candidate: failed exact-key domain validation");
    }

    if (this.candidates.has(candidate.candidateId)) {
      throw new PersistenceConflictError(
        `Duplicate candidateId: ${candidate.candidateId}`,
        candidate.candidateId
      );
    }

    const draftId = candidate.sourceDraft.draftId;
    if (this.draftIdIndex.has(draftId)) {
      throw new PersistenceConflictError(
        `Duplicate draftId: ${draftId}`,
        draftId
      );
    }

    const cloned = this.clone(candidate);
    this.candidates.set(cloned.candidateId, cloned);
    this.draftIdIndex.set(draftId, cloned.candidateId);

    return this.clone(cloned);
  }

  async getCandidate(
    candidateId: string
  ): Promise<ReviewedEvidenceFormalFindingCandidate | null> {
    const candidate = this.candidates.get(candidateId);
    if (!candidate) return null;
    return this.clone(candidate);
  }

  async getCandidateByDraftId(
    draftId: string
  ): Promise<ReviewedEvidenceFormalFindingCandidate | null> {
    const candidateId = this.draftIdIndex.get(draftId);
    if (!candidateId) return null;
    return this.getCandidate(candidateId);
  }

  async listCandidatesByScanId(
    scanId: string,
    options?: FormalFindingCandidateListOptions
  ): Promise<ReviewedEvidenceFormalFindingCandidate[]> {
    let limit = 100;
    if (options && options.limit !== undefined) {
      if (
        typeof options.limit !== "number" ||
        options.limit <= 0 ||
        !Number.isInteger(options.limit)
      ) {
        throw new Error(`Invalid limit: ${options.limit}`);
      }
      limit = Math.min(options.limit, 100);
    }

    const matched = Array.from(this.candidates.values()).filter(
      (c) => c.scanId === scanId
    );

    // Deterministic ordering: createdAt DESC, candidateId ASC
    matched.sort((a, b) => {
      const aTime = new Date(a.createdAt).getTime();
      const bTime = new Date(b.createdAt).getTime();
      if (aTime !== bTime) {
        return bTime - aTime;
      }
      return a.candidateId.localeCompare(b.candidateId);
    });

    return matched.slice(0, limit).map((c) => this.clone(c));
  }
}
