import type { ReviewedEvidenceFindingCandidateDraft } from "./ReviewedEvidenceFindingCandidateDraftContracts.js";
import type {
  EvidenceDraftRepository,
  EvidenceDraftListOptions
} from "./EvidenceDraftPersistenceContracts.js";
import { validateReviewedEvidenceFindingCandidateDraft } from "./ReviewedEvidenceFindingCandidateDraftService.js";
import { PersistenceConflictError } from "../storage/StorageErrors.js";

/**
 * In-memory implementation of EvidenceDraftRepository.
 * Resides in Layer 8 (finding-candidate-draft domain layer).
 * Enforces defensive deep cloning to prevent shared reference mutation.
 */
export class InMemoryEvidenceDraftRepository implements EvidenceDraftRepository {
  private drafts: Map<string, ReviewedEvidenceFindingCandidateDraft> = new Map();

  private clone<T>(record: T): T {
    return JSON.parse(JSON.stringify(record));
  }

  async saveDraft(
    draft: ReviewedEvidenceFindingCandidateDraft
  ): Promise<ReviewedEvidenceFindingCandidateDraft> {
    if (!validateReviewedEvidenceFindingCandidateDraft(draft)) {
      throw new Error("Invalid draft: failed exact-key domain validation");
    }

    if (this.drafts.has(draft.draftId)) {
      throw new PersistenceConflictError(
        `Duplicate draftId: ${draft.draftId}`,
        draft.draftId
      );
    }

    const cloned = this.clone(draft);
    this.drafts.set(cloned.draftId, cloned);
    return this.clone(cloned);
  }

  async getDraft(
    draftId: string
  ): Promise<ReviewedEvidenceFindingCandidateDraft | null> {
    const draft = this.drafts.get(draftId);
    if (!draft) return null;
    return this.clone(draft);
  }

  async listDraftsByScanId(
    scanId: string,
    options?: EvidenceDraftListOptions
  ): Promise<ReviewedEvidenceFindingCandidateDraft[]> {
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

    const matched = Array.from(this.drafts.values()).filter(
      (d) => d.scanId === scanId
    );

    // Deterministic ordering: createdAt DESC, draftId ASC
    matched.sort((a, b) => {
      const aTime = new Date(a.createdAt).getTime();
      const bTime = new Date(b.createdAt).getTime();
      if (aTime !== bTime) {
        return bTime - aTime;
      }
      return a.draftId.localeCompare(b.draftId);
    });

    return matched.slice(0, limit).map((d) => this.clone(d));
  }
}
