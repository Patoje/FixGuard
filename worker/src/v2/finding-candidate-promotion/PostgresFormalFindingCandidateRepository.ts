import { eq, desc, asc } from 'drizzle-orm';
import type { ReviewedEvidenceFormalFindingCandidate } from './ReviewedEvidenceFindingCandidatePromotionContracts.js';
import type { 
  FormalFindingCandidateRepository, 
  FormalFindingCandidateListOptions 
} from './FindingCandidatePersistenceContracts.js';
import { validateReviewedEvidenceFormalFindingCandidate } from './ReviewedEvidenceFindingCandidatePromotionService.js';
import { 
  PersistenceConflictError, 
  SessionNotFoundError, 
  RecordCorruptedError 
} from '../storage/StorageErrors.js';
import { v2_formal_finding_candidates, type V2FormalFindingCandidateRow } from '../storage/postgres/schema.js';

type GenericDb = any;

function clone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

export class PostgresFormalFindingCandidateRepository implements FormalFindingCandidateRepository {
  constructor(private readonly db: GenericDb) {}

  public async saveCandidate(
    candidate: ReviewedEvidenceFormalFindingCandidate
  ): Promise<ReviewedEvidenceFormalFindingCandidate> {
    if (!validateReviewedEvidenceFormalFindingCandidate(candidate)) {
      throw new Error("Invalid candidate: failed exact-key domain validation");
    }

    const lineage = candidate.lineage;
    if (!lineage || !lineage.assessmentId) {
      throw new Error("Cannot persist formal finding candidate without lineage.assessmentId matching session_id");
    }

    const cloned = clone(candidate);

    try {
      await this.db.insert(v2_formal_finding_candidates).values({
        candidate_id: cloned.candidateId,
        session_id: lineage.assessmentId,
        scan_id: cloned.scanId,
        draft_id: cloned.sourceDraft.draftId,
        source_selection_id: cloned.sourceDraft.sourceSelectionId,
        reviewer_id: cloned.humanTriage.reviewerId,
        triage_decision_id: cloned.humanTriage.decisionId,
        selected_evidence_count: cloned.sourceDraft.selectedCount,
        created_at: new Date(cloned.createdAt),
        candidate_json: cloned
      });
    } catch (err: any) {
      if (err.code === '23505' || err.message?.includes('duplicate key') || err.message?.includes('unique constraint')) {
        throw new PersistenceConflictError(`Duplicate candidate in repository: ${cloned.candidateId}`, cloned.candidateId);
      }
      if (err.code === '23503' || err.message?.includes('foreign key') || err.message?.includes('violates foreign key constraint')) {
        throw new SessionNotFoundError(`Session not found for session_id: ${lineage.assessmentId}`, lineage.assessmentId);
      }
      throw err;
    }

    return cloned;
  }

  private deserializeAndValidate(row: V2FormalFindingCandidateRow): ReviewedEvidenceFormalFindingCandidate {
    const rawJson = row.candidate_json;

    // 1. Defensive Deserialization
    let isValid = false;
    try {
      isValid = validateReviewedEvidenceFormalFindingCandidate(rawJson);
    } catch {
      isValid = false;
    }
    if (!isValid) {
      throw new RecordCorruptedError(
        `Formal finding candidate failed defensive domain deserialization validation`,
        row.candidate_id
      );
    }

    const entity = rawJson as ReviewedEvidenceFormalFindingCandidate;

    // 2. Relational Cross-Column Consistency Check
    if (
      row.candidate_id !== entity.candidateId ||
      row.scan_id !== entity.scanId ||
      row.draft_id !== entity.sourceDraft?.draftId ||
      row.source_selection_id !== entity.sourceDraft?.sourceSelectionId ||
      row.reviewer_id !== entity.humanTriage?.reviewerId ||
      row.triage_decision_id !== entity.humanTriage?.decisionId ||
      row.selected_evidence_count !== entity.sourceDraft?.selectedCount ||
      (entity.lineage?.assessmentId && row.session_id !== entity.lineage.assessmentId)
    ) {
      throw new RecordCorruptedError(
        `Relational cross-column consistency check failed for candidate ${row.candidate_id}`,
        row.candidate_id
      );
    }

    return clone(entity);
  }

  public async getCandidate(candidateId: string): Promise<ReviewedEvidenceFormalFindingCandidate | null> {
    const rows = await this.db.select()
      .from(v2_formal_finding_candidates)
      .where(eq(v2_formal_finding_candidates.candidate_id, candidateId))
      .limit(1);

    if (rows.length === 0) return null;
    return this.deserializeAndValidate(rows[0]);
  }

  public async getCandidateByDraftId(draftId: string): Promise<ReviewedEvidenceFormalFindingCandidate | null> {
    const rows = await this.db.select()
      .from(v2_formal_finding_candidates)
      .where(eq(v2_formal_finding_candidates.draft_id, draftId))
      .limit(1);

    if (rows.length === 0) return null;
    return this.deserializeAndValidate(rows[0]);
  }

  public async listCandidatesByScanId(
    scanId: string,
    options?: FormalFindingCandidateListOptions
  ): Promise<ReviewedEvidenceFormalFindingCandidate[]> {
    let limit = 100;
    if (options && options.limit !== undefined) {
      if (typeof options.limit !== 'number' || options.limit <= 0 || !Number.isInteger(options.limit)) {
        throw new Error(`Invalid limit: ${options.limit}`);
      }
      limit = Math.min(options.limit, 100);
    }

    const rows: V2FormalFindingCandidateRow[] = await this.db.select()
      .from(v2_formal_finding_candidates)
      .where(eq(v2_formal_finding_candidates.scan_id, scanId))
      .orderBy(
        desc(v2_formal_finding_candidates.created_at),
        asc(v2_formal_finding_candidates.candidate_id)
      )
      .limit(limit);

    return rows.map((r: V2FormalFindingCandidateRow) => this.deserializeAndValidate(r));
  }
}
