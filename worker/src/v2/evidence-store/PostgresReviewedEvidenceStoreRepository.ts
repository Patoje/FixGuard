import { eq, desc, asc } from 'drizzle-orm';
import type { 
  ReviewedEvidenceStoreRecord, 
  ReviewedEvidenceStoreRepository, 
  ReviewedEvidenceListOptions 
} from './ReviewedEvidenceStoreContracts.js';
import { validateReviewedEvidenceStoreRecord } from './ReviewedEvidenceStoreService.js';
import { validateEvidenceSubstance } from '../evidence/EvidenceBoundaryService.js';
import { 
  PersistenceConflictError, 
  SessionNotFoundError, 
  RecordCorruptedError 
} from '../storage/StorageErrors.js';
import { v2_reviewed_evidence_records, type V2ReviewedEvidenceRecordRow } from '../storage/postgres/schema.js';

type GenericDb = any;

function clone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

export class PostgresReviewedEvidenceStoreRepository implements ReviewedEvidenceStoreRepository {
  constructor(private readonly db: GenericDb) {}

  public async save(record: ReviewedEvidenceStoreRecord): Promise<ReviewedEvidenceStoreRecord> {
    if (!validateReviewedEvidenceStoreRecord(record)) {
      throw new Error("Invalid record: failed exact-key domain validation");
    }

    const evidence = record.evidenceRecord;
    const substanceVal = validateEvidenceSubstance(evidence);
    if (!substanceVal.isValid) {
      throw new Error(`Invalid evidence substance: ${substanceVal.message}`);
    }

    const lineage = evidence.lineage;
    if (!lineage || !lineage.assessmentId) {
      throw new Error("Cannot persist reviewed evidence record without evidenceRecord.lineage.assessmentId matching session_id");
    }

    const cloned = clone(record);

    try {
      await this.db.insert(v2_reviewed_evidence_records).values({
        store_record_id: cloned.storeRecordId,
        session_id: lineage.assessmentId,
        scan_id: evidence.scanId,
        evidence_id: evidence.evidenceId,
        indicator_id: evidence.indicatorId,
        evidence_type: evidence.evidenceType,
        strength: evidence.strength,
        actor_id: lineage.actorId,
        validation_id: lineage.validationId,
        saved_at: new Date(cloned.savedAt),
        record_json: cloned,
        created_at: new Date()
      });
    } catch (err: any) {
      if (err.code === '23505' || err.message?.includes('duplicate key') || err.message?.includes('unique constraint')) {
        throw new PersistenceConflictError(`Duplicate record in store: ${cloned.storeRecordId}`, cloned.storeRecordId);
      }
      if (err.code === '23503' || err.message?.includes('foreign key') || err.message?.includes('violates foreign key constraint')) {
        throw new SessionNotFoundError(`Session not found for session_id: ${lineage.assessmentId}`, lineage.assessmentId);
      }
      throw err;
    }

    return cloned;
  }

  private deserializeAndValidate(row: V2ReviewedEvidenceRecordRow): ReviewedEvidenceStoreRecord {
    const rawJson = row.record_json;

    // 1. Defensive Deserialization
    let isValid = false;
    try {
      isValid = validateReviewedEvidenceStoreRecord(rawJson);
    } catch {
      isValid = false;
    }
    if (!isValid) {
      throw new RecordCorruptedError(
        `Reviewed evidence record failed defensive domain deserialization validation`,
        row.store_record_id
      );
    }

    const entity = rawJson as ReviewedEvidenceStoreRecord;
    const evidence = entity.evidenceRecord;

    // Validate substance defensively
    const substanceVal = validateEvidenceSubstance(evidence);
    if (!substanceVal.isValid) {
      throw new RecordCorruptedError(
        `Evidence substance failed defensive validation: ${substanceVal.message}`,
        row.store_record_id
      );
    }

    // 2. Relational Cross-Column Consistency Check
    if (
      row.store_record_id !== entity.storeRecordId ||
      row.scan_id !== evidence.scanId ||
      row.evidence_id !== evidence.evidenceId ||
      row.indicator_id !== evidence.indicatorId ||
      row.evidence_type !== evidence.evidenceType ||
      row.strength !== evidence.strength ||
      (evidence.lineage?.assessmentId && row.session_id !== evidence.lineage.assessmentId) ||
      (evidence.lineage?.actorId && row.actor_id !== evidence.lineage.actorId) ||
      (evidence.lineage?.validationId && row.validation_id !== evidence.lineage.validationId)
    ) {
      throw new RecordCorruptedError(
        `Relational cross-column consistency check failed for store record ${row.store_record_id}`,
        row.store_record_id
      );
    }

    return clone(entity);
  }

  public async getByStoreRecordId(storeRecordId: string): Promise<ReviewedEvidenceStoreRecord | null> {
    const rows = await this.db.select()
      .from(v2_reviewed_evidence_records)
      .where(eq(v2_reviewed_evidence_records.store_record_id, storeRecordId))
      .limit(1);

    if (rows.length === 0) return null;
    return this.deserializeAndValidate(rows[0]);
  }

  public async getByEvidenceId(evidenceId: string): Promise<ReviewedEvidenceStoreRecord | null> {
    const rows = await this.db.select()
      .from(v2_reviewed_evidence_records)
      .where(eq(v2_reviewed_evidence_records.evidence_id, evidenceId))
      .limit(1);

    if (rows.length === 0) return null;
    return this.deserializeAndValidate(rows[0]);
  }

  public async listByScanId(scanId: string, options?: ReviewedEvidenceListOptions): Promise<ReviewedEvidenceStoreRecord[]> {
    let limit = 100;
    if (options && options.limit !== undefined) {
      if (typeof options.limit !== 'number' || options.limit <= 0 || !Number.isInteger(options.limit)) {
        throw new Error(`Invalid limit: ${options.limit}`);
      }
      limit = Math.min(options.limit, 100);
    }

    const rows: V2ReviewedEvidenceRecordRow[] = await this.db.select()
      .from(v2_reviewed_evidence_records)
      .where(eq(v2_reviewed_evidence_records.scan_id, scanId))
      .orderBy(
        desc(v2_reviewed_evidence_records.saved_at),
        asc(v2_reviewed_evidence_records.store_record_id)
      )
      .limit(limit);

    return rows.map((r: V2ReviewedEvidenceRecordRow) => this.deserializeAndValidate(r));
  }
}
