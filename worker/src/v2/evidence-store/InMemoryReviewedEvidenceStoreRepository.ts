import type { ReviewedEvidenceStoreRecord, ReviewedEvidenceStoreRepository, ReviewedEvidenceListOptions } from "./ReviewedEvidenceStoreContracts.js";

export class InMemoryReviewedEvidenceStoreRepository implements ReviewedEvidenceStoreRepository {
  private records: Map<string, ReviewedEvidenceStoreRecord> = new Map();
  private evidenceIdIndex: Map<string, string> = new Map();

  private clone(record: ReviewedEvidenceStoreRecord): ReviewedEvidenceStoreRecord {
    return JSON.parse(JSON.stringify(record));
  }

  async save(record: ReviewedEvidenceStoreRecord): Promise<ReviewedEvidenceStoreRecord> {
    if (this.records.has(record.storeRecordId)) {
      throw new Error(`Duplicate storeRecordId: ${record.storeRecordId}`);
    }
    if (this.evidenceIdIndex.has(record.evidenceRecord.evidenceId)) {
      throw new Error(`Duplicate evidenceId: ${record.evidenceRecord.evidenceId}`);
    }

    const cloned = this.clone(record);
    this.records.set(cloned.storeRecordId, cloned);
    this.evidenceIdIndex.set(cloned.evidenceRecord.evidenceId, cloned.storeRecordId);

    return this.clone(cloned);
  }

  async getByStoreRecordId(storeRecordId: string): Promise<ReviewedEvidenceStoreRecord | null> {
    const record = this.records.get(storeRecordId);
    if (!record) return null;
    return this.clone(record);
  }

  async getByEvidenceId(evidenceId: string): Promise<ReviewedEvidenceStoreRecord | null> {
    const storeRecordId = this.evidenceIdIndex.get(evidenceId);
    if (!storeRecordId) return null;
    return this.getByStoreRecordId(storeRecordId);
  }

  async listByScanId(scanId: string, options?: ReviewedEvidenceListOptions): Promise<ReviewedEvidenceStoreRecord[]> {
    let limit = 100; // safe default
    if (options && options.limit !== undefined) {
      if (typeof options.limit !== 'number' || options.limit <= 0 || !Number.isInteger(options.limit)) {
        throw new Error(`Invalid limit: ${options.limit}`);
      }
      limit = Math.min(options.limit, 100);
    }

    const matched = Array.from(this.records.values())
      .filter(r => r.evidenceRecord.scanId === scanId || r.source.sourceScanId === scanId); // both should be equal anyway

    // Deterministic ordering: savedAt DESC, storeRecordId ASC
    matched.sort((a, b) => {
      const aTime = new Date(a.savedAt).getTime();
      const bTime = new Date(b.savedAt).getTime();
      if (aTime !== bTime) {
        return bTime - aTime;
      }
      return a.storeRecordId.localeCompare(b.storeRecordId);
    });

    return matched.slice(0, limit).map(r => this.clone(r));
  }
}
