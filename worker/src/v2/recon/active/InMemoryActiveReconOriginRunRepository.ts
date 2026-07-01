import type { ActiveReconRunListFilter, ActiveReconRunRepository } from './ActiveReconOriginRunRepository.js';
import type { PersistedActiveReconRunRecord } from './ActiveReconOriginRunPersistenceContracts.js';

export class InMemoryActiveReconOriginRunRepository implements ActiveReconRunRepository {
  private readonly records = new Map<string, string>();

  async saveRun(record: PersistedActiveReconRunRecord): Promise<PersistedActiveReconRunRecord> {
    if (this.records.has(record.runId)) {
      throw new Error('Duplicate runId');
    }
    // Save as JSON string to ensure deep cloning and prevent mutation leakage
    this.records.set(record.runId, JSON.stringify(record));
    return JSON.parse(this.records.get(record.runId)!) as PersistedActiveReconRunRecord;
  }

  async getRun(runId: string): Promise<PersistedActiveReconRunRecord | null> {
    const raw = this.records.get(runId);
    if (!raw) return null;
    return JSON.parse(raw) as PersistedActiveReconRunRecord;
  }

  async listRuns(filter?: ActiveReconRunListFilter): Promise<PersistedActiveReconRunRecord[]> {
    const results: PersistedActiveReconRunRecord[] = [];
    for (const raw of this.records.values()) {
      const record = JSON.parse(raw) as PersistedActiveReconRunRecord;
      let match = true;
      if (filter) {
        if (filter.recordKind && record.recordKind !== filter.recordKind) match = false;
        if (filter.normalizedOrigin && record.subject.normalizedOrigin !== filter.normalizedOrigin) match = false;
        if (filter.status && record.status !== filter.status) match = false;
      }
      if (match) {
        results.push(record);
      }
    }
    return results;
  }
}
