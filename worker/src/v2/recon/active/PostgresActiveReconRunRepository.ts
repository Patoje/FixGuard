import { eq, and } from 'drizzle-orm';
import type { ActiveReconRunRepository } from './ActiveReconOriginRunRepository.js';
import type { PersistedActiveReconRunRecord } from './ActiveReconOriginRunPersistenceContracts.js';
import { validatePersistedActiveReconRecord } from './ActiveReconOriginRunPersistenceService.js';
import { v2_active_recon_run_records } from '../../storage/postgres/schema.js';

function clone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

type GenericDb = any;

export class PostgresActiveReconRunRepository implements ActiveReconRunRepository {
  constructor(private readonly db: GenericDb) {}

  public async saveRun(record: PersistedActiveReconRunRecord): Promise<PersistedActiveReconRunRecord> {
    const validation = validatePersistedActiveReconRecord(record);
    if (validation.status === 'invalid') {
      throw new Error(`Invalid record: ${validation.message}`);
    }
    const cloned = clone(validation.record);

    // If duplicate runId, postgres should naturally reject on PK constraint
    try {
      await this.db.insert(v2_active_recon_run_records).values({
        run_id: cloned.runId,
        record_version: cloned.recordVersion,
        record_kind: cloned.recordKind,
        subject_kind: cloned.subject.kind,
        normalized_origin: cloned.subject.normalizedOrigin || null,
        status: cloned.status,
        record_json: cloned,
        created_at: new Date(cloned.createdAt),
        updated_at: new Date(cloned.updatedAt),
      });
    } catch (err: any) {
      if (err.code === '23505' || err.message?.includes('duplicate key')) {
        throw new Error('Duplicate runId');
      }
      throw err;
    }

    return cloned;
  }

  public async getRun(runId: string): Promise<PersistedActiveReconRunRecord | null> {
    const rows = await this.db.select()
      .from(v2_active_recon_run_records)
      .where(eq(v2_active_recon_run_records.run_id, runId))
      .limit(1);

    if (rows.length === 0) return null;

    return clone(rows[0].record_json as PersistedActiveReconRunRecord);
  }

  public async listRuns(filter?: {
    recordKind?: 'active-recon.origin-run';
    normalizedOrigin?: string;
    status?: 'completed' | 'partial' | 'failed';
  }): Promise<PersistedActiveReconRunRecord[]> {
    let query = this.db.select().from(v2_active_recon_run_records);
    
    const conditions = [];
    if (filter?.recordKind) {
      conditions.push(eq(v2_active_recon_run_records.record_kind, filter.recordKind));
    }
    if (filter?.normalizedOrigin) {
      conditions.push(eq(v2_active_recon_run_records.normalized_origin, filter.normalizedOrigin));
    }
    if (filter?.status) {
      conditions.push(eq(v2_active_recon_run_records.status, filter.status));
    }

    if (conditions.length > 0) {
      query = query.where(and(...conditions));
    }

    const rows = await query;
    return rows.map((r: any) => clone(r.record_json as PersistedActiveReconRunRecord));
  }
}
