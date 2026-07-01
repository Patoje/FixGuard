import type {
  ActiveReconPersistedRecordKind,
  PersistedActiveReconRunRecord,
} from './ActiveReconOriginRunPersistenceContracts.js';

export type ActiveReconRunListFilter = {
  recordKind?: ActiveReconPersistedRecordKind;
  normalizedOrigin?: string;
  status?: 'completed' | 'partial' | 'failed';
};

export interface ActiveReconRunRepository {
  saveRun(record: PersistedActiveReconRunRecord): Promise<PersistedActiveReconRunRecord>;
  getRun(runId: string): Promise<PersistedActiveReconRunRecord | null>;
  listRuns(filter?: ActiveReconRunListFilter): Promise<PersistedActiveReconRunRecord[]>;
}
