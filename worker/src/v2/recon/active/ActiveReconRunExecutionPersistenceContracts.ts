import type { 
  PersistedActiveReconRunRecord, 
  PersistedActiveReconRunError 
} from './ActiveReconOriginRunPersistenceContracts.js';

export type ActiveReconRunExecutionPersistenceContractVersion =
  | 'active-recon-run-execution-persistence/v0';

export type ActiveReconRunExecutionPersistenceStatus =
  | 'completed'
  | 'partial'
  | 'failed';

export type ActiveReconRunExecutionPersistenceErrorCode =
  | 'origin_run_failed'
  | 'persistence_failed'
  | 'repository_save_failed'
  | 'repository_reload_failed'
  | 'repository_reloaded_invalid_record'
  | 'unexpected_execution_persistence_failure';

export type ActiveReconRunExecutionPersistenceError = {
  code: ActiveReconRunExecutionPersistenceErrorCode;
  message: string;
};

export type ActiveReconRunExecutionPersistenceResult = {
  contractVersion: ActiveReconRunExecutionPersistenceContractVersion;

  status: ActiveReconRunExecutionPersistenceStatus;

  originRun: {
    runId: string;
    normalizedOrigin?: string;
    status: 'completed' | 'partial' | 'failed';
  } | null;

  persistedRecord: PersistedActiveReconRunRecord | null;

  reloadVerified: boolean;

  counts: {
    requested: number;
    planned: number;
    completed: number;
    blocked: number;
    candidate: number;
    failed: number;
  };

  runErrors: PersistedActiveReconRunError[];

  persistenceErrors: ActiveReconRunExecutionPersistenceError[];

  classification: {
    finding: false;
    evidence: false;
    vulnerability: false;
    riskClaim: false;
  };
};
