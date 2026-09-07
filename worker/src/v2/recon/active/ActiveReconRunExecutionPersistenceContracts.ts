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
  | 'persistence_record_invalid'
  | 'repository_save_failed'
  | 'repository_save_result_invalid'
  | 'repository_save_result_mismatch'
  | 'repository_reload_missing'
  | 'repository_reload_invalid'
  | 'repository_reload_mismatch'
  | 'repository_reload_failed'
  | 'unexpected_execution_persistence_failure'
  | 'preflight_denied_no_persistence';

export type ActiveReconRunExecutionPersistenceError = {
  code: ActiveReconRunExecutionPersistenceErrorCode;
  message: string;
};

export type ActiveReconReloadMismatchReasonCode = 'repository_reload_mismatch' | 'repository_save_result_mismatch';

export type ActiveReconReloadVerificationResult =
  | Readonly<{
      status: 'verified';
    }>
  | Readonly<{
      status: 'mismatch';
      reasonCode: ActiveReconReloadMismatchReasonCode;
    }>;

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
