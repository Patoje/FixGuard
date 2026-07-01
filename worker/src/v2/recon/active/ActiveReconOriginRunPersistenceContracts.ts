import type { SafeActiveReconObservation } from './ActiveReconContracts.js';

export type ActiveReconPersistedRecordVersion =
  | 'active-recon-origin-run-record/v0';

export type ActiveReconPersistedRecordKind =
  | 'active-recon.origin-run';

export type PersistedActiveReconRunRecord = {
  recordVersion: ActiveReconPersistedRecordVersion;
  recordKind: ActiveReconPersistedRecordKind;

  runId: string;

  subject: {
    kind: 'origin';
    normalizedOrigin?: string;
  };

  status: 'completed' | 'partial' | 'failed';

  counts: {
    requested: number;
    planned: number;
    completed: number;
    blocked: number;
    candidate: number;
    failed: number;
  };

  items: PersistedActiveReconRunItem[];

  observations: SafeActiveReconObservation[];

  runErrors: PersistedActiveReconRunError[];

  classification: {
    finding: false;
    evidence: false;
    vulnerability: false;
    riskClaim: false;
  };

  provenance: {
    sourceBoundary: 'M39';
    sourceContractVersion: 'active-recon-origin-run/v0';
    persistedBy: 'M40';
  };

  createdAt: string;
  updatedAt: string;
};

export type PersistedActiveReconRunItem =
  | PersistedDocumentProbeRunItem;

export type PersistedDocumentProbeRunItem = {
  itemVersion: 'active-recon-document-probe-item/v0';

  family: 'document';

  safeProbeIndex: string;

  safeKind:
    | 'http.robots.inspect'
    | 'http.security_txt.inspect'
    | 'unknown';

  status:
    | 'completed'
    | 'blocked'
    | 'candidate'
    | 'failed';

  target: {
    normalizedOrigin?: string;
    safeDisplayUrl?: string;
  };

  observations: SafeActiveReconObservation[];

  error?: PersistedActiveReconRunError;
};

export type PersistedActiveReconRunError = {
  code:
    | 'authorization_not_confirmed'
    | 'invalid_origin'
    | 'origin_out_of_scope'
    | 'unsupported_probe'
    | 'empty_probe_set'
    | 'planning_failed'
    | 'runner_failed'
    | 'adapter_missing'
    | 'adapter_failed'
    | 'policy_blocked'
    | 'policy_candidate'
    | 'persistence_validation_failed';

  message: string;
};
