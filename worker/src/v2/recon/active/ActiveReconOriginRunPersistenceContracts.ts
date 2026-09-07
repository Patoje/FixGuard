import type { SafeActiveReconObservation } from './ActiveReconContracts.js';

export type ActiveReconPersistedRecordVersion =
  | 'active-recon-origin-run-record/v0'
  | 'active-recon-origin-run-record/v1';

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

  provenance:
    | {
        // v0 legacy provenance — readable but not accepted for new executions
        sourceBoundary: 'M39';
        sourceContractVersion: 'active-recon-origin-run/v0';
        persistedBy: 'M40';
      }
    | {
        // v1 provenance — carries authorization source reference (M56A+)
        sourceBoundary: 'M39';
        sourceContractVersion: 'active-recon-origin-run/v1';
        persistedBy: 'M40';
        authorizationSource: 'fixguard-verified-authorization-decision/v0';
        authorizationDecisionId: string;
        authorizationGrantId: string;
        assessmentId: string;
        scanId: string;
        actorId: string;
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

export type PersistedActiveReconRecordValidationResult =
  | Readonly<{
      status: 'valid_v0_legacy';
      record: PersistedActiveReconRunRecord;
    }>
  | Readonly<{
      status: 'valid_v1';
      record: PersistedActiveReconRunRecord;
    }>
  | Readonly<{
      status: 'invalid';
      reasonCode:
        | 'unknown_record_format'
        | 'missing_provenance'
        | 'legacy_provenance_on_v1'
        | 'v1_provenance_on_v0'
        | 'invalid_provenance_shape'
        | 'missing_scan_id'
        | 'empty_provenance_id'
        | 'wrong_authorization_source'
        | 'invalid_record_structure';
      message: string;
    }>;
