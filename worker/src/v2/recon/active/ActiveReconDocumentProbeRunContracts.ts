import type { AuthorizedScope } from '../policy/EgressPolicyContracts.js';
import type { SafeActiveReconObservation } from './ActiveReconContracts.js';
import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';

// Supported probe kinds for the document probe runner — fixed set, no extension point
export type ActiveReconDocumentProbeKind =
  | 'http.robots.inspect'
  | 'http.security_txt.inspect';

// Per-probe entry in a run request
export type ActiveReconDocumentProbeEntry = {
  /** Caller-assigned ID for this probe — used to correlate input/output */
  probeId: string;
  kind: ActiveReconDocumentProbeKind;
  /** Transient only — never stored in result or any output shape */
  targetUrl: string;
};

/**
 * The canonical run request type.
 * v1 is required for new active executions (runtime enforcement).
 */
export type ActiveReconDocumentProbeRunRequest = {
  contractVersion: 'active-recon-document-probe-run/v1';
  /** Optional caller-assigned run ID; a UUID is generated if absent */
  runId?: string;
  evaluatedAt: string;

  /**
   * v1: A runtime-established VerifiedAuthorizationDecision.
   * Plain object lookalikes are rejected.
   */
  verifiedAuthorizationDecision: VerifiedAuthorizationDecision;

  probes: ActiveReconDocumentProbeEntry[];
};

// Errors the runner may report per-probe
export type ActiveReconDocumentProbeErrorCode =
  | 'authorization_not_confirmed'
  | 'unsupported_probe'
  | 'invalid_target'
  | 'policy_blocked'
  | 'policy_candidate'
  | 'adapter_missing'
  | 'adapter_failed'
  | 'batch_preflight_aborted';

// Per-probe result — rawTargetUrl, raw probeId, and unsupported kind are intentionally absent/sanitized
export type ActiveReconDocumentProbeRunProbeResult = {
  /** Runner-generated safe probe index, never the raw caller-supplied probeId */
  safeProbeIndex: string;
  /** Only set for supported, known probe kinds; 'unknown' for unsupported */
  safeKind: ActiveReconDocumentProbeKind | 'unknown';
  status: 'completed' | 'blocked' | 'candidate' | 'failed';
  policyDecision: 'allow' | 'block' | 'candidate' | 'none';
  /** Safe target representation — never includes raw targetUrl */
  target: {
    normalizedOrigin?: string;
    safeDisplayUrl?: string;
  };
  observations: SafeActiveReconObservation[];
  error?: {
    code: ActiveReconDocumentProbeErrorCode;
    /** Message must not include raw URLs, IDs, or unsupported kind values */
    message: string;
  };
};

export type ActiveReconBatchDisposition =
  | "authorization_denied"
  | "preflight_denied"
  | "execution_completed"
  | "execution_failed";

// The aggregated runner result
export type ActiveReconDocumentProbeRunResult = {
  runId: string;
  disposition: ActiveReconBatchDisposition;
  requestedProbeCount: number;
  completedProbeCount: number;
  blockedProbeCount: number;
  failedProbeCount: number;
  candidateProbeCount: number;
  probes: ActiveReconDocumentProbeRunProbeResult[];
  /** All observations aggregated across all completed probes */
  observations: SafeActiveReconObservation[];
  classification: {
    finding: false;
    evidence: false;
    vulnerability: false;
    riskClaim: false;
  };
};
