import type { AuthorizedScope } from '../policy/EgressPolicyContracts.js';
import type { SafeActiveReconObservation } from './ActiveReconContracts.js';

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

// The run request. targetUrl is transient input only.
export type ActiveReconDocumentProbeRunRequest = {
  /** Optional caller-assigned run ID; a UUID is generated if absent */
  runId?: string;
  authorizedScope: AuthorizedScope;
  authorization: {
    /** Must be set explicitly by caller — prevents accidental invocation */
    confirmed: true;
    /** Optional human-readable label for audit log / smoke proof only */
    scopeLabel?: string;
  };
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
  | 'adapter_failed';

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

// The aggregated runner result
export type ActiveReconDocumentProbeRunResult = {
  runId: string;
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
