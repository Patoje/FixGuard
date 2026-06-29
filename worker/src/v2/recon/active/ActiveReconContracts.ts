import type { AuthorizedScope } from '../policy/EgressPolicyContracts.js';

export type ActiveReconProbeKind =
  | 'http.robots.inspect'
  | 'http.security_txt.inspect';

export interface ActiveReconProbeRequest {
  capabilityId: ActiveReconProbeKind;
  targetUrl: string;
  authorizedScope: AuthorizedScope;
  requestedAtMs: number;
}

export type SafeActiveReconObservation = {
  kind: 'robots_metadata' | 'security_txt_metadata';
  safeSummary: string;
  confidence: 'low' | 'medium' | 'high';
};

export type ActiveReconProbeStatus =
  | 'observed'
  | 'blocked'
  | 'candidate'
  | 'skipped';

export interface ActiveReconProbeResult {
  capabilityId: ActiveReconProbeKind;
  status: ActiveReconProbeStatus;
  policyDecision: 'allow' | 'block' | 'candidate';
  target: {
    safeDisplayUrl: string;
    scheme?: 'http' | 'https';
    hostname?: string;
    normalizedOrigin?: string;
  };
  observations: SafeActiveReconObservation[];
  classification: {
    finding: false;
    evidence: false;
    vulnerability: false;
    riskClaim: false;
  };
}
