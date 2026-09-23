import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';

export type TlsInspectionContractVersion = 'fixguard-tls-inspection/v0';
export const TLS_INSPECTION_CONTRACT_VERSION: TlsInspectionContractVersion =
  'fixguard-tls-inspection/v0';

export interface TlsInspectionExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const TLS_INSPECTION_NON_CLAIMS: TlsInspectionExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetworkPayloads: false,
  severity: 'info',
});

export interface DiscoveredTlsObservation {
  readonly host: string;
  readonly port: number;
  readonly ip?: string;
  readonly issuer?: string;
  readonly subjectAlternativeNames: readonly string[];
  readonly supportedProtocols: readonly string[];
  readonly cipherSuites: readonly string[];
  readonly notBefore?: string;
  readonly notAfter?: string;
  readonly expired?: boolean;
  readonly selfSigned?: boolean;
  readonly discoveredAt: string;
  readonly collectedAt?: string;
  readonly freshness?: 'live' | 'historical' | 'unknown';
  readonly sourceReliability?: 'direct_observation' | 'historical_archive' | 'inferred_relationship';
}

export interface TlsInspectionRequest {
  readonly targetHostOrUrl: string;
  readonly targetPorts?: readonly number[];
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timeoutMs?: number;
}

export type TlsInspectionResult =
  | {
      readonly status: 'success';
      readonly contractVersion: TlsInspectionContractVersion;
      readonly targetHost: string;
      readonly observations: readonly DiscoveredTlsObservation[];
      readonly explicitNonClaims: TlsInspectionExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: TlsInspectionContractVersion;
      readonly targetHost: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: TlsInspectionExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
    }
  | {
      readonly status: 'execution_failed';
      readonly contractVersion: TlsInspectionContractVersion;
      readonly targetHost: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: TlsInspectionExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly exitCode?: number;
      readonly stderr?: string;
      readonly durationMs?: number;
    };

export interface TlsInspectionTool {
  inspectTls(request: TlsInspectionRequest): Promise<TlsInspectionResult>;
}
