import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';

export type WebInspectionContractVersion = 'fixguard-web-inspection/v0';
export const WEB_INSPECTION_CONTRACT_VERSION: WebInspectionContractVersion =
  'fixguard-web-inspection/v0';

export interface WebInspectionExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const WEB_INSPECTION_NON_CLAIMS: WebInspectionExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetworkPayloads: false,
  severity: 'info',
});

export interface DiscoveredWebObservation {
  readonly url: string;
  readonly method: string;
  readonly statusCode: number;
  readonly title?: string;
  readonly webServer?: string;
  readonly technologies: readonly string[];
  readonly resolvedIp?: string;
  readonly discoveredAt: string;
  readonly collectedAt?: string;
  readonly freshness?: 'live' | 'historical' | 'unknown';
  readonly sourceReliability?: 'direct_observation' | 'historical_archive' | 'inferred_relationship';
}

export interface WebInspectionRequest {
  readonly targetUrl: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timeoutMs?: number;
}

export type WebInspectionResult =
  | {
      readonly status: 'success';
      readonly contractVersion: WebInspectionContractVersion;
      readonly targetUrl: string;
      readonly observations: readonly DiscoveredWebObservation[];
      readonly explicitNonClaims: WebInspectionExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: WebInspectionContractVersion;
      readonly targetUrl: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: WebInspectionExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
    }
  | {
      readonly status: 'execution_failed';
      readonly contractVersion: WebInspectionContractVersion;
      readonly targetUrl: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: WebInspectionExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly exitCode?: number;
      readonly stderr?: string;
      readonly durationMs?: number;
    };

export interface WebInspectionTool {
  inspectWeb(request: WebInspectionRequest): Promise<WebInspectionResult>;
}
