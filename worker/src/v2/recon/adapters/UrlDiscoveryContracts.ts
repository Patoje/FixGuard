import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';

export type UrlDiscoveryContractVersion = 'fixguard-url-discovery/v0';
export const URL_DISCOVERY_CONTRACT_VERSION: UrlDiscoveryContractVersion =
  'fixguard-url-discovery/v0';

export interface UrlDiscoveryExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const URL_DISCOVERY_NON_CLAIMS: UrlDiscoveryExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetworkPayloads: false,
  severity: 'info',
});

export interface DiscoveredUrlObservation {
  readonly url: string;
  readonly host: string;
  readonly path: string;
  readonly query?: string;
  readonly sources: readonly string[];
  readonly discoveredAt: string;
  readonly collectedAt?: string;
  readonly freshness?: 'live' | 'historical' | 'unknown';
  readonly sourceReliability?: 'direct_observation' | 'historical_archive' | 'inferred_relationship';
}

export interface UrlDiscoveryRequest {
  readonly targetUrlOrDomain: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timeoutMs?: number;
  readonly maxDepth?: number;
}

export type UrlDiscoveryResult =
  | {
      readonly status: 'success';
      readonly contractVersion: UrlDiscoveryContractVersion;
      readonly targetUrlOrDomain: string;
      readonly observations: readonly DiscoveredUrlObservation[];
      readonly explicitNonClaims: UrlDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: UrlDiscoveryContractVersion;
      readonly targetUrlOrDomain: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: UrlDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
    }
  | {
      readonly status: 'execution_failed';
      readonly contractVersion: UrlDiscoveryContractVersion;
      readonly targetUrlOrDomain: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: UrlDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly exitCode?: number;
      readonly stderr?: string;
      readonly durationMs?: number;
    };

export interface UrlDiscoveryTool {
  discoverUrls(request: UrlDiscoveryRequest): Promise<UrlDiscoveryResult>;
}
