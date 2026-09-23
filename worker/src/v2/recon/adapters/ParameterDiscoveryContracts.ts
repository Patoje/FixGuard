import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';

export type ParameterDiscoveryContractVersion = 'fixguard-parameter-discovery/v0';
export const PARAMETER_DISCOVERY_CONTRACT_VERSION: ParameterDiscoveryContractVersion =
  'fixguard-parameter-discovery/v0';

export type HttpParameterMethod = 'GET' | 'POST' | 'JSON' | 'XML';

export interface ParameterDiscoveryExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const PARAMETER_DISCOVERY_NON_CLAIMS: ParameterDiscoveryExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetworkPayloads: false,
  severity: 'info',
});

export interface DiscoveredParameterObservation {
  readonly url: string;
  readonly method: HttpParameterMethod;
  readonly parameterName: string;
  readonly discoveredAt: string;
  readonly collectedAt?: string;
  readonly freshness?: 'live' | 'historical' | 'unknown';
  readonly sourceReliability?: 'direct_observation' | 'historical_archive' | 'inferred_relationship';
}

export interface ParameterDiscoveryRequest {
  readonly targetUrl: string;
  readonly httpMethod?: HttpParameterMethod;
  readonly chunkSize?: number;
  readonly delaySeconds?: number;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timeoutMs?: number;
}

export type ParameterDiscoveryResult =
  | {
      readonly status: 'success';
      readonly contractVersion: ParameterDiscoveryContractVersion;
      readonly targetUrl: string;
      readonly observations: readonly DiscoveredParameterObservation[];
      readonly explicitNonClaims: ParameterDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: ParameterDiscoveryContractVersion;
      readonly targetUrl: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: ParameterDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
    }
  | {
      readonly status: 'execution_failed';
      readonly contractVersion: ParameterDiscoveryContractVersion;
      readonly targetUrl: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: ParameterDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly exitCode?: number;
      readonly stderr?: string;
      readonly durationMs?: number;
    };

export interface ParameterDiscoveryTool {
  discoverParameters(request: ParameterDiscoveryRequest): Promise<ParameterDiscoveryResult>;
}
