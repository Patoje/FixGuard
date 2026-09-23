import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';

export type PortDiscoveryContractVersion = 'fixguard-port-discovery/v0';
export const PORT_DISCOVERY_CONTRACT_VERSION: PortDiscoveryContractVersion =
  'fixguard-port-discovery/v0';

export interface PortDiscoveryExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const PORT_DISCOVERY_NON_CLAIMS: PortDiscoveryExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetworkPayloads: false,
  severity: 'info',
});

export interface DiscoveredPortObservation {
  readonly host: string;
  readonly ip: string;
  readonly port: number;
  readonly protocol: 'tcp';
  readonly state: 'open';
  readonly discoveredAt: string;
  readonly collectedAt?: string;
  readonly freshness?: 'live' | 'historical' | 'unknown';
  readonly sourceReliability?: 'direct_observation' | 'historical_archive' | 'inferred_relationship';
}

export interface PortDiscoveryRequest {
  readonly targetHostOrIp: string;
  readonly targetPorts?: readonly (number | string)[];
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timeoutMs?: number;
  readonly rate?: number;
}

export type PortDiscoveryResult =
  | {
      readonly status: 'success';
      readonly contractVersion: PortDiscoveryContractVersion;
      readonly targetHostOrIp: string;
      readonly observations: readonly DiscoveredPortObservation[];
      readonly explicitNonClaims: PortDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: PortDiscoveryContractVersion;
      readonly targetHostOrIp: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: PortDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
    }
  | {
      readonly status: 'execution_failed';
      readonly contractVersion: PortDiscoveryContractVersion;
      readonly targetHostOrIp: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: PortDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly exitCode?: number;
      readonly stderr?: string;
      readonly durationMs?: number;
    };

export interface PortDiscoveryTool {
  discoverPorts(request: PortDiscoveryRequest): Promise<PortDiscoveryResult>;
}
