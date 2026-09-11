import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';

export type SubdomainDiscoveryContractVersion = 'fixguard-subdomain-discovery/v0';
export const SUBDOMAIN_DISCOVERY_CONTRACT_VERSION: SubdomainDiscoveryContractVersion =
  'fixguard-subdomain-discovery/v0';

export interface SubdomainDiscoveryExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const SUBDOMAIN_DISCOVERY_NON_CLAIMS: SubdomainDiscoveryExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetworkPayloads: false,
  severity: 'info',
});

export interface DiscoveredSubdomainObservation {
  readonly subdomain: string;
  readonly parentDomain: string;
  readonly ipAddresses?: readonly string[];
  readonly sources?: readonly string[];
  readonly discoveredAt: string;
  readonly confidence: number;
}

export interface SubdomainDiscoveryRequest {
  readonly targetDomain: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timeoutMs?: number;
}

export type SubdomainDiscoveryResult =
  | {
      readonly status: 'success';
      readonly contractVersion: SubdomainDiscoveryContractVersion;
      readonly targetDomain: string;
      readonly observations: readonly DiscoveredSubdomainObservation[];
      readonly explicitNonClaims: SubdomainDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: SubdomainDiscoveryContractVersion;
      readonly targetDomain: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: SubdomainDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
    }
  | {
      readonly status: 'execution_failed';
      readonly contractVersion: SubdomainDiscoveryContractVersion;
      readonly targetDomain: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: SubdomainDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly exitCode?: number;
      readonly stderr?: string;
      readonly durationMs?: number;
    };

export interface SubdomainDiscoveryTool {
  discoverSubdomains(request: SubdomainDiscoveryRequest): Promise<SubdomainDiscoveryResult>;
}
