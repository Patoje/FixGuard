import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';

export type DnsResolutionContractVersion = 'fixguard-dns-resolution/v0';
export const DNS_RESOLUTION_CONTRACT_VERSION: DnsResolutionContractVersion =
  'fixguard-dns-resolution/v0';

export type DnsRecordType = 'A' | 'AAAA' | 'CNAME' | 'TXT' | 'MX';

export interface DnsResolutionExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const DNS_RESOLUTION_NON_CLAIMS: DnsResolutionExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetworkPayloads: false,
  severity: 'info',
});

export interface DiscoveredDnsObservation {
  readonly domain: string;
  readonly recordType: DnsRecordType;
  readonly values: readonly string[];
  readonly discoveredAt: string;
}

export interface DnsResolutionRequest {
  readonly targetDomain: string;
  readonly recordTypes?: readonly DnsRecordType[];
  readonly resolvers?: readonly string[];
  readonly wildcardFiltering?: boolean;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timeoutMs?: number;
}

export type DnsResolutionResult =
  | {
      readonly status: 'success';
      readonly contractVersion: DnsResolutionContractVersion;
      readonly targetDomain: string;
      readonly observations: readonly DiscoveredDnsObservation[];
      readonly explicitNonClaims: DnsResolutionExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: DnsResolutionContractVersion;
      readonly targetDomain: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: DnsResolutionExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
    }
  | {
      readonly status: 'execution_failed';
      readonly contractVersion: DnsResolutionContractVersion;
      readonly targetDomain: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: DnsResolutionExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly exitCode?: number;
      readonly stderr?: string;
      readonly durationMs?: number;
    };

export interface DnsResolutionTool {
  resolveDns(request: DnsResolutionRequest): Promise<DnsResolutionResult>;
}
