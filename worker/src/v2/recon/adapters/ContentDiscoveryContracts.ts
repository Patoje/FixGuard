import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';

export type ContentDiscoveryContractVersion = 'fixguard-content-discovery/v0';
export const CONTENT_DISCOVERY_CONTRACT_VERSION: ContentDiscoveryContractVersion =
  'fixguard-content-discovery/v0';

export interface ContentDiscoveryExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const CONTENT_DISCOVERY_NON_CLAIMS: ContentDiscoveryExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetworkPayloads: false,
  severity: 'info',
});

export interface DiscoveredContentObservation {
  readonly url: string;
  readonly path: string;
  readonly statusCode: number;
  readonly contentLength?: number;
  readonly contentType?: string;
  readonly redirectLocation?: string;
  readonly discoveredAt: string;
}

export interface ContentDiscoveryRequest {
  readonly targetUrl: string;
  readonly wordlistPath: string;
  readonly rateLimit?: number;
  readonly delaySeconds?: number;
  readonly autoCalibrate?: boolean;
  readonly recursionDepth?: number;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timeoutMs?: number;
}

export type ContentDiscoveryResult =
  | {
      readonly status: 'success';
      readonly contractVersion: ContentDiscoveryContractVersion;
      readonly targetUrl: string;
      readonly wordlistPath: string;
      readonly observations: readonly DiscoveredContentObservation[];
      readonly explicitNonClaims: ContentDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: ContentDiscoveryContractVersion;
      readonly targetUrl: string;
      readonly wordlistPath: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: ContentDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
    }
  | {
      readonly status: 'execution_failed';
      readonly contractVersion: ContentDiscoveryContractVersion;
      readonly targetUrl: string;
      readonly wordlistPath: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: ContentDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly exitCode?: number;
      readonly stderr?: string;
      readonly durationMs?: number;
    };

export interface ContentDiscoveryTool {
  discoverContent(request: ContentDiscoveryRequest): Promise<ContentDiscoveryResult>;
}
