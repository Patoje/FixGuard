import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';

export type SecretDiscoveryContractVersion = 'fixguard-secret-discovery/v0';
export const SECRET_DISCOVERY_CONTRACT_VERSION: SecretDiscoveryContractVersion =
  'fixguard-secret-discovery/v0';

export interface SecretDiscoveryExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const SECRET_DISCOVERY_NON_CLAIMS: SecretDiscoveryExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetworkPayloads: false,
  severity: 'info',
});

export interface DiscoveredSecretObservation {
  readonly locationUrl: string;
  readonly detectorName: string;
  readonly redactedSecret: string;
  readonly discoveredAt: string;
  readonly verified?: boolean;
  readonly collectedAt?: string;
  readonly freshness?: 'live' | 'historical' | 'unknown';
  readonly sourceReliability?: 'direct_observation' | 'historical_archive' | 'inferred_relationship';
}

export interface SecretDiscoveryRequest {
  readonly targetUrlOrPath: string;
  readonly scanType?: 'git' | 'filesystem';
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timeoutMs?: number;
}

export type SecretDiscoveryResult =
  | {
      readonly status: 'success';
      readonly contractVersion: SecretDiscoveryContractVersion;
      readonly targetUrlOrPath: string;
      readonly observations: readonly DiscoveredSecretObservation[];
      readonly explicitNonClaims: SecretDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: SecretDiscoveryContractVersion;
      readonly targetUrlOrPath: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: SecretDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
    }
  | {
      readonly status: 'execution_failed';
      readonly contractVersion: SecretDiscoveryContractVersion;
      readonly targetUrlOrPath: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: SecretDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly exitCode?: number;
      readonly stderr?: string;
      readonly durationMs?: number;
    };

export interface SecretScannerTool {
  scanSecrets(request: SecretDiscoveryRequest): Promise<SecretDiscoveryResult>;
}
