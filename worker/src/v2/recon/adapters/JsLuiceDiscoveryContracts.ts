/**
 * Etapa 2 · P3 — jsluice discovery-only contracts.
 * Extracts endpoints / params / secret *kinds* from JavaScript sources.
 * Never creates findings or severities. Secrets are redacted.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';
import type { DiscoveredUrlObservation } from './UrlDiscoveryContracts.js';
import type { DiscoveredSecretObservation } from './SecretDiscoveryContracts.js';

export type JsLuiceDiscoveryContractVersion = 'fixguard-jsluice-discovery/v0';
export const JSLUICE_DISCOVERY_CONTRACT_VERSION: JsLuiceDiscoveryContractVersion =
  'fixguard-jsluice-discovery/v0';

export interface JsLuiceDiscoveryExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  /** Remote URL mode may fetch JS for parsing; payloads are never executed in-app. */
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const JSLUICE_DISCOVERY_NON_CLAIMS: JsLuiceDiscoveryExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetworkPayloads: false,
  severity: 'info',
});

export interface DiscoveredJsParameterObservation {
  readonly sourceUrl: string;
  readonly parameterName: string;
  readonly location: 'query' | 'body' | 'unknown';
  readonly discoveredAt: string;
}

export interface JsLuiceDiscoveryRequest {
  readonly targetJsUrlOrPath: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timeoutMs?: number;
  /** Absolute base URL for resolving relative paths extracted from JS. */
  readonly resolvePathsBase?: string;
}

export type JsLuiceDiscoveryResult =
  | {
      readonly status: 'success';
      readonly contractVersion: JsLuiceDiscoveryContractVersion;
      readonly targetJsUrlOrPath: string;
      readonly urlObservations: readonly DiscoveredUrlObservation[];
      readonly parameterObservations: readonly DiscoveredJsParameterObservation[];
      readonly secretObservations: readonly DiscoveredSecretObservation[];
      readonly explicitNonClaims: JsLuiceDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: JsLuiceDiscoveryContractVersion;
      readonly targetJsUrlOrPath: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: JsLuiceDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
    }
  | {
      readonly status: 'execution_failed';
      readonly contractVersion: JsLuiceDiscoveryContractVersion;
      readonly targetJsUrlOrPath: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: JsLuiceDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly exitCode?: number;
      readonly stderr?: string;
      readonly durationMs?: number;
    }
  | {
      readonly status: 'tool_unavailable';
      readonly contractVersion: JsLuiceDiscoveryContractVersion;
      readonly targetJsUrlOrPath: string;
      readonly reasonCode: 'jsluice_binary_missing';
      readonly reason: string;
      readonly explicitNonClaims: JsLuiceDiscoveryExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
    };

export interface JsLuiceDiscoveryTool {
  discoverFromJavaScript(request: JsLuiceDiscoveryRequest): Promise<JsLuiceDiscoveryResult>;
}
