/**
 * FixGuard V2 — Auth Differential Matrix Contracts.
 * Contract version: fixguard-auth-differential/v0
 *
 * Defines models and evaluation criteria for general matrix comparison
 * across anonymous and authenticated contexts.
 *
 * Invariants:
 * 1. Zero speculative vulnerability claims: an observed difference is an OBSERVED fact,
 *    not an automatic vulnerability or IDOR finding.
 * 2. Closed-world classification: strict union of outcomes.
 * 3. Lineage preservation: propagates continuous 5-tuple lineage into all generated facts.
 * 4. Configurable budget: no arbitrary 2-endpoint hardcoding; bounded by request budget.
 */

import type { HttpMethod } from '../comparison/ResponseComparatorContracts.js';
import type { ObservedFact } from '../observation/ObservedFactContracts.js';
import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { SessionSanctuaryService } from '../session/SessionSanctuaryService.js';

export const AUTH_DIFFERENTIAL_CONTRACT_VERSION = 'fixguard-auth-differential/v0' as const;
export type AuthDifferentialContractVersion = typeof AUTH_DIFFERENTIAL_CONTRACT_VERSION;

export type AuthDifferentialClassification =
  | 'expected_auth_difference'
  | 'protected'
  | 'authentication_required'
  | 'application_behavior_differs'
  | 'potential_authorization_boundary'
  | 'interfered'
  | 'inconclusive';

export interface AuthDifferentialEndpointResult {
  readonly endpointUrl: string;
  readonly method: 'GET' | 'HEAD';
  readonly classification: AuthDifferentialClassification;
  readonly reasonCode: string;
  readonly explanation: string;
  readonly anonStatusCode: number;
  readonly authStatusCode: number;
  readonly anonBodyHash: string;
  readonly authBodyHash: string;
  readonly anonBodyShape?: 'empty' | 'json_object' | 'json_array' | 'html' | 'text';
  readonly authBodyShape?: 'empty' | 'json_object' | 'json_array' | 'html' | 'text';
  readonly interfered: boolean;
  readonly observedFact: ObservedFact | null;
}

export interface AuthDifferentialMatrixRequest {
  readonly targetDomain: string;
  readonly endpointUrls: readonly string[];
  readonly sessionSanctuary: SessionSanctuaryService;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  /** Explicit maximum number of endpoints to evaluate. Default: 15. */
  readonly maxEndpoints?: number;
  readonly observedAt?: string;
}

export interface AuthDifferentialMatrixResult {
  readonly contractVersion: AuthDifferentialContractVersion;
  readonly targetDomain: string;
  readonly evaluatedAt: string;
  readonly totalEvaluated: number;
  readonly results: readonly AuthDifferentialEndpointResult[];
  readonly generatedFacts: readonly ObservedFact[];
  readonly summaryCounts: Readonly<Record<AuthDifferentialClassification, number>>;
}
