/**
 * Milestone M1 — Auth Boundary Differential Contracts
 * Contract version: fixguard-detection/v0 (shared detection family)
 *
 * Auth boundary = authenticated resource vs unauthenticated (anon) access on the
 * SAME observed account/order path (A 200 / anon 302-login = secure).
 * Distinct from BOLA/IDOR (same object ID cross-user A↔B).
 *
 * Does NOT invent object/order IDs. GET-only comparable probes.
 */

import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import type {
  AuthorizedExecutionLineageTuple,
  DetectionContractVersion,
  IdorHttpProbeTransport,
  ProbeAuthContext,
} from './DetectionContracts.js';

export type AuthBoundaryInvestigationOutcome =
  | 'secure'
  | 'suspicious'
  | 'validated'
  | 'refuted'
  | 'interfered'
  | 'inconclusive';

export type AuthBoundaryDetectionStatus =
  | 'boundary_secure'
  | 'boundary_suspicious'
  | 'boundary_validated'
  | 'boundary_refuted'
  | 'measurement_interfered'
  | 'measurement_inconclusive'
  | 'preflight_denied'
  | 'unexpected_failure';

/**
 * Safe comparable facets from a single GET probe — no raw cookies / Authorization.
 */
export interface AuthBoundaryProbeFacet {
  readonly identityRole: 'authenticated_a' | 'authenticated_b' | 'anonymous';
  readonly identityId: string;
  readonly statusCode: number;
  readonly redirectLocationHostPath?: string;
  readonly contentType?: string;
  readonly bodyHash: string;
  readonly bodyLength: number;
  readonly bodyShapeKind: 'empty' | 'json_object' | 'json_array' | 'html' | 'text';
}

export interface AuthBoundaryDifferentialDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'auth_boundary_differential_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly endpointUrl: string;
  /** Authenticated baseline (Identity A). Required. */
  readonly identityA: ProbeAuthContext;
  /** Optional second authenticated identity (BYOT B). Never required for A+anon. */
  readonly identityB?: ProbeAuthContext;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface AuthBoundaryDifferentialDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'auth_boundary_differential_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: AuthBoundaryDetectionStatus;
  readonly investigationOutcome: AuthBoundaryInvestigationOutcome;
  readonly reasonCode: string;
  readonly safeMessage: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly endpointUrl: string;
  readonly facets?: readonly AuthBoundaryProbeFacet[];
  readonly bodySimilarityRatio?: number;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}
