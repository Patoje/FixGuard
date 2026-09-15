/**
 * Milestone 8 — Controlled Active Verification & Safe PoC Engine Contracts
 *
 * Contract Version: fixguard-active-verification/v0
 *
 * Invariants:
 * 1. Human Authorization Gate: Requires explicit VerifiedExploitationAuthorizationDecision
 *    sealed via ADR-001 WeakSet brand.
 * 2. Non-Destructive Payloads Only: Inert canaries, differential read probes, non-destructive headers.
 * 3. Double SSRF & Egress Gate: Preflight static/dynamic DNS rebinding check + Egress gate.
 * 4. Blast Radius & Target Circuit Breaker: Enforces TargetExecutionCoordinator ceilings & circuit trip states.
 * 5. Cryptographic Proof: Auditable SHA-256 request/response hashes, sanitized diffs, continuous lineage.
 * 6. Strictly zero type bypasses.
 */

import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';

export type ActiveVerificationContractVersion = 'fixguard-active-verification/v0';
export const ACTIVE_VERIFICATION_CONTRACT_VERSION: ActiveVerificationContractVersion =
  'fixguard-active-verification/v0';

export type SafeExploitationVectorKind =
  | 'idor_read_differential'
  | 'cors_arbitrary_origin_reflection'
  | 'parameter_reflection_canary'
  | 'security_header_enforcement';

export interface ActiveVerificationExplicitNonClaims {
  readonly executesDestructivePayloads: false;
  readonly modifiesTargetState: false;
  readonly exploitsServiceDenial: false;
  readonly causesDataLoss: false;
  readonly requiresHumanAuthorization: true;
  readonly severity: 'info';
}

export const ACTIVE_VERIFICATION_NON_CLAIMS: ActiveVerificationExplicitNonClaims = Object.freeze({
  executesDestructivePayloads: false,
  modifiesTargetState: false,
  exploitsServiceDenial: false,
  causesDataLoss: false,
  requiresHumanAuthorization: true,
  severity: 'info',
});

// ---------------------------------------------------------------------------
// ADR-001 WeakSet Brand for Verified Exploitation Authorization Decision
// ---------------------------------------------------------------------------

const _exploitationDecisionBrand = new WeakSet<object>();

export interface VerifiedExploitationAuthorizationDecision {
  readonly contractVersion: ActiveVerificationContractVersion;
  readonly kind: 'verified_exploitation_authorization_decision';
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly candidateId: string;
  readonly targetUrl: string;
  readonly allowedVector: SafeExploitationVectorKind;
  readonly authorizedActor: {
    readonly actorId: string;
    readonly actorType: 'human';
  };
  readonly decision: 'authorized';
  readonly decidedAt: string;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly verification: {
    readonly verifiedAt: string;
    readonly method: 'trusted_application_boundary';
  };
}

export interface EstablishExploitationDecisionRequest {
  readonly contractVersion: ActiveVerificationContractVersion;
  readonly kind: 'establish_verified_exploitation_decision_request';
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationDecisionId: string;
  readonly candidateId: string;
  readonly targetUrl: string;
  readonly allowedVector: SafeExploitationVectorKind;
  readonly authorizedActor: {
    readonly actorId: string;
    readonly actorType: 'human';
  };
  readonly decision: 'authorized';
  readonly decidedAt: string;
  readonly scopeGrant: AuthorizedScopeGrant;
}

export type EstablishExploitationDecisionResult =
  | {
      readonly status: 'established';
      readonly decision: VerifiedExploitationAuthorizationDecision;
    }
  | {
      readonly status: 'failed';
      readonly reasonCode: string;
      readonly safeMessage: string;
    };

export function establishVerifiedExploitationDecision(
  request: EstablishExploitationDecisionRequest,
  nowIso?: string
): EstablishExploitationDecisionResult {
  const evaluatedAt = nowIso ?? new Date().toISOString();

  if (request.contractVersion !== ACTIVE_VERIFICATION_CONTRACT_VERSION) {
    return {
      status: 'failed',
      reasonCode: 'invalid_contract_version',
      safeMessage: 'Invalid contractVersion for exploitation decision',
    };
  }

  if (request.decision !== 'authorized') {
    return {
      status: 'failed',
      reasonCode: 'decision_not_authorized',
      safeMessage: 'Only authorized decisions may establish a verified exploitation token',
    };
  }

  if (request.authorizedActor.actorType !== 'human') {
    return {
      status: 'failed',
      reasonCode: 'forbidden_actor_type',
      safeMessage: 'Only human operators can authorize active verification exploitation probes',
    };
  }

  const decisionObj: VerifiedExploitationAuthorizationDecision = {
    contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
    kind: 'verified_exploitation_authorization_decision',
    assessmentId: request.assessmentId,
    scanId: request.scanId,
    authorizationGrantId: request.scopeGrant.grantId,
    authorizationDecisionId: request.authorizationDecisionId,
    candidateId: request.candidateId,
    targetUrl: request.targetUrl,
    allowedVector: request.allowedVector,
    authorizedActor: { ...request.authorizedActor },
    decision: 'authorized',
    decidedAt: request.decidedAt,
    scopeGrant: request.scopeGrant,
    verification: {
      verifiedAt: evaluatedAt,
      method: 'trusted_application_boundary',
    },
  };

  _exploitationDecisionBrand.add(decisionObj);

  return {
    status: 'established',
    decision: Object.freeze(decisionObj),
  };
}

export function isRuntimeEstablishedExploitationDecision(
  value: unknown
): value is VerifiedExploitationAuthorizationDecision {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return _exploitationDecisionBrand.has(value);
}

// ---------------------------------------------------------------------------
// Active Verification Command & Proof
// ---------------------------------------------------------------------------

export interface ActiveVerificationCommand {
  readonly candidateId: string;
  readonly targetUrl: string;
  readonly httpMethod?: 'GET' | 'POST' | 'OPTIONS' | 'HEAD';
  readonly vector: SafeExploitationVectorKind;
  readonly canaryToken?: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly queryParams?: Readonly<Record<string, string>>;
  readonly bodyText?: string;
  readonly verifiedAuthorizationDecision: VerifiedExploitationAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly coordinator?: TargetExecutionCoordinator;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly timeoutMs?: number;
}

export interface ActiveVerificationProofRecord {
  readonly candidateId: string;
  readonly vector: SafeExploitationVectorKind;
  readonly targetUrl: string;
  readonly requestHash: string;
  readonly responseHash: string;
  readonly statusCode: number;
  readonly canaryReflected?: boolean;
  readonly sanitizedExcerpt: string;
  readonly responseTimeMs: number;
  readonly verifiedAt: string;
}

export interface VerificationHttpRequest {
  readonly url: string;
  readonly method: 'GET' | 'POST' | 'OPTIONS' | 'HEAD';
  readonly headers: Readonly<Record<string, string>>;
  readonly bodyText?: string;
  readonly timeoutMs?: number;
}

export interface VerificationHttpResponse {
  readonly statusCode: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly bodyText: string;
  readonly responseTimeMs: number;
}

export type VerificationHttpTransport = (
  req: VerificationHttpRequest
) => Promise<VerificationHttpResponse>;

export interface ConfirmedFindingCandidateRecord {
  readonly candidateId: string;
  readonly type: string;
  readonly severity: 'high' | 'medium';
  readonly exploitConfidence: 1.0;
  readonly proofSummary: string;
}

export type ActiveVerificationResult =
  | {
      readonly status: 'exploit_confirmed';
      readonly contractVersion: ActiveVerificationContractVersion;
      readonly command: ActiveVerificationCommand;
      readonly proof: ActiveVerificationProofRecord;
      readonly confirmedFindingCandidate: ConfirmedFindingCandidateRecord;
      readonly explicitNonClaims: ActiveVerificationExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'exploit_refuted';
      readonly contractVersion: ActiveVerificationContractVersion;
      readonly command: ActiveVerificationCommand;
      readonly reasonCode: 'target_enforced_control' | 'canary_not_reflected' | 'access_denied';
      readonly reason: string;
      readonly responseStatus: number;
      readonly responseHash: string;
      readonly explicitNonClaims: ActiveVerificationExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'circuit_broken';
      readonly contractVersion: ActiveVerificationContractVersion;
      readonly targetHost: string;
      readonly reasonCode: 'target_instability_circuit_open';
      readonly reason: string;
      readonly explicitNonClaims: ActiveVerificationExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: ActiveVerificationContractVersion;
      readonly targetUrl: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: ActiveVerificationExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'verification_failed';
      readonly contractVersion: ActiveVerificationContractVersion;
      readonly targetUrl: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: ActiveVerificationExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    };
