/**
 * M56A — Verified Authorization Decision Service (DB-free)
 *
 * This module establishes, validates, and checks runtime-branded
 * VerifiedAuthorizationDecision artifacts.
 *
 * DESIGN: module-private WeakSet brand
 * ------------------------------------
 * A WeakSet<object> is maintained as a module-private constant.
 * Only objects registered through `establishVerifiedAuthorizationDecision` are
 * added to the WeakSet. The validator rejects any object not present in the set,
 * even if it has exactly the same field values (structural equality is NOT
 * sufficient).
 *
 * LIMITATIONS:
 * - The brand is per-runtime-instance. A decision established in one Node.js
 *   process cannot be validated in another. This is intentional for the
 *   in-process DB-free boundary.
 * - This does NOT constitute cryptographic verification of the human actor's
 *   identity or the decision's integrity across process boundaries.
 * - M56A does not authenticate the actor. The actor identity is modeled but
 *   not verified by an external authority.
 *
 * AUTHORIZATION EVALUATION ORDER (conceptual):
 *   1. Runtime-established VerifiedAuthorizationDecision
 *   2. M46 evaluateScopePolicy (scope/action/permission validation)
 *   3. M30 evaluateEgressPolicy (network/SSRF gate)
 *   4. Adapter invocation
 *
 * M30 must never become the human authorization source.
 * M46 must never replace M30's network safety gate.
 * Both must pass before any network adapter invocation.
 */

import { validateAuthorizedScopeGrant } from '../scope/AuthorizedScopePolicyService.js';
import type {
  VerifiedAuthorizationDecision,
  EstablishVerifiedAuthorizationDecisionRequest,
  EstablishVerifiedAuthorizationDecisionResult,
  ValidateVerifiedAuthorizationDecisionResult,
} from './VerifiedAuthorizationDecisionContracts.js';
import {
  VERIFIED_AUTHORIZATION_DECISION_CONTRACT_VERSION,
} from './VerifiedAuthorizationDecisionContracts.js';

// ---------------------------------------------------------------------------
// Module-private runtime brand
//
// Only objects registered via establishVerifiedAuthorizationDecision are
// in this set. Structural lookalikes are rejected.
// ---------------------------------------------------------------------------

const _runtimeBrand = new WeakSet<object>();

// ---------------------------------------------------------------------------
// Safe string helpers
// ---------------------------------------------------------------------------

function isSafeId(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128) return false;
  return /^[a-zA-Z0-9_\-.:]+$/.test(value);
}

function isSafeIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const d = Date.parse(value);
  return !isNaN(d);
}

const FORBIDDEN_TERMS = [
  'secret', 'token', 'password', 'bearer', 'cookie',
  'api_key', 'apikey', 'access_token', 'refresh_token',
  'stack trace', 'error:', 'confirmed vulnerability', 'critical severity',
];

function hasForbiddenContent(value: string): boolean {
  const lower = value.toLowerCase();
  return FORBIDDEN_TERMS.some(t => lower.includes(t));
}

function isSafePrintableId(value: unknown): value is string {
  if (!isSafeId(value)) return false;
  return !hasForbiddenContent(value as string);
}

// ---------------------------------------------------------------------------
// Actor validator
// ---------------------------------------------------------------------------

function validateActor(actor: unknown): { valid: true } | { valid: false; safeMessage: string } {
  if (!actor || typeof actor !== 'object' || Array.isArray(actor)) {
    return { valid: false, safeMessage: 'authorizedActor must be a plain object' };
  }
  const a = actor as Record<string, unknown>;
  const keys = Object.keys(a);
  const allowedKeys = ['actorId', 'actorType'];
  for (const k of keys) {
    if (!allowedKeys.includes(k)) {
      return { valid: false, safeMessage: 'authorizedActor has unknown field' };
    }
  }
  if (!isSafePrintableId(a.actorId)) {
    return { valid: false, safeMessage: 'authorizedActor.actorId is invalid or unsafe' };
  }
  if (a.actorType !== 'human') {
    return { valid: false, safeMessage: 'authorizedActor.actorType must be "human"' };
  }
  return { valid: true };
}

// ---------------------------------------------------------------------------
// establishVerifiedAuthorizationDecision
// ---------------------------------------------------------------------------

export function establishVerifiedAuthorizationDecision(
  request: unknown,
  evaluatedAt: string
): EstablishVerifiedAuthorizationDecisionResult {
  try {
    // Validate evaluatedAt
    if (!isSafeIsoTimestamp(evaluatedAt)) {
      return {
        status: 'failed',
        reasonCode: 'establishment_request_invalid',
        safeMessage: 'evaluatedAt is not a valid ISO timestamp',
      };
    }

    // Validate request shape
    if (!request || typeof request !== 'object' || Array.isArray(request)) {
      return {
        status: 'failed',
        reasonCode: 'establishment_request_invalid',
        safeMessage: 'Request must be a plain object',
      };
    }

    const req = request as Record<string, unknown>;

    const allowedKeys = [
      'contractVersion', 'kind', 'assessmentId', 'scanId',
      'authorizationDecisionId', 'authorizedActor', 'decision',
      'decidedAt', 'scopeGrant',
    ];
    for (const k of Object.keys(req)) {
      if (!allowedKeys.includes(k)) {
        return {
          status: 'failed',
          reasonCode: 'establishment_request_invalid',
          safeMessage: 'Request contains unknown field',
        };
      }
    }

    if (req.contractVersion !== VERIFIED_AUTHORIZATION_DECISION_CONTRACT_VERSION) {
      return {
        status: 'failed',
        reasonCode: 'establishment_request_invalid',
        safeMessage: 'Invalid contractVersion',
      };
    }
    if (req.kind !== 'establish_verified_authorization_decision_request') {
      return {
        status: 'failed',
        reasonCode: 'establishment_request_invalid',
        safeMessage: 'Invalid kind',
      };
    }

    // Validate IDs
    if (!isSafePrintableId(req.assessmentId)) {
      return {
        status: 'failed',
        reasonCode: 'establishment_request_invalid',
        safeMessage: 'assessmentId is invalid or unsafe',
      };
    }
    if (!isSafePrintableId(req.scanId)) {
      return {
        status: 'failed',
        reasonCode: 'establishment_request_invalid',
        safeMessage: 'scanId is invalid or unsafe',
      };
    }
    if (!isSafePrintableId(req.authorizationDecisionId)) {
      return {
        status: 'failed',
        reasonCode: 'establishment_request_invalid',
        safeMessage: 'authorizationDecisionId is invalid or unsafe',
      };
    }

    // Validate decision — only 'authorized' produces an artifact
    if (req.decision !== 'authorized') {
      return {
        status: 'failed',
        reasonCode: 'decision_not_authorized',
        safeMessage: 'Only "authorized" decisions may produce a verified artifact',
      };
    }

    // Validate decidedAt
    if (!isSafeIsoTimestamp(req.decidedAt)) {
      return {
        status: 'failed',
        reasonCode: 'establishment_request_invalid',
        safeMessage: 'decidedAt is not a valid ISO timestamp',
      };
    }

    // Validate actor
    const actorResult = validateActor(req.authorizedActor);
    if (!actorResult.valid) {
      return {
        status: 'failed',
        reasonCode: 'actor_invalid',
        safeMessage: actorResult.safeMessage,
      };
    }

    // Validate scopeGrant via M46 validator
    const grantVal = validateAuthorizedScopeGrant(req.scopeGrant);
    if (!grantVal.isValid) {
      return {
        status: 'failed',
        reasonCode: 'scope_grant_invalid',
        safeMessage: 'scopeGrant failed M46 validation: ' + grantVal.message,
      };
    }

    const scopeGrant = req.scopeGrant as import('../scope/AuthorizedScopeContracts.js').AuthorizedScopeGrant;

    // Validate ID invariants
    if (req.scanId !== scopeGrant.scanId) {
      return {
        status: 'failed',
        reasonCode: 'id_invariant_violated',
        safeMessage: 'Request scanId does not match scopeGrant.scanId',
      };
    }

    // authorizationGrantId is derived from scopeGrant.grantId
    const authorizationGrantId = scopeGrant.grantId;

    // Temporal invariant: issuedAt <= evaluatedAt <= expiresAt
    const issuedAtMs = Date.parse(scopeGrant.issuedAt);
    const expiresAtMs = Date.parse(scopeGrant.expiresAt);
    const evaluatedAtMs = Date.parse(evaluatedAt);
    const decidedAtMs = Date.parse(req.decidedAt as string);

    if (isNaN(issuedAtMs) || isNaN(expiresAtMs)) {
      return {
        status: 'failed',
        reasonCode: 'scope_grant_invalid',
        safeMessage: 'scopeGrant has invalid temporal fields',
      };
    }

    if (evaluatedAtMs < issuedAtMs) {
      return {
        status: 'failed',
        reasonCode: 'temporal_invariant_violated',
        safeMessage: 'evaluatedAt is before grant issuedAt (not yet valid)',
      };
    }

    if (evaluatedAtMs > expiresAtMs) {
      return {
        status: 'failed',
        reasonCode: 'temporal_invariant_violated',
        safeMessage: 'evaluatedAt is after grant expiresAt (expired)',
      };
    }

    if (isNaN(decidedAtMs)) {
      return {
        status: 'failed',
        reasonCode: 'establishment_request_invalid',
        safeMessage: 'decidedAt is not a valid timestamp',
      };
    }

    // Build the immutable decision artifact
    const actorInput = req.authorizedActor as { actorId: string; actorType: 'human' };
    const frozenActor = Object.freeze({
      actorId: actorInput.actorId,
      actorType: 'human' as const,
    });

    const frozenVerification = Object.freeze({
      verifiedAt: evaluatedAt,
      method: 'trusted_application_boundary' as const,
    });

    // Deep-clone and freeze the scopeGrant to prevent shared mutation
    const frozenScopeGrant = cloneAndFreezeScopeGrant(scopeGrant);

    const decision: VerifiedAuthorizationDecision = Object.freeze({
      contractVersion: VERIFIED_AUTHORIZATION_DECISION_CONTRACT_VERSION,
      kind: 'verified_authorization_decision' as const,
      assessmentId: req.assessmentId as string,
      scanId: req.scanId as string,
      authorizationGrantId,
      authorizationDecisionId: req.authorizationDecisionId as string,
      authorizedActor: frozenActor,
      decision: 'authorized' as const,
      decidedAt: req.decidedAt as string,
      scopeGrant: frozenScopeGrant,
      verification: frozenVerification,
    });

    // Register with runtime brand
    _runtimeBrand.add(decision);

    return {
      status: 'established',
      reasonCode: 'verified_authorization_decision_established',
      decision,
    };
  } catch {
    return {
      status: 'failed',
      reasonCode: 'unexpected_establishment_failure',
      safeMessage: 'Unexpected failure during authorization decision establishment',
    };
  }
}

// ---------------------------------------------------------------------------
// isRuntimeEstablishedVerifiedAuthorizationDecision
// ---------------------------------------------------------------------------

export function isRuntimeEstablishedVerifiedAuthorizationDecision(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;
  return _runtimeBrand.has(value as object);
}

// ---------------------------------------------------------------------------
// validateVerifiedAuthorizationDecision
// ---------------------------------------------------------------------------

export function validateVerifiedAuthorizationDecision(
  value: unknown,
  evaluatedAt: string
): ValidateVerifiedAuthorizationDecisionResult {
  try {
    // 1. Runtime brand check — structural equality is NOT sufficient
    if (!isRuntimeEstablishedVerifiedAuthorizationDecision(value)) {
      return {
        status: 'invalid',
        reasonCode: 'not_runtime_established',
        safeMessage: 'Decision was not established by the trusted application boundary service',
      };
    }

    // 2. Basic structural checks
    if (!value || typeof value !== 'object') {
      return {
        status: 'invalid',
        reasonCode: 'decision_invalid',
        safeMessage: 'Decision is not an object',
      };
    }

    const d = value as Record<string, unknown>;

    if (d.contractVersion !== VERIFIED_AUTHORIZATION_DECISION_CONTRACT_VERSION) {
      return {
        status: 'invalid',
        reasonCode: 'decision_invalid',
        safeMessage: 'Invalid contractVersion on decision',
      };
    }
    if (d.kind !== 'verified_authorization_decision') {
      return {
        status: 'invalid',
        reasonCode: 'decision_invalid',
        safeMessage: 'Invalid kind on decision',
      };
    }
    if (d.decision !== 'authorized') {
      return {
        status: 'invalid',
        reasonCode: 'decision_invalid',
        safeMessage: 'Decision.decision must be "authorized"',
      };
    }

    // 3. Validate evaluatedAt and temporal invariants
    if (!isSafeIsoTimestamp(evaluatedAt)) {
      return {
        status: 'invalid',
        reasonCode: 'decision_invalid',
        safeMessage: 'evaluatedAt is not a valid ISO timestamp',
      };
    }

    const scopeGrant = d.scopeGrant as Record<string, unknown> | undefined;
    if (!scopeGrant) {
      return {
        status: 'invalid',
        reasonCode: 'scope_grant_invalid',
        safeMessage: 'scopeGrant is missing',
      };
    }

    const issuedAtMs = Date.parse(scopeGrant.issuedAt as string);
    const expiresAtMs = Date.parse(scopeGrant.expiresAt as string);
    const evaluatedAtMs = Date.parse(evaluatedAt);

    if (isNaN(issuedAtMs) || isNaN(expiresAtMs)) {
      return {
        status: 'invalid',
        reasonCode: 'scope_grant_invalid',
        safeMessage: 'scopeGrant temporal fields invalid',
      };
    }

    if (evaluatedAtMs < issuedAtMs) {
      return {
        status: 'invalid',
        reasonCode: 'temporal_invariant_violated',
        safeMessage: 'evaluatedAt is before grant issuedAt (not yet valid)',
      };
    }

    if (evaluatedAtMs > expiresAtMs) {
      return {
        status: 'invalid',
        reasonCode: 'temporal_invariant_violated',
        safeMessage: 'evaluatedAt is after grant expiresAt (expired)',
      };
    }

    // 4. Validate M46 grant still passes full validation
    const grantVal = validateAuthorizedScopeGrant(scopeGrant);
    if (!grantVal.isValid) {
      return {
        status: 'invalid',
        reasonCode: 'scope_grant_invalid',
        safeMessage: 'scopeGrant failed M46 validation: ' + grantVal.message,
      };
    }

    return { status: 'valid', reasonCode: 'valid_verified_authorization_decision' };
  } catch {
    return {
      status: 'invalid',
      reasonCode: 'unexpected_validation_failure',
      safeMessage: 'Unexpected failure during decision validation',
    };
  }
}

function cloneAndFreezeStringArray(arr?: readonly string[]): readonly string[] | undefined {
  if (!arr) return undefined;
  return Object.freeze([...arr]);
}

import type { AuthorizedScopeGrant, PathScopePattern } from '../scope/AuthorizedScopeContracts.js';

function cloneAndFreezePathPatterns(arr?: readonly PathScopePattern[]): readonly PathScopePattern[] | undefined {
  if (!arr) return undefined;
  return Object.freeze(arr.map(p => Object.freeze({ ...p })));
}

function cloneAndFreezeScopeGrant(grant: AuthorizedScopeGrant): AuthorizedScopeGrant {
  const subject = Object.freeze({
    targetKind: grant.subject.targetKind,
    normalizedOrigin: grant.subject.normalizedOrigin,
    host: grant.subject.host,
    domain: grant.subject.domain,
  });

  const authorizationBasis = Object.freeze({
    basisKind: grant.authorizationBasis.basisKind,
    recordedBy: grant.authorizationBasis.recordedBy,
    authorizationText: grant.authorizationBasis.authorizationText,
    referenceId: grant.authorizationBasis.referenceId,
  });

  const permissionSet = Object.freeze({
    passiveRecon: grant.permissionSet.passiveRecon,
    technologyFingerprinting: grant.permissionSet.technologyFingerprinting,
    endpointDiscovery: grant.permissionSet.endpointDiscovery,
    activeCrawling: grant.permissionSet.activeCrawling,
    authenticatedTesting: grant.permissionSet.authenticatedTesting,
    lightValidation: grant.permissionSet.lightValidation,
    activeValidation: grant.permissionSet.activeValidation,
    aggressiveValidation: grant.permissionSet.aggressiveValidation,
    oobTesting: grant.permissionSet.oobTesting,
    destructiveOperations: grant.permissionSet.destructiveOperations,
  });

  const boundaries = Object.freeze({
    allowedOrigins: cloneAndFreezeStringArray(grant.boundaries.allowedOrigins) as string[] | undefined,
    allowedHosts: cloneAndFreezeStringArray(grant.boundaries.allowedHosts) as string[] | undefined,
    allowedDomains: cloneAndFreezeStringArray(grant.boundaries.allowedDomains) as string[] | undefined,
    allowedMethods: cloneAndFreezeStringArray(grant.boundaries.allowedMethods) as import('../scope/AuthorizedScopeContracts.js').HttpMethod[] | undefined,
    deniedMethods: cloneAndFreezeStringArray(grant.boundaries.deniedMethods) as import('../scope/AuthorizedScopeContracts.js').HttpMethod[] | undefined,
    allowedPathPatterns: cloneAndFreezePathPatterns(grant.boundaries.allowedPathPatterns) as PathScopePattern[] | undefined,
    deniedPathPatterns: cloneAndFreezePathPatterns(grant.boundaries.deniedPathPatterns) as PathScopePattern[] | undefined,
  });

  const constraints = Object.freeze({
    maxRequestsPerMinute: grant.constraints.maxRequestsPerMinute,
    maxDepth: grant.constraints.maxDepth,
    maxRuntimeSeconds: grant.constraints.maxRuntimeSeconds,
    allowLoginRequiredAreas: grant.constraints.allowLoginRequiredAreas,
    allowStateChangingRequests: grant.constraints.allowStateChangingRequests,
    allowCredentialUse: grant.constraints.allowCredentialUse,
    allowOobCallbacks: grant.constraints.allowOobCallbacks,
    allowThirdPartyTargets: grant.constraints.allowThirdPartyTargets,
    notes: grant.constraints.notes,
  });

  const classification = Object.freeze({
    createsRealFindings: grant.classification.createsRealFindings,
    createsPersistedEvidence: grant.classification.createsPersistedEvidence,
    confirmsVulnerabilities: grant.classification.confirmsVulnerabilities,
    makesRiskClaims: grant.classification.makesRiskClaims,
    makesSeverityClaims: grant.classification.makesSeverityClaims,
    makesImpactClaims: grant.classification.makesImpactClaims,
    executesNetwork: grant.classification.executesNetwork,
    executesTools: grant.classification.executesTools,
    persistsData: grant.classification.persistsData,
  });

  return Object.freeze({
    contractVersion: grant.contractVersion,
    kind: grant.kind,
    grantId: grant.grantId,
    scanId: grant.scanId,
    issuedAt: grant.issuedAt,
    expiresAt: grant.expiresAt,
    subject,
    authorizationBasis,
    permissionSet,
    boundaries,
    constraints,
    classification,
  });
}

// ---------------------------------------------------------------------------
// deriveAuthorizationLineageRef
// ---------------------------------------------------------------------------

import type { AuthorizationLineageRef, AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';

export function deriveAuthorizationLineageRef(decision: VerifiedAuthorizationDecision): AuthorizedActiveReconRequestLineage {
  return {
    assessmentId: decision.assessmentId,
    scanId: decision.scanId,
    authorizationGrantId: decision.authorizationGrantId,
    authorizationDecisionId: decision.authorizationDecisionId,
    actorId: decision.authorizedActor.actorId,
  };
}

// ---------------------------------------------------------------------------
// deriveM30EgressScope
// ---------------------------------------------------------------------------

import type { AuthorizedScope } from '../recon/policy/EgressPolicyContracts.js';

export function deriveM30EgressScope(grant: AuthorizedScopeGrant): AuthorizedScope {
  // M30 egress scope derived strictly from M46 boundaries without expanding scope.
  // - allowedOrigins maps directly.
  // - allowSameHostPaths is enabled because M46 explicitly enforces fine-grained path denials before M30.
  // - allowSubdomains remains false per M56A requirements.
  return {
    allowedOrigins: grant.boundaries.allowedOrigins ?? [],
    allowSameHostPaths: true,
    allowSubdomains: false,
  };
}
