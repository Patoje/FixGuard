/**
 * Milestone A4 — Attack Authorization Service (DB-free)
 *
 * Graduated WeakSet brands: one module-private WeakSet per authorizable
 * blast-radius class. Higher classes NEVER grant lower classes (no cascade).
 *
 * CRITICAL INVARIANTS:
 * 1. No WeakSet exists for `persistence` or `destructive` (permanently prohibited).
 * 2. No superadmin / cascade across classes.
 * 3. Tokens are sealed only by establishAttackAuthorization().
 *    authorizePlan() and authorizeReadObservationFromVerifiedDecision()
 *    both go through that sealer. The read operation additionally requires
 *    the assessment's runtime-branded VerifiedAuthorizationDecision and a
 *    read-observation class. It does not brand state-changing, persistence,
 *    or destructive classes, and it does not set AttackPlan.executable.
 * 4. isRuntimeAuthorizedForBlastRadius() requires exact class match +
 *    plan/assessment bindings + WeakSet membership.
 * 5. Plan must exist in AttackPlanRepository for the assessment before sealing.
 *
 * Brand is process-local — not cryptographic, not transferable via JSON.
 */

import type {
  AttackAuthorizationToken,
  AuthorizeReadObservationResult,
  AuthorizableBlastRadiusClass,
  BlastRadiusClass,
  EstablishAttackAuthorizationRequest,
  EstablishAttackAuthorizationResult,
} from './AttackAuthorizationContracts.js';
import {
  ATTACK_AUTHORIZATION_CONTRACT_VERSION,
  AUTHORIZE_READ_OBSERVATION_REQUEST_KIND,
  isAuthorizableBlastRadiusClass,
  isProhibitedBlastRadiusClass,
  isReadObservationBlastRadiusClass,
  requiredAuthorizationLevelFor,
} from './AttackAuthorizationContracts.js';
import type { AttackPlanRepository } from '../attack-planning/AttackPlanRepository.js';
import { isRuntimeEstablishedVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';

// ---------------------------------------------------------------------------
// Module-private WeakSet brands — one per AUTHORIZABLE class only.
// persistence / destructive brands MUST NOT exist.
// ---------------------------------------------------------------------------

const _readPublicBrand = new WeakSet<object>();
const _readAuthenticatedBrand = new WeakSet<object>();
const _readEscalatedBrand = new WeakSet<object>();
const _sensitiveDataBrand = new WeakSet<object>();
const _credentialUseBrand = new WeakSet<object>();
const _privilegeEscalationBrand = new WeakSet<object>();
const _lateralMovementBrand = new WeakSet<object>();
const _stateChangeBenignBrand = new WeakSet<object>();
const _stateChangeImpactBrand = new WeakSet<object>();

const BRAND_BY_CLASS: Readonly<
  Record<AuthorizableBlastRadiusClass, WeakSet<object>>
> = {
  read_public: _readPublicBrand,
  read_authenticated: _readAuthenticatedBrand,
  read_escalated: _readEscalatedBrand,
  sensitive_data_access: _sensitiveDataBrand,
  credential_use: _credentialUseBrand,
  privilege_escalation: _privilegeEscalationBrand,
  lateral_movement: _lateralMovementBrand,
  state_change_benign: _stateChangeBenignBrand,
  state_change_impact: _stateChangeImpactBrand,
};

const TOKEN_TO_STRING_TAG = 'AttackAuthorizationToken';

// ---------------------------------------------------------------------------
// Safe helpers
// ---------------------------------------------------------------------------

function isSafeId(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128) return false;
  return /^[a-zA-Z0-9_\-.:]+$/.test(value);
}

function isSafeIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const d = Date.parse(value);
  return !Number.isNaN(d);
}

function isBlastRadiusClass(value: unknown): value is BlastRadiusClass {
  return (
    value === 'read_public' ||
    value === 'read_authenticated' ||
    value === 'read_escalated' ||
    value === 'sensitive_data_access' ||
    value === 'credential_use' ||
    value === 'privilege_escalation' ||
    value === 'lateral_movement' ||
    value === 'state_change_benign' ||
    value === 'state_change_impact' ||
    value === 'persistence' ||
    value === 'destructive'
  );
}

function sealToken(token: AttackAuthorizationToken): void {
  const brand = BRAND_BY_CLASS[token.blastRadiusClass];
  brand.add(token);
}

function hasBrandForClass(
  token: object,
  blastRadiusClass: AuthorizableBlastRadiusClass
): boolean {
  return BRAND_BY_CLASS[blastRadiusClass].has(token);
}

function tokenRegistryKey(planId: string, assessmentId: string): string {
  return `${assessmentId}::${planId}`;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readBrandedDecisionField(decision: object, key: string): unknown {
  return Reflect.get(decision, key);
}

// ---------------------------------------------------------------------------
// authorizePlan / establishAttackAuthorization (sync core — no repo)
// ---------------------------------------------------------------------------

/**
 * Authorize an attack plan for a specific blast-radius class.
 * Seals a runtime-branded token in the corresponding WeakSet.
 * Permanently rejects `persistence` and `destructive`.
 *
 * NOTE: Does not check plan repository existence. Prefer
 * AttackAuthorizationService.authorizePlan which enforces plan presence.
 */
export function authorizePlan(
  planId: string,
  assessmentId: string,
  blastRadiusClass: BlastRadiusClass,
  operatorId: string,
  authorizedAt?: string
): EstablishAttackAuthorizationResult {
  const request: EstablishAttackAuthorizationRequest = {
    contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
    kind: 'establish_attack_authorization_request',
    planId,
    assessmentId,
    blastRadiusClass,
    operatorId,
    ...(authorizedAt !== undefined ? { authorizedAt } : {}),
  };
  return establishAttackAuthorization(request);
}

/**
 * Closed-world establishment from a request DTO.
 * Callers must not self-authorize via confirmed:true — that field is rejected.
 */
export function establishAttackAuthorization(
  request: unknown
): EstablishAttackAuthorizationResult {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    return {
      status: 'failed',
      reasonCode: 'establishment_request_invalid',
      safeMessage: 'Request must be a plain object',
    };
  }

  const req = request as Record<string, unknown>;
  const allowedKeys = [
    'contractVersion',
    'kind',
    'planId',
    'assessmentId',
    'blastRadiusClass',
    'operatorId',
    'authorizedAt',
  ];
  for (const k of Object.keys(req)) {
    if (!allowedKeys.includes(k)) {
      return {
        status: 'failed',
        reasonCode: 'establishment_request_invalid',
        safeMessage: 'Request contains unknown or forbidden field',
      };
    }
  }

  // Reject self-authorization flags if smuggled under any alias
  if ('confirmed' in req || 'authorized' in req || 'authorizedScope' in req) {
    return {
      status: 'failed',
      reasonCode: 'establishment_request_invalid',
      safeMessage: 'Self-authorization fields are forbidden',
    };
  }

  if (req.contractVersion !== ATTACK_AUTHORIZATION_CONTRACT_VERSION) {
    return {
      status: 'failed',
      reasonCode: 'establishment_request_invalid',
      safeMessage: 'Invalid contractVersion',
    };
  }
  if (req.kind !== 'establish_attack_authorization_request') {
    return {
      status: 'failed',
      reasonCode: 'establishment_request_invalid',
      safeMessage: 'Invalid kind',
    };
  }

  if (!isSafeId(req.planId)) {
    return {
      status: 'failed',
      reasonCode: 'establishment_request_invalid',
      safeMessage: 'planId is invalid or unsafe',
    };
  }
  if (!isSafeId(req.assessmentId)) {
    return {
      status: 'failed',
      reasonCode: 'establishment_request_invalid',
      safeMessage: 'assessmentId is invalid or unsafe',
    };
  }
  if (!isSafeId(req.operatorId)) {
    return {
      status: 'failed',
      reasonCode: 'operator_invalid',
      safeMessage: 'operatorId is invalid or unsafe',
    };
  }

  if (!isBlastRadiusClass(req.blastRadiusClass)) {
    return {
      status: 'failed',
      reasonCode: 'establishment_request_invalid',
      safeMessage: 'blastRadiusClass is not a recognized closed-world class',
    };
  }

  if (isProhibitedBlastRadiusClass(req.blastRadiusClass)) {
    return {
      status: 'failed',
      reasonCode: 'blast_radius_class_prohibited',
      safeMessage: `Blast radius class "${req.blastRadiusClass}" is permanently prohibited and cannot be authorized`,
    };
  }

  if (!isAuthorizableBlastRadiusClass(req.blastRadiusClass)) {
    return {
      status: 'failed',
      reasonCode: 'establishment_request_invalid',
      safeMessage: 'blastRadiusClass is not authorizable',
    };
  }

  const authorizedAt =
    req.authorizedAt !== undefined ? req.authorizedAt : new Date().toISOString();
  if (!isSafeIsoTimestamp(authorizedAt)) {
    return {
      status: 'failed',
      reasonCode: 'establishment_request_invalid',
      safeMessage: 'authorizedAt is not a valid ISO timestamp',
    };
  }

  const level = requiredAuthorizationLevelFor(req.blastRadiusClass);
  if (level === 'PROHIBITED') {
    return {
      status: 'failed',
      reasonCode: 'blast_radius_class_prohibited',
      safeMessage: 'Blast radius class maps to PROHIBITED authorization level',
    };
  }

  const token: AttackAuthorizationToken = Object.freeze({
    contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
    kind: 'attack_authorization_token',
    planId: req.planId,
    assessmentId: req.assessmentId,
    blastRadiusClass: req.blastRadiusClass,
    authorizationLevel: level,
    authorizedBy: req.operatorId,
    authorizedAt,
    [Symbol.toStringTag]: TOKEN_TO_STRING_TAG,
  });

  sealToken(token);

  return {
    status: 'established',
    reasonCode: 'attack_authorization_established',
    token,
  };
}

// ---------------------------------------------------------------------------
// Runtime brand check
// ---------------------------------------------------------------------------

/**
 * Returns true only when:
 * - token is a plain branded AttackAuthorizationToken object
 * - token.blastRadiusClass === requiredClass (exact match; no cascade)
 * - token.planId / assessmentId match expected bindings
 * - token is present in the WeakSet for that exact class
 *
 * Fail-closed on forgery, spread, JSON round-trip, wrong plan, wrong class,
 * or prohibited requiredClass.
 */
export function isRuntimeAuthorizedForBlastRadius(
  token: unknown,
  requiredClass: BlastRadiusClass,
  expectedPlanId: string,
  expectedAssessmentId: string
): boolean {
  if (isProhibitedBlastRadiusClass(requiredClass)) {
    return false;
  }
  if (!isAuthorizableBlastRadiusClass(requiredClass)) {
    return false;
  }
  if (!isSafeId(expectedPlanId) || !isSafeId(expectedAssessmentId)) {
    return false;
  }
  if (!token || typeof token !== 'object' || Array.isArray(token)) {
    return false;
  }

  const t = token as Record<string | symbol, unknown>;

  if (t.contractVersion !== ATTACK_AUTHORIZATION_CONTRACT_VERSION) return false;
  if (t.kind !== 'attack_authorization_token') return false;
  if (typeof t.planId !== 'string' || t.planId !== expectedPlanId) return false;
  if (typeof t.assessmentId !== 'string' || t.assessmentId !== expectedAssessmentId) {
    return false;
  }
  if (t.blastRadiusClass !== requiredClass) return false;
  if (typeof t.authorizedBy !== 'string' || !isSafeId(t.authorizedBy)) return false;
  if (typeof t.authorizedAt !== 'string' || !isSafeIsoTimestamp(t.authorizedAt)) {
    return false;
  }

  const expectedLevel = requiredAuthorizationLevelFor(requiredClass);
  if (expectedLevel === 'PROHIBITED') return false;
  if (t.authorizationLevel !== expectedLevel) return false;

  return hasBrandForClass(token, requiredClass);
}

/**
 * Façade for composition-root DI. Brand state remains module-private.
 * Requires AttackPlanRepository — planId must exist for assessmentId
 * before minting a WeakSet brand.
 */
export class AttackAuthorizationService {
  private readonly sealedTokens = new Map<string, AttackAuthorizationToken>();

  constructor(private readonly planRepository: AttackPlanRepository) {}

  public async authorizePlan(
    planId: string,
    assessmentId: string,
    blastRadiusClass: BlastRadiusClass,
    operatorId: string,
    authorizedAt?: string
  ): Promise<EstablishAttackAuthorizationResult> {
    return this.establishAttackAuthorization({
      contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
      kind: 'establish_attack_authorization_request',
      planId,
      assessmentId,
      blastRadiusClass,
      operatorId,
      ...(authorizedAt !== undefined ? { authorizedAt } : {}),
    });
  }

  public async establishAttackAuthorization(
    request: unknown
  ): Promise<EstablishAttackAuthorizationResult> {
    // Pre-validate IDs enough to query the repository before sealing.
    if (request && typeof request === 'object' && !Array.isArray(request)) {
      const req = request as Record<string, unknown>;
      if (typeof req.planId === 'string' && typeof req.assessmentId === 'string') {
        if (isSafeId(req.planId) && isSafeId(req.assessmentId)) {
          const plan = await this.planRepository.getPlan(req.planId);
          if (!plan || plan.assessmentId !== req.assessmentId) {
            return {
              status: 'failed',
              reasonCode: 'plan_not_found',
              safeMessage: 'Attack plan does not exist for the given assessment',
            };
          }
        }
      }
    }

    const result = establishAttackAuthorization(request);
    if (result.status === 'established') {
      this.sealedTokens.set(
        tokenRegistryKey(result.token.planId, result.token.assessmentId),
        result.token
      );
    }
    return result;
  }

  /**
   * Mint one read-observation attack token from the assessment's already
   * branded VerifiedAuthorizationDecision. Does not create a decision brand.
   * `confirmed` and any other self-authorization field fail closed.
   * One token per planId+assessmentId. The plan's executable flag is untouched.
   */
  public async authorizeReadObservationFromVerifiedDecision(
    request: unknown
  ): Promise<AuthorizeReadObservationResult> {
    if (!isPlainRecord(request)) {
      return {
        status: 'failed',
        reasonCode: 'read_authorization_request_invalid',
        safeMessage: 'Request must be a plain object',
      };
    }
    if ('confirmed' in request || 'authorized' in request || 'authorizedScope' in request) {
      return {
        status: 'failed',
        reasonCode: 'read_authorization_request_invalid',
        safeMessage: 'Self-authorization fields are forbidden',
      };
    }

    const allowedKeys = [
      'contractVersion',
      'kind',
      'planId',
      'assessmentId',
      'blastRadiusClass',
      'operatorId',
      'verifiedAuthorizationDecision',
      'authorizedAt',
    ];
    for (const key of Object.keys(request)) {
      if (!allowedKeys.includes(key)) {
        return {
          status: 'failed',
          reasonCode: 'read_authorization_request_invalid',
          safeMessage: 'Request contains unknown or forbidden field',
        };
      }
    }

    if (request.contractVersion !== ATTACK_AUTHORIZATION_CONTRACT_VERSION) {
      return {
        status: 'failed',
        reasonCode: 'read_authorization_request_invalid',
        safeMessage: 'Invalid contractVersion',
      };
    }
    if (request.kind !== AUTHORIZE_READ_OBSERVATION_REQUEST_KIND) {
      return {
        status: 'failed',
        reasonCode: 'read_authorization_request_invalid',
        safeMessage: 'Invalid kind',
      };
    }
    if (!isSafeId(request.planId)) {
      return {
        status: 'failed',
        reasonCode: 'read_authorization_request_invalid',
        safeMessage: 'planId is invalid or unsafe',
      };
    }
    if (!isSafeId(request.assessmentId)) {
      return {
        status: 'failed',
        reasonCode: 'read_authorization_request_invalid',
        safeMessage: 'assessmentId is invalid or unsafe',
      };
    }
    if (!isSafeId(request.operatorId)) {
      return {
        status: 'failed',
        reasonCode: 'operator_invalid',
        safeMessage: 'operatorId is invalid or unsafe',
      };
    }
    if (!isBlastRadiusClass(request.blastRadiusClass)) {
      return {
        status: 'failed',
        reasonCode: 'read_authorization_request_invalid',
        safeMessage: 'blastRadiusClass is not a recognized closed-world class',
      };
    }
    if (isProhibitedBlastRadiusClass(request.blastRadiusClass)) {
      return {
        status: 'failed',
        reasonCode: 'blast_radius_class_prohibited',
        safeMessage: `Blast radius class "${request.blastRadiusClass}" is permanently prohibited and cannot be authorized`,
      };
    }
    if (!isReadObservationBlastRadiusClass(request.blastRadiusClass)) {
      return {
        status: 'failed',
        reasonCode: 'blast_radius_class_not_read_observation',
        safeMessage: 'Blast radius class is not a read observation class',
      };
    }

    const decision = request.verifiedAuthorizationDecision;
    if (!isRuntimeEstablishedVerifiedAuthorizationDecision(decision) || !isPlainRecord(decision)) {
      return {
        status: 'failed',
        reasonCode: 'verified_decision_not_branded',
        safeMessage: 'Verified authorization decision is missing or not runtime-branded',
      };
    }
    const decisionAssessmentId = readBrandedDecisionField(decision, 'assessmentId');
    if (typeof decisionAssessmentId !== 'string' || !isSafeId(decisionAssessmentId)) {
      return {
        status: 'failed',
        reasonCode: 'verified_decision_not_branded',
        safeMessage: 'Verified authorization decision is missing or not runtime-branded',
      };
    }
    if (decisionAssessmentId !== request.assessmentId) {
      return {
        status: 'failed',
        reasonCode: 'verified_decision_assessment_mismatch',
        safeMessage: 'Verified authorization decision is not bound to this assessment',
      };
    }
    const actor = readBrandedDecisionField(decision, 'authorizedActor');
    if (!isPlainRecord(actor) || !isSafeId(actor.actorId) || actor.actorId !== request.operatorId) {
      return {
        status: 'failed',
        reasonCode: 'operator_invalid',
        safeMessage: 'operatorId does not match the verified decision actor',
      };
    }

    const planId = request.planId;
    const assessmentId = request.assessmentId;
    const blastRadiusClass = request.blastRadiusClass;
    const operatorId = request.operatorId;

    const plan = await this.planRepository.getPlan(planId);
    if (!plan || plan.assessmentId !== assessmentId) {
      return {
        status: 'failed',
        reasonCode: 'plan_not_found',
        safeMessage: 'Attack plan does not exist for the given assessment',
      };
    }
    if (this.getRuntimeToken(planId, assessmentId)) {
      return {
        status: 'failed',
        reasonCode: 'read_authorization_already_established',
        safeMessage: 'A read authorization token is already sealed for this plan',
      };
    }

    let authorizedAt: string | undefined;
    if (request.authorizedAt !== undefined) {
      if (!isSafeIsoTimestamp(request.authorizedAt)) {
        return {
          status: 'failed',
          reasonCode: 'read_authorization_request_invalid',
          safeMessage: 'authorizedAt is not a valid ISO timestamp',
        };
      }
      authorizedAt = request.authorizedAt;
    }

    const sealed = await this.establishAttackAuthorization({
      contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
      kind: 'establish_attack_authorization_request',
      planId,
      assessmentId,
      blastRadiusClass,
      operatorId,
      ...(authorizedAt !== undefined ? { authorizedAt } : {}),
    });
    if (sealed.status === 'established') {
      return {
        status: 'established',
        reasonCode: 'read_attack_authorization_established',
        token: sealed.token,
      };
    }
    if (
      sealed.reasonCode === 'plan_not_found' ||
      sealed.reasonCode === 'operator_invalid' ||
      sealed.reasonCode === 'blast_radius_class_prohibited'
    ) {
      return {
        status: 'failed',
        reasonCode: sealed.reasonCode,
        safeMessage: sealed.safeMessage,
      };
    }
    return {
      status: 'failed',
      reasonCode: 'read_authorization_request_invalid',
      safeMessage: sealed.safeMessage,
    };
  }

  /**
   * Retrieve the process-local branded token for in-process execution (A5).
   * JSON/plain copies are never stored — only the WeakSet-sealed object.
   */
  public getRuntimeToken(
    planId: string,
    assessmentId: string
  ): AttackAuthorizationToken | null {
    if (!isSafeId(planId) || !isSafeId(assessmentId)) return null;
    return this.sealedTokens.get(tokenRegistryKey(planId, assessmentId)) ?? null;
  }

  public isRuntimeAuthorizedForBlastRadius(
    token: unknown,
    requiredClass: BlastRadiusClass,
    expectedPlanId: string,
    expectedAssessmentId: string
  ): boolean {
    return isRuntimeAuthorizedForBlastRadius(
      token,
      requiredClass,
      expectedPlanId,
      expectedAssessmentId
    );
  }
}
