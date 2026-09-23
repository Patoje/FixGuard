/**
 * Milestone A4 — Attack Authorization Model Contracts
 * Contract version: fixguard-attack-authorization/v0
 *
 * Graduated blast-radius authorization for attack plans.
 * Tokens are process-local runtime brands (WeakSet) — NOT identity proof from JSON.
 * Plans remain non-executable until a later execution milestone checks these brands.
 *
 * NOTE: This BlastRadiusClass is the authorization taxonomy (Master Phase 4).
 * AttackPlan advisory scope uses AttackPlanScopeClass in attack-planning (A3).
 */

export type AttackAuthorizationContractVersion = 'fixguard-attack-authorization/v0';
export const ATTACK_AUTHORIZATION_CONTRACT_VERSION: AttackAuthorizationContractVersion =
  'fixguard-attack-authorization/v0';

/**
 * Closed authorization blast-radius taxonomy (11 labels).
 * `persistence` and `destructive` are permanently PROHIBITED — no WeakSet brands exist.
 */
export type BlastRadiusClass =
  | 'read_public'
  | 'read_authenticated'
  | 'read_escalated'
  | 'sensitive_data_access'
  | 'credential_use'
  | 'privilege_escalation'
  | 'lateral_movement'
  | 'state_change_benign'
  | 'state_change_impact'
  | 'persistence'
  | 'destructive';

/** Authorizable subset — excludes permanently prohibited classes. */
export type AuthorizableBlastRadiusClass = Exclude<
  BlastRadiusClass,
  'persistence' | 'destructive'
>;

export type ProhibitedBlastRadiusClass = 'persistence' | 'destructive';

/**
 * Graduated human-authorization intensity required for a blast-radius class.
 * Higher classes never cascade into lower ones.
 */
export type AttackAuthorizationLevel =
  | 'assessment_authorization'
  | 'hitl_plan_approval'
  | 'explicit_per_step_approval'
  | 'PROHIBITED';

/**
 * Runtime-branded attack authorization token.
 * Only objects sealed via authorizePlan() carry a WeakSet brand.
 * Structural copies (spread, JSON, Object.assign) are not authorized.
 */
export interface AttackAuthorizationToken {
  readonly contractVersion: AttackAuthorizationContractVersion;
  readonly kind: 'attack_authorization_token';
  readonly planId: string;
  readonly assessmentId: string;
  readonly blastRadiusClass: AuthorizableBlastRadiusClass;
  readonly authorizationLevel: Exclude<AttackAuthorizationLevel, 'PROHIBITED'>;
  readonly authorizedBy: string;
  readonly authorizedAt: string;
  readonly [Symbol.toStringTag]: string;
}

export interface EstablishAttackAuthorizationRequest {
  readonly contractVersion: AttackAuthorizationContractVersion;
  readonly kind: 'establish_attack_authorization_request';
  readonly planId: string;
  readonly assessmentId: string;
  readonly blastRadiusClass: BlastRadiusClass;
  readonly operatorId: string;
  readonly authorizedAt?: string;
}

export type EstablishAttackAuthorizationReasonCode =
  | 'attack_authorization_established'
  | 'establishment_request_invalid'
  | 'blast_radius_class_prohibited'
  | 'operator_invalid'
  | 'plan_not_found';

export type EstablishAttackAuthorizationResult =
  | {
      readonly status: 'established';
      readonly reasonCode: 'attack_authorization_established';
      readonly token: AttackAuthorizationToken;
    }
  | {
      readonly status: 'failed';
      readonly reasonCode: EstablishAttackAuthorizationReasonCode;
      readonly safeMessage: string;
    };

export const AUTHORIZABLE_BLAST_RADIUS_CLASSES: readonly AuthorizableBlastRadiusClass[] = [
  'read_public',
  'read_authenticated',
  'read_escalated',
  'sensitive_data_access',
  'credential_use',
  'privilege_escalation',
  'lateral_movement',
  'state_change_benign',
  'state_change_impact',
] as const;

export const PROHIBITED_BLAST_RADIUS_CLASSES: readonly ProhibitedBlastRadiusClass[] = [
  'persistence',
  'destructive',
] as const;

/**
 * Maps blast-radius class → required authorization level.
 * No cascade: each class maps to exactly one level; higher does not imply lower.
 */
export function requiredAuthorizationLevelFor(
  blastRadiusClass: BlastRadiusClass
): AttackAuthorizationLevel {
  switch (blastRadiusClass) {
    case 'read_public':
    case 'read_authenticated':
      return 'assessment_authorization';
    case 'read_escalated':
    case 'sensitive_data_access':
      return 'hitl_plan_approval';
    case 'credential_use':
    case 'privilege_escalation':
    case 'lateral_movement':
    case 'state_change_benign':
    case 'state_change_impact':
      return 'explicit_per_step_approval';
    case 'persistence':
    case 'destructive':
      return 'PROHIBITED';
    default: {
      const _exhaustive: never = blastRadiusClass;
      return _exhaustive;
    }
  }
}

export function isProhibitedBlastRadiusClass(
  value: BlastRadiusClass
): value is ProhibitedBlastRadiusClass {
  return value === 'persistence' || value === 'destructive';
}

export function isAuthorizableBlastRadiusClass(
  value: BlastRadiusClass
): value is AuthorizableBlastRadiusClass {
  return !isProhibitedBlastRadiusClass(value);
}
