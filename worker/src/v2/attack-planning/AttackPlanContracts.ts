/**
 * Milestone A3 — Attack Planning Engine Contracts
 * Contract version: fixguard-attack-planning/v0
 *
 * Plans are pure advisory data for human authorization.
 * They are NOT executable payloads and must never auto-execute.
 */

import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';

export type AttackPlanningContractVersion = 'fixguard-attack-planning/v0';
export const ATTACK_PLANNING_CONTRACT_VERSION: AttackPlanningContractVersion =
  'fixguard-attack-planning/v0';

/**
 * Closed plan-scope taxonomy (exactly 10 classes).
 * Describes recommended validation scope on an advisory AttackPlan —
 * not an authorization blast-radius class (see attack-authorization BlastRadiusClass).
 */
export type AttackPlanScopeClass =
  | 'single_parameter'
  | 'single_endpoint'
  | 'single_resource'
  | 'user_scoped'
  | 'role_scoped'
  | 'tenant_scoped'
  | 'application_wide'
  | 'origin_wide'
  | 'domain_wide'
  | 'cross_origin_third_party';

/**
 * Closed capability allowlist.
 * A3: first 6 have generator rules; session_fixation / method_manipulation reserved.
 * A7: native LFI path traversal + SQL oracle advancement.
 * A8: nuclei XSS scan (allowlisted templates only).
 * A9: sqlmap error-based SQL injection verification (technique=E only).
 */
export type AttackCapabilityKind =
  | 'idor_read_differential'
  | 'cors_chain_exploit'
  | 'auth_bypass_probe'
  | 'jwt_alg_none_probe'
  | 'sql_error_oracle_probe'
  | 'parameter_reflection_probe'
  | 'session_fixation_probe'
  | 'method_manipulation_probe'
  | 'lfi_path_traversal'
  | 'sql_oracle_advancement'
  | 'nuclei_xss_scan'
  | 'sql_injection_verification'
  | 'credential_reuse';

/**
 * Capability expected if a human later authorizes a defensive validation step.
 * Not an exploit outcome and not a severity.
 */
export type CapabilityGained =
  | 'read_escalated'
  | 'read_authenticated'
  | 'active_validation'
  | 'none';

export type AttackPlanStatus =
  | 'ready_for_authorization'
  | 'prerequisite_missing'
  | 'authorized'
  | 'rejected'
  | 'superseded';

export type AttackStepStatus =
  | 'pending'
  | 'blocked'
  | 'ready'
  | 'skipped'
  | 'completed';

export type AttackPrerequisiteKind =
  | 'identity_count_at_least_2'
  | 'identity_present'
  | 'identity_with_jwt'
  | 'parameter_present'
  | 'credentialed_cors'
  | 'finding_present';

export interface AttackPrerequisite {
  readonly kind: AttackPrerequisiteKind;
  readonly description: string;
  readonly satisfied: boolean;
  readonly detail?: string;
}

export interface AttackStep {
  readonly stepId: string;
  readonly ordinal: number;
  readonly title: string;
  readonly description: string;
  readonly status: AttackStepStatus;
  readonly requiredPermissions: readonly string[];
}

export interface AttackPlan {
  readonly contractVersion: AttackPlanningContractVersion;
  readonly kind: 'attack_plan';
  readonly planId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly capability: AttackCapabilityKind;
  readonly title: string;
  readonly reasoning: string;
  readonly status: AttackPlanStatus;
  readonly blastRadius: AttackPlanScopeClass;
  readonly capabilityGained: CapabilityGained;
  readonly sourceFindingIds: readonly string[];
  readonly sourceFindingTypes: readonly string[];
  readonly prerequisites: readonly AttackPrerequisite[];
  readonly steps: readonly AttackStep[];
  readonly targetUrl?: string;
  readonly parameterName?: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly createdAt: string;
  /** Explicit non-executability: plans remain advisory until separate human authorization. */
  readonly executable: false;
}

export interface AttackPlanIdentityContext {
  readonly identityId: string;
  /** True when identity injects a JWT-like bearer/cookie token (analytical heuristic). */
  readonly hasJwt: boolean;
}

export interface AttackPlanGeneratorInput {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly findings: readonly import('../core/Evidence.js').Finding[];
  readonly identities: readonly AttackPlanIdentityContext[];
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly generatedAt?: string;
}

export interface AttackPlanGeneratorResult {
  readonly contractVersion: AttackPlanningContractVersion;
  readonly kind: 'attack_plan_generator_result';
  readonly assessmentId: string;
  readonly scanId: string;
  readonly plans: readonly AttackPlan[];
  readonly generatedAt: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
}

export interface GetAttackPlansResult {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly planCount: number;
  readonly plans: readonly AttackPlan[];
  readonly lineage: AuthorizedExecutionLineageTuple;
}
