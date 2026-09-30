/**
 * Phase 4 — automatic read-investigation loop state.
 * Persisted on the assessment. Unknown keys fail closed.
 * Absent on records written before this field existed.
 */

import type { ReadObservationBlastRadiusClass } from '../attack-authorization/AttackAuthorizationContracts.js';
import type { AttackCapabilityKind } from '../attack-planning/AttackPlanContracts.js';

export const READ_INVESTIGATION_LOOP_CONTRACT_VERSION =
  'fixguard-read-investigation-loop/v0' as const;

/** Small on purpose. One step under a cap of 1, then stop. */
export const READ_INVESTIGATION_DEFAULT_STEP_BUDGET = 4;

/** Wall clock for one loop invocation. Checked before each next step. */
export const READ_INVESTIGATION_DEFAULT_TIME_BUDGET_MS = 8_000;

export type ReadInvestigationStopReason =
  | 'no_read_plans_remaining'
  | 'step_budget_exhausted'
  | 'time_budget_exhausted'
  | 'circuit_open'
  | 'verified_decision_missing';

export type ReadInvestigationStepStatus = 'completed' | 'preflight_denied' | 'failed';

export interface ReadInvestigationExecutedStep {
  readonly planId: string;
  readonly capability: AttackCapabilityKind;
  readonly blastRadiusClass: ReadObservationBlastRadiusClass;
  readonly status: ReadInvestigationStepStatus;
  readonly reasonCode: string;
}

export interface ReadInvestigationLoopRecord {
  readonly contractVersion: typeof READ_INVESTIGATION_LOOP_CONTRACT_VERSION;
  readonly kind: 'read_investigation_loop';
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly stopReason: ReadInvestigationStopReason;
  readonly stepsExecuted: number;
  readonly stepBudget: number;
  readonly timeBudgetMs: number;
  readonly executedSteps: readonly ReadInvestigationExecutedStep[];
  readonly skippedNonReadPlanIds: readonly string[];
  readonly seenOutOfScopeUrls: readonly string[];
}

const RECORD_KEYS = [
  'contractVersion',
  'kind',
  'assessmentId',
  'scanId',
  'authorizationGrantId',
  'authorizationDecisionId',
  'actorId',
  'stopReason',
  'stepsExecuted',
  'stepBudget',
  'timeBudgetMs',
  'executedSteps',
  'skippedNonReadPlanIds',
  'seenOutOfScopeUrls',
] as const;

const STEP_KEYS = [
  'planId',
  'capability',
  'blastRadiusClass',
  'status',
  'reasonCode',
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = Object.keys(value);
  if (keys.length !== allowed.length) return false;
  for (const key of allowed) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) return false;
  }
  return true;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isStringList(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function parseStopReason(value: string): ReadInvestigationStopReason | null {
  if (
    value === 'no_read_plans_remaining' ||
    value === 'step_budget_exhausted' ||
    value === 'time_budget_exhausted' ||
    value === 'circuit_open' ||
    value === 'verified_decision_missing'
  ) {
    return value;
  }
  return null;
}

function parseReadClass(value: string): ReadObservationBlastRadiusClass | null {
  if (value === 'read_public' || value === 'read_authenticated' || value === 'read_escalated') {
    return value;
  }
  return null;
}

function parseStepStatus(value: string): ReadInvestigationStepStatus | null {
  if (value === 'completed' || value === 'preflight_denied' || value === 'failed') {
    return value;
  }
  return null;
}

function parseCapability(value: string): AttackCapabilityKind | null {
  if (
    value === 'security_header_probe' ||
    value === 'information_disclosure_probe' ||
    value === 'open_redirect_probe' ||
    value === 'graphql_surface_probe' ||
    value === 'cors_misconfiguration_probe' ||
    value === 'subdomain_takeover_probe' ||
    value === 'auth_boundary_differential' ||
    value === 'supabase_rls_read_confirm' ||
    value === 'graphql_auth_delta' ||
    value === 'auth_bypass_probe' ||
    value === 'idor_read_differential'
  ) {
    return value;
  }
  return null;
}

function parseExecutedStep(value: unknown): ReadInvestigationExecutedStep | null {
  if (!isRecord(value) || !hasExactKeys(value, STEP_KEYS)) return null;
  if (
    !isNonEmptyString(value.planId) ||
    !isNonEmptyString(value.capability) ||
    !isNonEmptyString(value.reasonCode) ||
    typeof value.blastRadiusClass !== 'string' ||
    typeof value.status !== 'string'
  ) {
    return null;
  }
  const capability = parseCapability(value.capability);
  const blastRadiusClass = parseReadClass(value.blastRadiusClass);
  const status = parseStepStatus(value.status);
  if (!capability || !blastRadiusClass || !status) return null;
  return {
    planId: value.planId,
    capability,
    blastRadiusClass,
    status,
    reasonCode: value.reasonCode,
  };
}

/**
 * Closed-world parse. Unknown keys, missing keys, and malformed steps fail closed.
 */
export function parseReadInvestigationLoopRecord(
  value: unknown
): ReadInvestigationLoopRecord | null {
  if (!isRecord(value) || !hasExactKeys(value, RECORD_KEYS)) return null;
  if (
    value.contractVersion !== READ_INVESTIGATION_LOOP_CONTRACT_VERSION ||
    value.kind !== 'read_investigation_loop' ||
    !isNonEmptyString(value.assessmentId) ||
    !isNonEmptyString(value.scanId) ||
    !isNonEmptyString(value.authorizationGrantId) ||
    !isNonEmptyString(value.authorizationDecisionId) ||
    !isNonEmptyString(value.actorId) ||
    typeof value.stopReason !== 'string' ||
    parseStopReason(value.stopReason) === null ||
    typeof value.stepsExecuted !== 'number' ||
    !Number.isFinite(value.stepsExecuted) ||
    typeof value.stepBudget !== 'number' ||
    !Number.isFinite(value.stepBudget) ||
    typeof value.timeBudgetMs !== 'number' ||
    !Number.isFinite(value.timeBudgetMs) ||
    !Array.isArray(value.executedSteps) ||
    !isStringList(value.skippedNonReadPlanIds) ||
    !isStringList(value.seenOutOfScopeUrls)
  ) {
    return null;
  }
  const stopReason = parseStopReason(value.stopReason);
  if (!stopReason) return null;
  const executedSteps: ReadInvestigationExecutedStep[] = [];
  for (const raw of value.executedSteps) {
    const step = parseExecutedStep(raw);
    if (!step) return null;
    executedSteps.push(step);
  }
  if (executedSteps.length !== value.stepsExecuted) return null;
  return {
    contractVersion: READ_INVESTIGATION_LOOP_CONTRACT_VERSION,
    kind: 'read_investigation_loop',
    assessmentId: value.assessmentId,
    scanId: value.scanId,
    authorizationGrantId: value.authorizationGrantId,
    authorizationDecisionId: value.authorizationDecisionId,
    actorId: value.actorId,
    stopReason,
    stepsExecuted: value.stepsExecuted,
    stepBudget: value.stepBudget,
    timeBudgetMs: value.timeBudgetMs,
    executedSteps,
    skippedNonReadPlanIds: value.skippedNonReadPlanIds,
    seenOutOfScopeUrls: value.seenOutOfScopeUrls,
  };
}
