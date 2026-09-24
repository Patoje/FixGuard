/**
 * Phase D2 Step 2 — persistence-boundary validation for AttackPlan + AttackChain.
 *
 * Fail-closed on forbidden secret/executable keys, missing lineage continuity,
 * and status/epistemic honesty (plans remain non-executable; chain epistemic preserved).
 */

import {
  ATTACK_CHAIN_CONTRACT_VERSION,
  type AttackChain,
  type AttackChainStatus,
  type EpistemicStatus,
  type ImpactLevel,
} from '../attack-chain/AttackChainContracts.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackPlan,
  type AttackPlanStatus,
} from '../attack-planning/AttackPlanContracts.js';
import {
  assertNoForbiddenPersistenceKeys,
  cloneForPersistence,
} from './OrchestratedAssessmentPersistenceValidation.js';

export { assertNoForbiddenPersistenceKeys, cloneForPersistence };

const EPISTEMIC_STATUSES = new Set<EpistemicStatus>([
  'OBSERVED',
  'INFERRED',
  'VERIFIED',
  'REFUTED',
]);

const PLAN_STATUSES = new Set<AttackPlanStatus>([
  'ready_for_authorization',
  'prerequisite_missing',
  'authorized',
  'rejected',
  'superseded',
]);

const CHAIN_STATUSES = new Set<AttackChainStatus>([
  'hypothesis',
  'partially_validated',
  'fully_validated',
  'refuted',
  'abandoned',
]);

const IMPACT_LEVELS = new Set<ImpactLevel>([
  'information_exposure',
  'authentication_bypass',
  'authorization_bypass',
  'data_access',
  'privilege_escalation',
  'lateral_movement',
  'rce_demonstrated',
]);

const PLAN_REQUIRED_KEYS = [
  'contractVersion',
  'kind',
  'planId',
  'assessmentId',
  'scanId',
  'capability',
  'title',
  'reasoning',
  'status',
  'blastRadius',
  'capabilityGained',
  'sourceFindingIds',
  'sourceFindingTypes',
  'prerequisites',
  'steps',
  'lineage',
  'createdAt',
  'executable',
] as const;

const CHAIN_REQUIRED_KEYS = [
  'contractVersion',
  'kind',
  'chainId',
  'assessmentId',
  'scanId',
  'hypothesis',
  'objectiveKind',
  'steps',
  'overallEpistemicStatus',
  'status',
  'impactLevel',
  'declaredImpactLevel',
  'lineage',
  'createdAt',
] as const;

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isExactKeyObject(
  value: unknown,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[] = []
): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const keys = Object.keys(value);
  const allowed = new Set([...requiredKeys, ...optionalKeys]);
  for (const key of keys) {
    if (!allowed.has(key)) {
      return false;
    }
  }
  for (const required of requiredKeys) {
    if (!Object.prototype.hasOwnProperty.call(value, required)) {
      return false;
    }
  }
  return true;
}

function validateLineageTuple(
  lineage: unknown,
  assessmentId: string,
  scanId: string
): boolean {
  if (
    !isExactKeyObject(lineage, [
      'assessmentId',
      'scanId',
      'authorizationGrantId',
      'authorizationDecisionId',
      'actorId',
    ])
  ) {
    return false;
  }
  return (
    lineage.assessmentId === assessmentId &&
    lineage.scanId === scanId &&
    isNonEmptyString(lineage.authorizationGrantId) &&
    isNonEmptyString(lineage.authorizationDecisionId) &&
    isNonEmptyString(lineage.actorId)
  );
}

function validatePlanPrerequisite(value: unknown): boolean {
  if (
    !isExactKeyObject(value, ['kind', 'description', 'satisfied'], ['detail'])
  ) {
    return false;
  }
  return (
    isNonEmptyString(value.kind) &&
    isNonEmptyString(value.description) &&
    typeof value.satisfied === 'boolean'
  );
}

function validatePlanStep(value: unknown): boolean {
  if (
    !isExactKeyObject(value, [
      'stepId',
      'ordinal',
      'title',
      'description',
      'status',
      'requiredPermissions',
    ])
  ) {
    return false;
  }
  return (
    isNonEmptyString(value.stepId) &&
    typeof value.ordinal === 'number' &&
    isNonEmptyString(value.title) &&
    isNonEmptyString(value.description) &&
    isNonEmptyString(value.status) &&
    Array.isArray(value.requiredPermissions)
  );
}

function validateChainStepEvidence(value: unknown): boolean {
  if (
    !isExactKeyObject(
      value,
      ['reasonCode', 'safeMessage', 'recordedAt'],
      ['evidenceId']
    )
  ) {
    return false;
  }
  return (
    isNonEmptyString(value.reasonCode) &&
    isNonEmptyString(value.safeMessage) &&
    isNonEmptyString(value.recordedAt)
  );
}

function validateChainStep(value: unknown): boolean {
  if (
    !isExactKeyObject(
      value,
      [
        'stepId',
        'sequence',
        'capabilityKind',
        'epistemicStatus',
        'evidence',
        'capabilityGained',
        'outcome',
      ],
      ['sourceStepId']
    )
  ) {
    return false;
  }
  if (
    !isNonEmptyString(value.stepId) ||
    typeof value.sequence !== 'number' ||
    !isNonEmptyString(value.capabilityKind) ||
    typeof value.epistemicStatus !== 'string' ||
    !EPISTEMIC_STATUSES.has(value.epistemicStatus as EpistemicStatus) ||
    !isNonEmptyString(value.capabilityGained) ||
    !isNonEmptyString(value.outcome)
  ) {
    return false;
  }
  return validateChainStepEvidence(value.evidence);
}

export function validateAttackPlan(value: unknown): value is AttackPlan {
  if (
    !isExactKeyObject(value, PLAN_REQUIRED_KEYS, ['targetUrl', 'parameterName'])
  ) {
    return false;
  }
  if (
    value.contractVersion !== ATTACK_PLANNING_CONTRACT_VERSION ||
    value.kind !== 'attack_plan' ||
    !isNonEmptyString(value.planId) ||
    !isNonEmptyString(value.assessmentId) ||
    !isNonEmptyString(value.scanId) ||
    !isNonEmptyString(value.capability) ||
    !isNonEmptyString(value.title) ||
    !isNonEmptyString(value.reasoning) ||
    typeof value.status !== 'string' ||
    !PLAN_STATUSES.has(value.status as AttackPlanStatus) ||
    !isNonEmptyString(value.blastRadius) ||
    !isNonEmptyString(value.capabilityGained) ||
    !Array.isArray(value.sourceFindingIds) ||
    !Array.isArray(value.sourceFindingTypes) ||
    !Array.isArray(value.prerequisites) ||
    !Array.isArray(value.steps) ||
    !isNonEmptyString(value.createdAt) ||
    value.executable !== false
  ) {
    return false;
  }
  if (
    !validateLineageTuple(
      value.lineage,
      value.assessmentId as string,
      value.scanId as string
    )
  ) {
    return false;
  }
  for (const prereq of value.prerequisites) {
    if (!validatePlanPrerequisite(prereq)) {
      return false;
    }
  }
  for (const step of value.steps) {
    if (!validatePlanStep(step)) {
      return false;
    }
  }
  try {
    assertNoForbiddenPersistenceKeys(value);
  } catch {
    return false;
  }
  return true;
}

export function validateAttackChain(value: unknown): value is AttackChain {
  if (!isExactKeyObject(value, CHAIN_REQUIRED_KEYS, ['completedAt'])) {
    return false;
  }
  if (
    value.contractVersion !== ATTACK_CHAIN_CONTRACT_VERSION ||
    value.kind !== 'attack_chain' ||
    !isNonEmptyString(value.chainId) ||
    !isNonEmptyString(value.assessmentId) ||
    !isNonEmptyString(value.scanId) ||
    !isNonEmptyString(value.hypothesis) ||
    !isNonEmptyString(value.objectiveKind) ||
    !Array.isArray(value.steps) ||
    typeof value.overallEpistemicStatus !== 'string' ||
    !EPISTEMIC_STATUSES.has(value.overallEpistemicStatus as EpistemicStatus) ||
    typeof value.status !== 'string' ||
    !CHAIN_STATUSES.has(value.status as AttackChainStatus) ||
    typeof value.impactLevel !== 'string' ||
    !IMPACT_LEVELS.has(value.impactLevel as ImpactLevel) ||
    typeof value.declaredImpactLevel !== 'string' ||
    !IMPACT_LEVELS.has(value.declaredImpactLevel as ImpactLevel) ||
    !isNonEmptyString(value.createdAt)
  ) {
    return false;
  }
  if (
    !validateLineageTuple(
      value.lineage,
      value.assessmentId as string,
      value.scanId as string
    )
  ) {
    return false;
  }
  for (const step of value.steps) {
    if (!validateChainStep(step)) {
      return false;
    }
  }
  try {
    assertNoForbiddenPersistenceKeys(value);
  } catch {
    return false;
  }
  return true;
}
