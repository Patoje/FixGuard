/**
 * Phase 6 — operator transcript built from data the run already stored.
 * Building a transcript does not start probes.
 * Unknown keys fail closed. Absent on records written before this field existed.
 */

import {
  isReadObservationBlastRadiusClass,
  type ReadObservationBlastRadiusClass,
} from '../attack-authorization/AttackAuthorizationContracts.js';
import type { AttackCapabilityKind, AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { CapturedStepInvocation } from '../core/StepInvocationCapture.js';
import { parseProbeInventory } from './ProbeInventory.js';
import type { ProbeInventory } from './ProbeInventoryContracts.js';

export const ASSESSMENT_TRANSCRIPT_CONTRACT_VERSION =
  'fixguard-assessment-transcript/v0' as const;

export type AssessmentTranscriptStopReason =
  | 'no_read_plans_remaining'
  | 'step_budget_exhausted'
  | 'time_budget_exhausted'
  | 'circuit_open'
  | 'verified_decision_missing'
  | 'loop_not_run';

export type AssessmentTranscriptStepOutcome = 'completed' | 'preflight_denied' | 'failed';

export interface AssessmentTranscriptExecutedStep {
  readonly capability: AttackCapabilityKind;
  readonly url: string;
  readonly blastRadiusClass: ReadObservationBlastRadiusClass;
  readonly outcome: AssessmentTranscriptStepOutcome;
  readonly invocation: CapturedStepInvocation;
}

export interface AssessmentTranscriptWithheldPlan {
  readonly capability: AttackCapabilityKind;
  readonly target: string;
}

export interface AssessmentTranscript {
  readonly contractVersion: typeof ASSESSMENT_TRANSCRIPT_CONTRACT_VERSION;
  readonly kind: 'assessment_transcript';
  readonly discoveries: ProbeInventory;
  readonly findings: readonly Finding[];
  readonly executedSteps: readonly AssessmentTranscriptExecutedStep[];
  readonly withheldPlans: readonly AssessmentTranscriptWithheldPlan[];
  readonly stopReason: AssessmentTranscriptStopReason;
}

const TRANSCRIPT_KEYS = [
  'contractVersion',
  'kind',
  'discoveries',
  'findings',
  'executedSteps',
  'withheldPlans',
  'stopReason',
] as const;

const STEP_KEYS = [
  'capability',
  'url',
  'blastRadiusClass',
  'outcome',
  'invocation',
] as const;

const WITHHELD_KEYS = ['capability', 'target'] as const;

const CAPABILITIES: readonly AttackCapabilityKind[] = [
  'idor_read_differential',
  'cors_chain_exploit',
  'auth_bypass_probe',
  'auth_boundary_differential',
  'jwt_alg_none_probe',
  'sql_error_oracle_probe',
  'parameter_reflection_probe',
  'session_fixation_probe',
  'method_manipulation_probe',
  'cors_misconfiguration_probe',
  'security_header_probe',
  'open_redirect_probe',
  'information_disclosure_probe',
  'subdomain_takeover_probe',
  'graphql_surface_probe',
  'graphql_auth_delta',
  'lfi_path_traversal',
  'sql_oracle_advancement',
  'nuclei_xss_scan',
  'sql_injection_verification',
  'credential_reuse',
  'supabase_rls_read_confirm',
  'supabase_rls_write_probe',
  'supabase_authz_write_matrix',
  'next_server_action_diff',
];

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

function parseCapability(value: unknown): AttackCapabilityKind | null {
  if (typeof value !== 'string') return null;
  for (const capability of CAPABILITIES) {
    if (capability === value) return capability;
  }
  return null;
}

function parseStopReason(value: unknown): AssessmentTranscriptStopReason | null {
  if (
    value === 'no_read_plans_remaining' ||
    value === 'step_budget_exhausted' ||
    value === 'time_budget_exhausted' ||
    value === 'circuit_open' ||
    value === 'verified_decision_missing' ||
    value === 'loop_not_run'
  ) {
    return value;
  }
  return null;
}

function parseOutcome(value: unknown): AssessmentTranscriptStepOutcome | null {
  if (value === 'completed' || value === 'preflight_denied' || value === 'failed') {
    return value;
  }
  return null;
}

function parseInvocation(value: unknown): CapturedStepInvocation | null {
  if (!isRecord(value) || typeof value.kind !== 'string') return null;
  if (value.kind === 'not_invoked') {
    if (!hasExactKeys(value, ['kind'])) return null;
    return { kind: 'not_invoked' };
  }
  if (value.kind === 'http') {
    if (!hasExactKeys(value, ['kind', 'method', 'url'])) return null;
    if (!isNonEmptyString(value.method) || !isNonEmptyString(value.url)) return null;
    return { kind: 'http', method: value.method, url: value.url };
  }
  if (value.kind === 'process') {
    if (!hasExactKeys(value, ['kind', 'binary', 'args'])) return null;
    if (!isNonEmptyString(value.binary) || !Array.isArray(value.args)) return null;
    const args: string[] = [];
    for (const arg of value.args) {
      if (typeof arg !== 'string') return null;
      args.push(arg);
    }
    return { kind: 'process', binary: value.binary, args: Object.freeze(args) };
  }
  return null;
}

function parseExecutedStep(value: unknown): AssessmentTranscriptExecutedStep | null {
  if (!isRecord(value) || !hasExactKeys(value, STEP_KEYS)) return null;
  const capability = parseCapability(value.capability);
  const outcome = parseOutcome(value.outcome);
  const invocation = parseInvocation(value.invocation);
  if (!capability || !outcome || !invocation) return null;
  if (!isNonEmptyString(value.url) || typeof value.blastRadiusClass !== 'string') return null;
  if (
    value.blastRadiusClass !== 'read_public' &&
    value.blastRadiusClass !== 'read_authenticated' &&
    value.blastRadiusClass !== 'read_escalated'
  ) {
    return null;
  }
  return {
    capability,
    url: value.url,
    blastRadiusClass: value.blastRadiusClass,
    outcome,
    invocation,
  };
}

function parseWithheld(value: unknown): AssessmentTranscriptWithheldPlan | null {
  if (!isRecord(value) || !hasExactKeys(value, WITHHELD_KEYS)) return null;
  const capability = parseCapability(value.capability);
  if (!capability || !isNonEmptyString(value.target)) return null;
  return { capability, target: value.target };
}

function isFinding(value: unknown): value is Finding {
  if (!isRecord(value)) return false;
  if (
    typeof value.id !== 'string' ||
    typeof value.type !== 'string' ||
    typeof value.title !== 'string' ||
    typeof value.description !== 'string' ||
    typeof value.target !== 'string' ||
    typeof value.evidence !== 'string' ||
    typeof value.confidence !== 'number' ||
    !isRecord(value.metadata) ||
    typeof value.verificationState !== 'string'
  ) {
    return false;
  }
  return (
    value.severity === 'info' ||
    value.severity === 'low' ||
    value.severity === 'medium' ||
    value.severity === 'high' ||
    value.severity === 'critical'
  );
}

function parseFindings(value: unknown): readonly Finding[] | null {
  if (!Array.isArray(value)) return null;
  const findings: Finding[] = [];
  for (const item of value) {
    if (!isFinding(item)) return null;
    findings.push(item);
  }
  return Object.freeze(findings);
}

/**
 * Closed-world parse. Unknown keys fail closed.
 * Findings stay the stored finding objects; this does not define a second model.
 */
export function parseAssessmentTranscript(value: unknown): AssessmentTranscript | null {
  if (!isRecord(value) || !hasExactKeys(value, TRANSCRIPT_KEYS)) return null;
  if (
    value.contractVersion !== ASSESSMENT_TRANSCRIPT_CONTRACT_VERSION ||
    value.kind !== 'assessment_transcript'
  ) {
    return null;
  }
  const stopReason = parseStopReason(value.stopReason);
  const discoveries = parseProbeInventory(value.discoveries);
  const findings = parseFindings(value.findings);
  if (!stopReason || !discoveries || !findings) return null;
  if (!Array.isArray(value.executedSteps) || !Array.isArray(value.withheldPlans)) return null;
  const executedSteps: AssessmentTranscriptExecutedStep[] = [];
  for (const raw of value.executedSteps) {
    const step = parseExecutedStep(raw);
    if (!step) return null;
    executedSteps.push(step);
  }
  const withheldPlans: AssessmentTranscriptWithheldPlan[] = [];
  for (const raw of value.withheldPlans) {
    const plan = parseWithheld(raw);
    if (!plan) return null;
    withheldPlans.push(plan);
  }
  return {
    contractVersion: ASSESSMENT_TRANSCRIPT_CONTRACT_VERSION,
    kind: 'assessment_transcript',
    discoveries,
    findings,
    executedSteps: Object.freeze(executedSteps),
    withheldPlans: Object.freeze(withheldPlans),
    stopReason,
  };
}

export function transcriptTargetForPlan(plan: AttackPlan): string {
  if (typeof plan.targetUrl === 'string' && plan.targetUrl.trim().length > 0) {
    return plan.targetUrl.trim();
  }
  return plan.planId;
}

/**
 * Plans whose declared class authorizeReadObservationFromVerifiedDecision would reject.
 * Read classes are not withheld. Plans stay unexecuted here; this function does not run them.
 */
export function withheldPlansForTranscript(
  plans: readonly AttackPlan[]
): readonly AssessmentTranscriptWithheldPlan[] {
  const withheld: AssessmentTranscriptWithheldPlan[] = [];
  for (const plan of plans) {
    const declared = plan.authorizationBlastRadiusClass;
    if (declared === undefined) continue;
    if (isReadObservationBlastRadiusClass(declared)) continue;
    withheld.push({
      capability: plan.capability,
      target: transcriptTargetForPlan(plan),
    });
  }
  return Object.freeze(withheld);
}

export function buildAssessmentTranscript(input: {
  readonly discoveries: ProbeInventory;
  readonly findings: readonly Finding[];
  readonly executedSteps: readonly AssessmentTranscriptExecutedStep[];
  readonly withheldPlans: readonly AssessmentTranscriptWithheldPlan[];
  readonly stopReason: AssessmentTranscriptStopReason;
}): AssessmentTranscript {
  return {
    contractVersion: ASSESSMENT_TRANSCRIPT_CONTRACT_VERSION,
    kind: 'assessment_transcript',
    discoveries: input.discoveries,
    findings: Object.freeze([...input.findings]),
    executedSteps: Object.freeze([...input.executedSteps]),
    withheldPlans: Object.freeze([...input.withheldPlans]),
    stopReason: input.stopReason,
  };
}
