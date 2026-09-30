/**
 * Read-investigation loop.
 * After plans are saved, select not-yet-run read-class plans, mint one
 * read-observation token from the assessment's existing verified decision,
 * and execute only through AttackExecutionService.execute.
 * A completed step can feed the next selection from in-scope finding URLs
 * and newlyReachableTargets. Correlation runs once at the end and does not
 * execute plans itself. AttackPlan.executable stays false.
 * Non-read classes are not minted.
 */

import {
  ATTACK_AUTHORIZATION_CONTRACT_VERSION,
  AUTHORIZE_READ_OBSERVATION_REQUEST_KIND,
  type BlastRadiusClass,
  type ReadObservationBlastRadiusClass,
} from '../attack-authorization/AttackAuthorizationContracts.js';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import {
  ATTACK_EXECUTION_CONTRACT_VERSION,
  type AttackCapabilityIdentityRef,
  type AttackExecutionRecord,
  type AttackExecutionResult,
} from '../attack-execution/AttackExecutionContracts.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import { isRuntimeEstablishedVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { Finding, FindingMetadata } from '../core/Evidence.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import {
  AttackPlanGeneratorService,
  isAccountBoundaryPath,
} from '../attack-planning/AttackPlanGeneratorService.js';
import type { AttackPlanRepository } from '../attack-planning/AttackPlanRepository.js';
import type {
  AttackCapabilityKind,
  AttackPlan,
  AttackPlanDraftSignal,
  AttackPlanIdentityContext,
  AttackPlanSurfaceHint,
} from '../attack-planning/AttackPlanContracts.js';
import { correlateCorsIdorChains } from '../intelligence/correlation/CorsIdorChainCorrelator.js';
import { correlateCrossFindingChains } from '../intelligence/correlation/CrossFindingChainCorrelator.js';
import type { IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import {
  captureStepInvocation,
  noteHttpProbeReceipt,
} from '../core/StepInvocationCapture.js';
import {
  buildAssessmentTranscript,
  transcriptTargetForPlan,
  type AssessmentTranscript,
  type AssessmentTranscriptExecutedStep,
  type AssessmentTranscriptWithheldPlan,
} from './AssessmentTranscript.js';
import { appendProbeCandidates, type ProbeCandidate } from './ProbeInventory.js';
import type { ProbeInventory } from './ProbeInventoryContracts.js';
import { isPublicStaticAssetUrl } from '../detection/PublicStaticAsset.js';
import {
  READ_INVESTIGATION_DEFAULT_STEP_BUDGET,
  READ_INVESTIGATION_DEFAULT_TIME_BUDGET_MS,
  READ_INVESTIGATION_LOOP_CONTRACT_VERSION,
  type ReadInvestigationExecutedStep,
  type ReadInvestigationLoopRecord,
  type ReadInvestigationStepStatus,
  type ReadInvestigationStopReason,
} from './ReadInvestigationLoopContracts.js';

/**
 * Capabilities the loop may execute. Each maps to one read class.
 * Tool payloads and state-changing capabilities are absent.
 */
const READ_CLASS_BY_CAPABILITY: Partial<
  Record<AttackCapabilityKind, ReadObservationBlastRadiusClass>
> = {
  security_header_probe: 'read_public',
  information_disclosure_probe: 'read_public',
  open_redirect_probe: 'read_public',
  graphql_surface_probe: 'read_public',
  cors_misconfiguration_probe: 'read_public',
  subdomain_takeover_probe: 'read_public',
  auth_boundary_differential: 'read_authenticated',
  supabase_rls_read_confirm: 'read_authenticated',
  graphql_auth_delta: 'read_authenticated',
  auth_bypass_probe: 'read_authenticated',
  idor_read_differential: 'read_escalated',
};

const RUNNABLE_STATUSES = new Set<AttackPlan['status']>([
  'ready_for_authorization',
  'authorized',
]);

export interface RunReadInvestigationLoopInput {
  readonly assessmentId: string;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision | undefined;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly coordinator: TargetExecutionCoordinator;
  readonly dnsResolver: PreSpawnDnsResolver;
  readonly transport: IdorHttpProbeTransport;
  readonly circuitHost: string;
  readonly findings: readonly Finding[];
  readonly probeInventory: ProbeInventory;
  readonly planRepository: AttackPlanRepository;
  readonly planGenerator: AttackPlanGeneratorService;
  readonly authorizationService: AttackAuthorizationService;
  readonly executionService: AttackExecutionService;
  readonly recordOutcome: (args: {
    readonly assessmentId: string;
    readonly planId: string;
    readonly executionRecord: AttackExecutionRecord;
  }) => Promise<unknown>;
  readonly identities?: readonly AttackPlanIdentityContext[];
  readonly primaryIdentity?: AttackCapabilityIdentityRef;
  readonly secondaryIdentity?: AttackCapabilityIdentityRef;
  readonly stepBudget?: number;
  readonly timeBudgetMs?: number;
  readonly nowMs?: () => number;
  /**
   * Hosts or absolute URLs recorded on acquired access after a step.
   * Absent means the caller has no post-exploitation snapshot to read.
   */
  readonly listNewlyReachableTargets?: () => Promise<readonly string[]>;
}

export interface RunReadInvestigationLoopResult {
  readonly record: ReadInvestigationLoopRecord;
  readonly probeInventory: ProbeInventory;
  readonly findings: readonly Finding[];
  readonly transcript: AssessmentTranscript;
}

function finiteBudget(value: number | undefined, fallback: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return fallback;
  return value;
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

function isReadClass(value: BlastRadiusClass): value is ReadObservationBlastRadiusClass {
  return (
    value === 'read_public' ||
    value === 'read_authenticated' ||
    value === 'read_escalated'
  );
}

/**
 * Read class for a runnable plan. A declared non-read class, including
 * persistence and destructive, yields null so no token is minted.
 * A declared read class is used only when it matches the capability allowlist.
 */
export function readObservationClassForPlan(
  plan: AttackPlan
): ReadObservationBlastRadiusClass | null {
  const declared = plan.authorizationBlastRadiusClass;
  if (declared !== undefined) {
    if (!isBlastRadiusClass(declared) || !isReadClass(declared)) return null;
  }
  const mapped = READ_CLASS_BY_CAPABILITY[plan.capability];
  if (!mapped) return null;
  if (declared !== undefined && declared !== mapped) return null;
  return mapped;
}

function planSort(left: AttackPlan, right: AttackPlan): number {
  const created = left.createdAt.localeCompare(right.createdAt);
  if (created !== 0) return created;
  return left.planId.localeCompare(right.planId);
}

/**
 * When identity A is already on the run, auth-bypass and auth-boundary
 * are eligible on the first automatic step. Other read plans keep createdAt order.
 */
function automaticReadRank(plan: AttackPlan, identityAPresent: boolean): number {
  if (!identityAPresent) return 1;
  if (
    plan.capability === 'auth_bypass_probe' ||
    plan.capability === 'auth_boundary_differential'
  ) {
    return 0;
  }
  return 1;
}

/** Application routes are selected before public static assets. */
function applicationRouteRank(plan: AttackPlan): number {
  const target = plan.targetUrl ?? '';
  return isPublicStaticAssetUrl(target) ? 1 : 0;
}

function skipsStaticAuthBypass(plan: AttackPlan): boolean {
  return (
    plan.capability === 'auth_bypass_probe' &&
    isPublicStaticAssetUrl(plan.targetUrl ?? '')
  );
}

function stringField(meta: FindingMetadata, key: string): string | undefined {
  if (!Object.prototype.hasOwnProperty.call(meta, key)) return undefined;
  const value = Reflect.get(meta, key);
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function stringListField(meta: FindingMetadata, key: string): readonly string[] {
  if (!Object.prototype.hasOwnProperty.call(meta, key)) return [];
  const value = Reflect.get(meta, key);
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const item of value) {
    if (typeof item === 'string' && item.trim().length > 0) out.push(item.trim());
  }
  return out;
}

function absoluteUrl(raw: string, baseUrl: string | undefined): string | null {
  try {
    if (raw.startsWith('http://') || raw.startsWith('https://')) {
      return new URL(raw).toString();
    }
    if (baseUrl && raw.startsWith('/')) {
      return new URL(raw, baseUrl).toString();
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * URLs and parameter names already present on the execution result's findings.
 * Does not parse response bodies.
 */
function candidatesFromFindings(
  findings: readonly Finding[],
  baseUrl: string | undefined
): readonly ProbeCandidate[] {
  const candidates: ProbeCandidate[] = [];
  const seen = new Set<string>();
  const push = (raw: string | undefined, parameterName: string | undefined): void => {
    if (!raw) return;
    const url = absoluteUrl(raw, baseUrl);
    if (!url) return;
    const key = `${url}\n${parameterName ?? ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push({
      url,
      ...(parameterName ? { parameterName } : {}),
      source: 'read_step',
    });
  };

  for (const finding of findings) {
    const meta = finding.metadata;
    const parameterName = stringField(meta, 'parameterName');
    push(stringField(meta, 'endpointUrl'), parameterName);
    push(stringField(meta, 'url'), parameterName);
    push(stringField(meta, 'finalUrl'), parameterName);
    const base = stringField(meta, 'endpointUrl') ?? baseUrl;
    for (const path of stringListField(meta, 'newlyExposedPaths')) {
      push(path, parameterName);
    }
    const route = stringField(meta, 'extractedRoutePattern');
    if (route) push(route, parameterName);
    if (parameterName && base) push(base, parameterName);
  }
  return candidates;
}

function sameTarget(left: string, right: string): boolean {
  try {
    const a = new URL(left);
    const b = new URL(right);
    return a.origin === b.origin && a.pathname === b.pathname;
  } catch {
    return left === right;
  }
}

function probeUrlFromReachableTarget(raw: string): string | null {
  const trimmed = raw.trim();
  if (trimmed.length === 0 || /[\s\r\n\0]/.test(trimmed)) return null;
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    return absoluteUrl(trimmed, undefined);
  }
  if (trimmed.includes('://') || trimmed.startsWith('//')) return null;
  const withScheme = trimmed.includes('/') ? `https://${trimmed}` : `https://${trimmed}/`;
  return absoluteUrl(withScheme, undefined);
}

function findingSurfaceUrl(finding: Finding): string | null {
  const endpoint = stringField(finding.metadata, 'endpointUrl');
  if (endpoint) {
    const fromEndpoint = absoluteUrl(endpoint, undefined);
    if (fromEndpoint) return fromEndpoint;
  }
  return absoluteUrl(finding.target, undefined);
}

function surfaceHintForUrl(url: string): AttackPlanSurfaceHint | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const path = parsed.pathname.length > 0 ? parsed.pathname : '/';
  const account = isAccountBoundaryPath(path) || isAccountBoundaryPath(url);
  return {
    endpointUrl: parsed.toString(),
    path,
    signalKind: account ? 'account_boundary' : 'auth_surface',
    resourceClass: 'api_or_protected',
  };
}

function executionStatus(result: AttackExecutionResult): ReadInvestigationStepStatus {
  if (result.status === 'completed') return 'completed';
  if (result.status === 'failed') return 'failed';
  return 'preflight_denied';
}

/**
 * The execution wrapper reports attack_execution_completed when the call
 * finished. The loop step keeps the capability outcome: a failed or denied
 * capability stays failed, and its reason code is the capability reason.
 */
function loopStepOutcome(result: AttackExecutionResult): {
  readonly status: ReadInvestigationStepStatus;
  readonly reasonCode: string;
} {
  if (result.status !== 'completed' || !result.record) {
    return { status: executionStatus(result), reasonCode: result.reasonCode };
  }
  const last = result.record.stepRecords[result.record.stepRecords.length - 1];
  if (!last) {
    return { status: 'completed', reasonCode: result.reasonCode };
  }
  if (
    last.outcome === 'failed' ||
    last.outcome === 'preflight_denied' ||
    last.outcome === 'capability_not_implemented'
  ) {
    return { status: 'failed', reasonCode: last.reasonCode };
  }
  return { status: 'completed', reasonCode: last.reasonCode };
}

function buildRecord(args: {
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly stopReason: ReadInvestigationStopReason;
  readonly stepsExecuted: number;
  readonly stepBudget: number;
  readonly timeBudgetMs: number;
  readonly executedSteps: readonly ReadInvestigationExecutedStep[];
  readonly skippedNonReadPlanIds: readonly string[];
  readonly seenOutOfScopeUrls: readonly string[];
}): ReadInvestigationLoopRecord {
  return {
    contractVersion: READ_INVESTIGATION_LOOP_CONTRACT_VERSION,
    kind: 'read_investigation_loop',
    assessmentId: args.lineage.assessmentId,
    scanId: args.lineage.scanId,
    authorizationGrantId: args.lineage.authorizationGrantId,
    authorizationDecisionId: args.lineage.authorizationDecisionId,
    actorId: args.lineage.actorId,
    stopReason: args.stopReason,
    stepsExecuted: args.stepsExecuted,
    stepBudget: args.stepBudget,
    timeBudgetMs: args.timeBudgetMs,
    executedSteps: Object.freeze([...args.executedSteps]),
    skippedNonReadPlanIds: Object.freeze([...args.skippedNonReadPlanIds]),
    seenOutOfScopeUrls: Object.freeze([...args.seenOutOfScopeUrls]),
  };
}

export async function runReadInvestigationLoop(
  input: RunReadInvestigationLoopInput
): Promise<RunReadInvestigationLoopResult> {
  const stepBudget = finiteBudget(input.stepBudget, READ_INVESTIGATION_DEFAULT_STEP_BUDGET);
  const timeBudgetMs = finiteBudget(input.timeBudgetMs, READ_INVESTIGATION_DEFAULT_TIME_BUDGET_MS);
  const nowMs = input.nowMs ?? ((): number => Date.now());
  const startedMs = nowMs();
  const executedPlanIds = new Set<string>();
  const executedSteps: ReadInvestigationExecutedStep[] = [];
  const transcriptSteps: AssessmentTranscriptExecutedStep[] = [];
  const withheldPlans: AssessmentTranscriptWithheldPlan[] = [];
  const withheldNoted = new Set<string>();
  const skippedNonReadPlanIds: string[] = [];
  const seenOutOfScopeUrls: string[] = [];
  const skippedNoted = new Set<string>();
  let findings = input.findings.map((finding) => finding);
  let inventory = input.probeInventory;
  const identityAPresent = input.primaryIdentity !== undefined;

  const finish = (
    stopReason: ReadInvestigationStopReason
  ): RunReadInvestigationLoopResult => ({
    record: buildRecord({
      lineage: input.lineage,
      stopReason,
      stepsExecuted: executedSteps.length,
      stepBudget,
      timeBudgetMs,
      executedSteps,
      skippedNonReadPlanIds,
      seenOutOfScopeUrls,
    }),
    probeInventory: inventory,
    findings,
    transcript: buildAssessmentTranscript({
      discoveries: inventory,
      findings,
      executedSteps: transcriptSteps,
      withheldPlans,
      stopReason,
    }),
  });

  const decision = input.verifiedAuthorizationDecision;
  const consideredReachable = new Set<string>();
  let correlated = false;

  const noteSkipped = (plans: readonly AttackPlan[]): void => {
    for (const plan of plans) {
      if (plan.assessmentId !== input.assessmentId) continue;
      const declared = plan.authorizationBlastRadiusClass;
      if (
        declared !== undefined &&
        isBlastRadiusClass(declared) &&
        !isReadClass(declared) &&
        !withheldNoted.has(plan.planId)
      ) {
        withheldNoted.add(plan.planId);
        withheldPlans.push({
          capability: plan.capability,
          target: transcriptTargetForPlan(plan),
        });
      }
      if (!RUNNABLE_STATUSES.has(plan.status)) continue;
      if (readObservationClassForPlan(plan) !== null) continue;
      if (skippedNoted.has(plan.planId)) continue;
      skippedNoted.add(plan.planId);
      skippedNonReadPlanIds.push(plan.planId);
    }
  };

  const selectNext = async (): Promise<{
    readonly plan: AttackPlan;
    readonly blastRadiusClass: ReadObservationBlastRadiusClass;
  } | null> => {
    const plans = [...(await input.planRepository.listByAssessmentId(input.assessmentId))].sort(
      (left, right) => {
        const rank = automaticReadRank(left, identityAPresent) - automaticReadRank(right, identityAPresent);
        if (rank !== 0) return rank;
        const route = applicationRouteRank(left) - applicationRouteRank(right);
        if (route !== 0) return route;
        return planSort(left, right);
      }
    );
    noteSkipped(plans);
    for (const plan of plans) {
      if (executedPlanIds.has(plan.planId)) continue;
      if (skipsStaticAuthBypass(plan)) continue;
      if (!RUNNABLE_STATUSES.has(plan.status)) continue;
      if (plan.capability === 'idor_read_differential' && !input.secondaryIdentity) {
        continue;
      }
      const blastRadiusClass = readObservationClassForPlan(plan);
      if (!blastRadiusClass) continue;
      return { plan, blastRadiusClass };
    }
    return null;
  };

  const rememberRejected = (urls: readonly string[]): void => {
    for (const url of urls) {
      if (!seenOutOfScopeUrls.includes(url)) seenOutOfScopeUrls.push(url);
    }
  };

  const saveNovelPlans = async (args: {
    readonly findingsForSurface: readonly Finding[];
    readonly hints: readonly AttackPlanSurfaceHint[];
    readonly draftSignals: readonly AttackPlanDraftSignal[];
  }): Promise<void> => {
    if (
      args.findingsForSurface.length === 0 &&
      args.hints.length === 0 &&
      args.draftSignals.length === 0
    ) {
      return;
    }
    const generated = input.planGenerator.generate({
      assessmentId: input.lineage.assessmentId,
      scanId: input.lineage.scanId,
      findings: args.findingsForSurface,
      identities: input.identities ?? [],
      lineage: input.lineage,
      ...(args.hints.length > 0 ? { surfaceHints: args.hints } : {}),
      ...(args.draftSignals.length > 0 ? { draftSignals: args.draftSignals } : {}),
      generatedAt: new Date(nowMs()).toISOString(),
    });
    const known = new Set(
      (await input.planRepository.listByAssessmentId(input.assessmentId)).map((plan) => plan.planId)
    );
    const novel = generated.plans.filter((plan) => !known.has(plan.planId));
    if (novel.length > 0) {
      await input.planRepository.savePlans(novel);
    }
  };

  const scopeCandidates = async (
    candidates: readonly ProbeCandidate[]
  ): Promise<{
    readonly hints: AttackPlanSurfaceHint[];
    readonly inScopeUrls: ReadonlySet<string>;
    readonly acceptedUrls: ReadonlySet<string>;
  }> => {
    const inScopeUrls = new Set<string>();
    const acceptedUrls = new Set<string>();
    if (candidates.length === 0) return { hints: [], inScopeUrls, acceptedUrls };
    const appended = appendProbeCandidates(
      inventory,
      input.scopeGrant,
      new Date(nowMs()).toISOString(),
      candidates
    );
    inventory = appended.inventory;
    rememberRejected(appended.rejectedUrls);
    for (const url of appended.acceptedUrls) acceptedUrls.add(url);
    const rejected = new Set(appended.rejectedUrls);
    const hints: AttackPlanSurfaceHint[] = [];
    const hinted = new Set<string>();
    for (const candidate of candidates) {
      let parsed = candidate.url;
      try {
        parsed = new URL(candidate.url).toString();
      } catch {
        continue;
      }
      if (rejected.has(parsed) || rejected.has(candidate.url)) continue;
      inScopeUrls.add(parsed);
      if (hinted.has(parsed)) continue;
      const hint = surfaceHintForUrl(parsed);
      if (!hint) continue;
      hinted.add(parsed);
      hints.push(hint);
    }
    return { hints, inScopeUrls, acceptedUrls };
  };

  const absorbNewlyReachableTargets = async (): Promise<void> => {
    if (!input.listNewlyReachableTargets) return;
    let targets: readonly string[] = [];
    try {
      targets = await input.listNewlyReachableTargets();
    } catch {
      return;
    }
    const candidates: ProbeCandidate[] = [];
    for (const raw of targets) {
      if (typeof raw !== 'string') continue;
      const trimmed = raw.trim();
      if (trimmed.length === 0 || consideredReachable.has(trimmed)) continue;
      consideredReachable.add(trimmed);
      const url = probeUrlFromReachableTarget(trimmed);
      if (!url) {
        rememberRejected([trimmed]);
        continue;
      }
      candidates.push({ url, source: 'newly_reachable_target' });
    }
    const scoped = await scopeCandidates(candidates);
    const hints = scoped.hints.filter((hint) => scoped.acceptedUrls.has(hint.endpointUrl));
    await saveNovelPlans({ findingsForSurface: [], hints, draftSignals: [] });
  };

  const correlateOnce = async (): Promise<void> => {
    if (correlated) return;
    correlated = true;
    const cors = correlateCorsIdorChains({
      assessmentId: input.lineage.assessmentId,
      scanId: input.lineage.scanId,
      actorId: input.lineage.actorId,
      findings,
    });
    const cross = correlateCrossFindingChains({
      assessmentId: input.lineage.assessmentId,
      scanId: input.lineage.scanId,
      actorId: input.lineage.actorId,
      findings,
    });
    const novelFindings = [...cors.compoundFindings, ...cross.compoundFindings].filter(
      (finding) => !findings.some((existing) => existing.id === finding.id)
    );
    const candidates: ProbeCandidate[] = [];
    const draftSignals: AttackPlanDraftSignal[] = [];
    for (const finding of novelFindings) {
      const url = findingSurfaceUrl(finding);
      if (url) candidates.push({ url, source: 'read_step' });
    }
    for (const draft of cors.compoundDrafts) {
      const endpoint = draft.differentialContext?.endpointUrl;
      const detectionKind = draft.differentialContext?.detectionKind;
      if (!endpoint || !detectionKind) continue;
      const url = absoluteUrl(endpoint, undefined);
      if (!url) continue;
      candidates.push({ url, source: 'read_step' });
      draftSignals.push({
        draftId: draft.draftId,
        detectionKind,
        endpointUrl: url,
      });
    }
    const scoped = await scopeCandidates(candidates);
    const hints = scoped.hints.filter((hint) => scoped.inScopeUrls.has(hint.endpointUrl));
    const allowed = scoped.inScopeUrls;
    const scopedFindings = novelFindings.filter((finding) => {
      const url = findingSurfaceUrl(finding);
      return url !== null && allowed.has(url);
    });
    const scopedSignals = draftSignals.filter((signal) => {
      const url = absoluteUrl(signal.endpointUrl, undefined);
      return url !== null && allowed.has(url);
    });
    if (scopedFindings.length > 0) {
      findings = [...findings, ...scopedFindings];
    }
    await saveNovelPlans({
      findingsForSurface: scopedFindings,
      hints,
      draftSignals: scopedSignals,
    });
  };

  noteSkipped(await input.planRepository.listByAssessmentId(input.assessmentId));

  if (!isRuntimeEstablishedVerifiedAuthorizationDecision(decision)) {
    await correlateOnce();
    return finish('verified_decision_missing');
  }

  while (true) {
    if (input.coordinator.isCircuitOpen(input.circuitHost)) {
      await correlateOnce();
      return finish('circuit_open');
    }
    if (nowMs() - startedMs >= timeBudgetMs) {
      await correlateOnce();
      return finish('time_budget_exhausted');
    }
    const next = await selectNext();
    if (!next) {
      if (!correlated) {
        await correlateOnce();
        continue;
      }
      return finish('no_read_plans_remaining');
    }
    if (executedSteps.length >= stepBudget) {
      await correlateOnce();
      return finish('step_budget_exhausted');
    }

    const minted = await input.authorizationService.authorizeReadObservationFromVerifiedDecision({
      contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
      kind: AUTHORIZE_READ_OBSERVATION_REQUEST_KIND,
      planId: next.plan.planId,
      assessmentId: input.assessmentId,
      blastRadiusClass: next.blastRadiusClass,
      operatorId: input.lineage.actorId,
      verifiedAuthorizationDecision: decision,
    });
    executedPlanIds.add(next.plan.planId);
    if (minted.status !== 'established') {
      executedSteps.push({
        planId: next.plan.planId,
        capability: next.plan.capability,
        blastRadiusClass: next.blastRadiusClass,
        status: 'failed',
        reasonCode: minted.reasonCode,
      });
      transcriptSteps.push({
        capability: next.plan.capability,
        url: transcriptTargetForPlan(next.plan),
        blastRadiusClass: next.blastRadiusClass,
        outcome: 'failed',
        invocation: { kind: 'not_invoked' },
      });
      continue;
    }

    const scopedTransport: IdorHttpProbeTransport = async (request) => {
      noteHttpProbeReceipt(request.method, request.url);
      return input.transport(request);
    };
    const captured = await captureStepInvocation(() =>
      input.executionService.execute({
        contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
        kind: 'attack_execution_request',
        planId: next.plan.planId,
        assessmentId: input.assessmentId,
        token: minted.token,
        scopeGrant: input.scopeGrant,
        coordinator: input.coordinator,
        dnsResolver: input.dnsResolver,
        findings: findings.map((finding) => finding),
        operatorId: input.lineage.actorId,
        verifiedAuthorizationDecision: decision,
        transport: scopedTransport,
        ...(input.primaryIdentity ? { primaryIdentity: input.primaryIdentity } : {}),
        ...(input.secondaryIdentity ? { secondaryIdentity: input.secondaryIdentity } : {}),
      })
    );
    const result = captured.result;

    if (result.record) {
      await input.recordOutcome({
        assessmentId: input.assessmentId,
        planId: next.plan.planId,
        executionRecord: result.record,
      });
      findings = result.record.updatedFindings.map((finding) => finding);
    }

    const recorded = loopStepOutcome(result);
    executedSteps.push({
      planId: next.plan.planId,
      capability: next.plan.capability,
      blastRadiusClass: next.blastRadiusClass,
      status: recorded.status,
      reasonCode: recorded.reasonCode,
    });
    transcriptSteps.push({
      capability: next.plan.capability,
      url: transcriptTargetForPlan(next.plan),
      blastRadiusClass: next.blastRadiusClass,
      outcome: recorded.status,
      invocation: captured.invocation,
    });

    if (result.reasonCode === 'gate_circuit_open') {
      await correlateOnce();
      return finish('circuit_open');
    }

    await absorbNewlyReachableTargets();

    if (recorded.status !== 'completed' || result.status !== 'completed' || !result.record) {
      continue;
    }

    const rawCandidates = candidatesFromFindings(
      result.record.updatedFindings,
      next.plan.targetUrl
    );
    const fresh = rawCandidates.filter((candidate) => {
      if (!next.plan.targetUrl) return true;
      if (!sameTarget(candidate.url, next.plan.targetUrl)) return true;
      return typeof candidate.parameterName === 'string' && candidate.parameterName.length > 0;
    });
    const scoped = await scopeCandidates(fresh);
    const newHints = scoped.hints.filter((hint) => scoped.acceptedUrls.has(hint.endpointUrl));
    await saveNovelPlans({ findingsForSurface: [], hints: newHints, draftSignals: [] });
  }
}
