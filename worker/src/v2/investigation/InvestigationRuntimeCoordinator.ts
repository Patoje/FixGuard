/**
 * Block B.1 — Canonical Investigation Runtime Coordinator
 *
 * The single canonical closed-loop investigation runtime for FixGuard V2.
 *
 * Implements the lifecycle:
 * DISCOVERY → OBSERVATION → HYPOTHESIS GENERATION → SCHEDULER SELECTION
 * → INVESTIGATION PLAN → JIT PLAN SYNTHESIS → AUTHORIZED TEST
 * → TEST VALIDITY EVALUATION → RESPONSE COMPARISON → HYPOTHESIS STATE UPDATE
 * → RE-SCHEDULING → NEXT INVESTIGATION
 *
 * Invariants:
 * - Deterministic, bounded execution (strictly terminates within step & time budgets).
 * - Read-only safety: zero state modification, zero destructive payloads.
 * - Test validity enforced: WAF/challenge interference cannot confirm vulnerabilities.
 * - Legitimate application 403 responses are valid observations (not blindly WAF-interfered).
 * - Negative evidence refutes/deprioritizes hypotheses.
 * - No pre-seeded plan dependency: plans are synthesized JIT from scheduled hypotheses.
 * - Zero fallback to legacy static plans in the canonical adaptive loop.
 * - Genuinely integrates ResponseComparatorService for semantic differential evidence.
 * - Preserves complete lineage and generates compliant ReadInvestigationLoopRecord.
 */

import { createHash } from 'node:crypto';
import {
  ATTACK_AUTHORIZATION_CONTRACT_VERSION,
  AUTHORIZE_READ_OBSERVATION_REQUEST_KIND,
  type AuthorizeReadObservationFromVerifiedDecisionRequest,
  type AuthorizeReadObservationResult,
  type ReadObservationBlastRadiusClass,
} from '../attack-authorization/AttackAuthorizationContracts.js';
import {
  ATTACK_EXECUTION_CONTRACT_VERSION,
  type AttackCapabilityIdentityRef,
  type AttackExecutionRecord,
  type AttackExecutionRequest,
  type AttackExecutionResult,
} from '../attack-execution/AttackExecutionContracts.js';
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
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import { isRuntimeEstablishedVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { Finding } from '../core/Evidence.js';
import {
  captureStepInvocation,
  noteHttpProbeReceipt,
} from '../core/StepInvocationCapture.js';
import type { IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import {
  HYPOTHESIS_SCHEDULER_CONTRACT_VERSION,
  isDeferredToManualValidation,
  type SecurityHypothesis,
  type SecurityHypothesisKind,
} from '../hypothesis-scheduler/HypothesisSchedulerContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import {
  evaluateTestValidity,
} from '../test-validity/TestValidityService.js';
import type { HttpResponseDefenseSignals } from '../test-validity/TestValidityContracts.js';
import {
  buildAssessmentTranscript,
  transcriptTargetForPlan,
  type AssessmentTranscript,
  type AssessmentTranscriptExecutedStep,
  type AssessmentTranscriptWithheldPlan,
} from './AssessmentTranscript.js';
import {
  appendProbeCandidates,
  type ProbeCandidate,
} from './ProbeInventory.js';
import { inventoryHasScreen } from './InventoryRouteClass.js';
import type { ProbeInventory } from './ProbeInventoryContracts.js';
import {
  READ_INVESTIGATION_DEFAULT_STEP_BUDGET,
  READ_INVESTIGATION_DEFAULT_TIME_BUDGET_MS,
  READ_INVESTIGATION_LOOP_CONTRACT_VERSION,
  READ_INVESTIGATION_PREFLIGHT_DENIED_CAP,
  type ReadInvestigationExecutedStep,
  type ReadInvestigationLoopRecord,
  type ReadInvestigationStepStatus,
  type ReadInvestigationStopReason,
} from './ReadInvestigationLoopContracts.js';
import {
  applyInvestigationFeedback,
  generateHypothesesFromObservations,
  normalizeStructuralRoute,
  scheduleNextInvestigation,
  stableHypothesisId,
} from './InvestigationHypothesisScheduler.js';
import type {
  InvestigationExecutionResult,
  InvestigationFeedbackStepRecord,
} from './InvestigationFeedbackContracts.js';
import {
  compareResponses,
} from '../comparison/ResponseComparatorService.js';
import {
  RESPONSE_COMPARATOR_CONTRACT_VERSION,
  type SafeResponseSnapshot,
  type ResponseComparisonRequest,
} from '../comparison/ResponseComparatorContracts.js';
import { correlateCorsIdorChains } from '../intelligence/correlation/CorsIdorChainCorrelator.js';
import { correlateCrossFindingChains } from '../intelligence/correlation/CrossFindingChainCorrelator.js';

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

function isReadClass(value: unknown): value is ReadObservationBlastRadiusClass {
  return (
    value === 'read_public' ||
    value === 'read_authenticated' ||
    value === 'read_escalated'
  );
}

export function readObservationClassForPlan(plan: AttackPlan): ReadObservationBlastRadiusClass | null {
  const declared = plan.authorizationBlastRadiusClass;
  if (declared !== undefined) {
    if (!isReadClass(declared)) return null;
  }
  const mapped = READ_CLASS_BY_CAPABILITY[plan.capability];
  if (!mapped) return null;
  if (declared !== undefined && declared !== mapped) return null;
  return mapped;
}

function executionStatus(result: AttackExecutionResult): ReadInvestigationStepStatus {
  if (result.status === 'completed') return 'completed';
  if (result.status === 'failed') return 'failed';
  return 'preflight_denied';
}

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
  if (last.outcome === 'preflight_denied') {
    return { status: 'preflight_denied', reasonCode: last.reasonCode };
  }
  if (last.outcome === 'failed' || last.outcome === 'capability_not_implemented') {
    return { status: 'failed', reasonCode: last.reasonCode };
  }
  return { status: 'completed', reasonCode: last.reasonCode };
}

function buildSafeSnapshot(args: {
  readonly scanId: string;
  readonly role: 'baseline' | 'validation';
  readonly url: string;
  readonly statusCode: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly bodyText: string;
  readonly responseTimeMs: number;
}): SafeResponseSnapshot {
  const hash = createHash('sha256').update(args.bodyText).digest('hex').slice(0, 32);
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(args.url);
  } catch {
    parsedUrl = new URL('https://target.local/');
  }
  return {
    contractVersion: RESPONSE_COMPARATOR_CONTRACT_VERSION,
    kind: 'safe_response_snapshot',
    snapshotId: `snap_${args.role}_${createHash('sha256').update(args.url + args.role).digest('hex').slice(0, 8)}`,
    scanId: args.scanId,
    capturedAt: new Date().toISOString(),
    role: args.role,
    subject: {
      normalizedOrigin: parsedUrl.origin,
      method: 'GET',
      pathTemplate: parsedUrl.pathname,
      routeId: parsedUrl.pathname,
    },
    statusCode: args.statusCode,
    contentLength: Buffer.byteLength(args.bodyText, 'utf8'),
    responseTimeMs: args.responseTimeMs,
    headerNames: Object.keys(args.headers).map((h) => h.toLowerCase()),
    bodyHash: hash,
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false,
    },
  };
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
  const endpoint =
    finding.metadata && typeof finding.metadata === 'object' && 'endpointUrl' in finding.metadata
      ? String((finding.metadata as { endpointUrl?: unknown }).endpointUrl)
      : undefined;
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

/**
 * M1 — narrow structural ports for the two active-execution touchpoints this
 * coordinator depends on (minting a read-observation authorization token, and
 * executing one authorized probe). `AttackAuthorizationService` and
 * `AttackExecutionService` already satisfy these shapes; defining them here
 * removes the coordinator's compile-time dependency on those concrete classes
 * without changing either class or its call signatures. Each request
 * parameter uses the exact existing request contract this file's one call
 * site already constructs (`AuthorizeReadObservationFromVerifiedDecisionRequest`,
 * `AttackExecutionRequest`) rather than `unknown` — the real services declare
 * their public methods as `(request: unknown) => Promise<...>`, and a function
 * accepting `unknown` is a valid substitute wherever a function accepting a
 * narrower type is expected, so both concrete classes still satisfy these
 * port signatures unchanged.
 *
 * M1 follow-up: this was previously left as `unknown` after narrowing it
 * surfaced a `tsc` error — `decision` (below, at the `verified_decision_missing`
 * guard) was typed `VerifiedAuthorizationDecision | undefined` for the rest of
 * the function because `isRuntimeEstablishedVerifiedAuthorizationDecision`
 * returns a plain `boolean`, not a type predicate, so TS never narrowed past
 * that guard. The fix did not require touching that function: adding an
 * explicit `decision === undefined` check to this file's own guard gives TS a
 * native narrowing expression it can carry for the rest of the function,
 * closing the gap entirely locally, with no cast and no signature change
 * elsewhere.
 */
export interface ReadObservationAuthorizationPort {
  authorizeReadObservationFromVerifiedDecision(
    request: AuthorizeReadObservationFromVerifiedDecisionRequest
  ): Promise<AuthorizeReadObservationResult>;
}

export interface ReadObservationExecutionPort {
  execute(request: AttackExecutionRequest): Promise<AttackExecutionResult>;
}

export interface InvestigationRuntimeCoordinatorInput {
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
  /**
   * Optional by design (M1): a read-only composition that never needs to
   * mint an authorization token or execute an active probe may omit this.
   * When absent, any hypothesis that would require active execution is
   * reported as a truthful failed/inconclusive step — never silently
   * skipped, and never treated as executed or successful.
   */
  readonly authorizationService?: ReadObservationAuthorizationPort;
  /**
   * Optional by design (M1), same rationale as `authorizationService`.
   * Execution is still never attempted without an established authorization
   * token, regardless of whether this is present.
   */
  readonly executionService?: ReadObservationExecutionPort;
  readonly recordOutcome: (args: {
    readonly assessmentId: string;
    readonly planId: string;
    readonly executionRecord: AttackExecutionRecord;
  }) => Promise<unknown>;
  readonly identities?: readonly AttackPlanIdentityContext[];
  readonly primaryIdentity?: AttackCapabilityIdentityRef;
  readonly secondaryIdentity?: AttackCapabilityIdentityRef;
  readonly listNewlyReachableTargets?: () => Promise<readonly string[]>;
  readonly timeBudgetMs?: number;
  readonly stepBudget?: number;
  readonly nowMs?: () => number;
  readonly now?: () => number;
  readonly differentialRecords?: readonly {
    readonly url: string;
    readonly outcome: string;
    readonly reasonCode: string;
  }[];
  readonly maxRequestsPerHypothesis?: number;
}

export interface InvestigationRuntimeCoordinatorResult {
  readonly findings: readonly Finding[];
  readonly probeInventory: ProbeInventory;
  readonly hypotheses: readonly SecurityHypothesis[];
  readonly feedbackSteps: readonly InvestigationFeedbackStepRecord[];
  readonly record: ReadInvestigationLoopRecord;
  readonly transcript: AssessmentTranscript;
}

export class InvestigationRuntimeCoordinator {
  public async execute(
    input: InvestigationRuntimeCoordinatorInput
  ): Promise<InvestigationRuntimeCoordinatorResult> {
    const nowMs = input.nowMs ?? input.now ?? (() => Date.now());
    const startedMs = nowMs();
    const timeBudgetMs = input.timeBudgetMs ?? READ_INVESTIGATION_DEFAULT_TIME_BUDGET_MS;
    const stepBudget = input.stepBudget ?? READ_INVESTIGATION_DEFAULT_STEP_BUDGET;
    const maxRequestsPerHyp = input.maxRequestsPerHypothesis ?? 2;

    let inventory = input.probeInventory;
    let findings = [...input.findings];
    const executedSteps: ReadInvestigationExecutedStep[] = [];
    const transcriptSteps: AssessmentTranscriptExecutedStep[] = [];
    const withheldPlans: AssessmentTranscriptWithheldPlan[] = [];
    const skippedNonReadPlanIds: string[] = [];
    const seenOutOfScopeUrls: string[] = [];
    const executedPlanIds = new Set<string>();
    const feedbackSteps: InvestigationFeedbackStepRecord[] = [];
    const baselineSnapshots = new Map<string, SafeResponseSnapshot>();
    let correlated = false;

    const identityCount = (input.primaryIdentity ? 1 : 0) + (input.secondaryIdentity ? 1 : 0);
    const hasJwt = Boolean(input.identities?.some((id) => id.hasJwt));

    // Absorb candidate URLs from findings into probe inventory
    const initialCandidates: ProbeCandidate[] = [];
    for (const f of findings) {
      const meta = f.metadata;
      const endpoint =
        meta && typeof meta === 'object' && 'endpointUrl' in meta
          ? String((meta as { endpointUrl?: unknown }).endpointUrl)
          : undefined;
      const rawUrl = endpoint ?? (f.target.startsWith('http') ? f.target : undefined);
      if (rawUrl) {
        initialCandidates.push({ url: rawUrl, source: 'read_step' });
      }
    }
    if (initialCandidates.length > 0) {
      const appended = appendProbeCandidates(
        inventory,
        input.scopeGrant,
        new Date(startedMs).toISOString(),
        initialCandidates
      );
      inventory = appended.inventory;
      for (const rej of appended.rejectedUrls) {
        if (!seenOutOfScopeUrls.includes(rej)) seenOutOfScopeUrls.push(rej);
      }
    }

    // 1. Initial Hypothesis Generation from Real Observations
    const initialHypotheses = generateHypothesesFromObservations({
      assessmentId: input.assessmentId,
      scanId: input.lineage.scanId,
      targetDomain: input.circuitHost,
      probeInventory: inventory,
      findings,
      differentialRecords: input.differentialRecords,
      sessionContext: {
        hasAuthenticatedContext: Boolean(input.primaryIdentity),
        hasSecondaryAuthenticatedContext: Boolean(input.secondaryIdentity),
        hasJwt,
      },
      nowIso: new Date(startedMs).toISOString(),
    });

    const hypothesesMap = new Map<string, SecurityHypothesis>(
      initialHypotheses.map((h) => [h.hypothesisId, h])
    );

    const withheldNoted = new Set<string>();
    const skippedNoted = new Set<string>();

    const RUNNABLE_STATUSES = new Set<AttackPlan['status']>([
      'ready_for_authorization',
      'authorized',
    ]);

    const noteSkipped = (plans: readonly AttackPlan[]): void => {
      for (const p of plans) {
        if (p.assessmentId !== input.assessmentId) continue;
        const declared = p.authorizationBlastRadiusClass;
        if (
          declared !== undefined &&
          !isReadClass(declared) &&
          !withheldNoted.has(p.planId)
        ) {
          withheldNoted.add(p.planId);
          withheldPlans.push({
            capability: p.capability,
            target: transcriptTargetForPlan(p),
          });
        }
        if (!RUNNABLE_STATUSES.has(p.status)) continue;
        if (readObservationClassForPlan(p) !== null) continue;
        if (skippedNoted.has(p.planId)) continue;
        skippedNoted.add(p.planId);
        skippedNonReadPlanIds.push(p.planId);
      }
    };

    const registerPlans = (plans: readonly AttackPlan[]): void => {
      noteSkipped(plans);
      for (const p of plans) {
        if (!RUNNABLE_STATUSES.has(p.status)) continue;
        const readClass = readObservationClassForPlan(p);
        if (!readClass) continue;
        const targetUrl = p.targetUrl ?? `https://${input.circuitHost}/`;
        const norm = normalizeStructuralRoute(targetUrl);
        const hypId = stableHypothesisId(p.capability as SecurityHypothesisKind, norm.normalizedPattern);
        if (!hypothesesMap.has(hypId)) {
          hypothesesMap.set(hypId, {
            contractVersion: HYPOTHESIS_SCHEDULER_CONTRACT_VERSION,
            kind: 'security_hypothesis',
            hypothesisId: hypId,
            hypothesisKind: p.capability as SecurityHypothesisKind,
            createdAt: p.createdAt,
            title: p.title || `${p.capability} on ${norm.normalizedPattern}`,
            epistemicStatus: 'OBSERVED',
            state: 'candidate',
            score: p.capability === 'supabase_rls_read_confirm' ? 95 : 75,
            priorityBand: 'high',
            rationale: p.reasoning || `Pre-planned read investigation for ${p.capability}`,
            explanation: Object.freeze([`Assessment plan ${p.planId} registered for capability ${p.capability}`]),
            sourceFindingIds: Object.freeze(p.sourceFindingIds ?? []),
            targetUrl,
            normalizedRoutePattern: norm.normalizedPattern,
            suggestedCapability: p.capability,
            deferredToManualValidation: isDeferredToManualValidation(p.capability),
            supportingEvidence: Object.freeze([`Registered plan ${p.planId}`]),
            contradictingEvidence: Object.freeze([]),
            blocked: false,
            blockReason: 'none',
            dependencies: {
              requiresAuth: readClass === 'read_authenticated' || readClass === 'read_escalated',
              requiresSecondaryAuth: readClass === 'read_escalated',
              requiresParameter: false,
              satisfied: true,
              blockReason: 'none',
            },
            investigationCount: 0,
            originatingObservation: {
              sourceKind: 'probe_inventory',
              summary: `Pre-planned capability ${p.capability} on ${targetUrl}`,
            },
          });
        }
      }
    };

    const existingInitialPlans = await input.planRepository.listByAssessmentId(input.assessmentId);
    registerPlans(existingInitialPlans);

    const rememberRejected = (urls: readonly string[]): void => {
      for (const url of urls) {
        if (!seenOutOfScopeUrls.includes(url)) seenOutOfScopeUrls.push(url);
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
        registerPlans(novel);
      }
    };

    const consideredReachable = new Set<string>();
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

    const finish = (stopReason: ReadInvestigationStopReason): InvestigationRuntimeCoordinatorResult => {
      const record: ReadInvestigationLoopRecord = {
        contractVersion: READ_INVESTIGATION_LOOP_CONTRACT_VERSION,
        kind: 'read_investigation_loop',
        assessmentId: input.assessmentId,
        scanId: input.lineage.scanId,
        authorizationGrantId: input.lineage.authorizationGrantId,
        authorizationDecisionId: input.lineage.authorizationDecisionId,
        actorId: input.lineage.actorId,
        stopReason,
        stepsExecuted: executedSteps.length,
        stepBudget,
        timeBudgetMs,
        executedSteps: Object.freeze(executedSteps),
        skippedNonReadPlanIds: Object.freeze(skippedNonReadPlanIds),
        seenOutOfScopeUrls: Object.freeze(seenOutOfScopeUrls),
      };

      const transcript: AssessmentTranscript = buildAssessmentTranscript({
        discoveries: inventory,
        findings,
        executedSteps: transcriptSteps,
        withheldPlans,
        stopReason,
      });

      return {
        findings: Object.freeze(findings),
        probeInventory: inventory,
        hypotheses: Object.freeze([...hypothesesMap.values()]),
        feedbackSteps: Object.freeze(feedbackSteps),
        record,
        transcript,
      };
    };

    const decision = input.verifiedAuthorizationDecision;
    // The explicit `=== undefined` check is redundant at runtime — the
    // validator already returns false for undefined — but it gives
    // TypeScript a native narrowing expression, so `decision` is typed
    // `VerifiedAuthorizationDecision` (not `| undefined`) for the rest of
    // this function, matching the two ports' now-exact request contracts.
    if (decision === undefined || !isRuntimeEstablishedVerifiedAuthorizationDecision(decision)) {
      return finish('verified_decision_missing');
    }

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
      const novelFindingsFiltered = novelFindings.filter((finding) => {
        const url = findingSurfaceUrl(finding);
        return url !== null && scoped.inScopeUrls.has(url);
      });
      const novelSignalsFiltered = draftSignals.filter((signal) => {
        const url = absoluteUrl(signal.endpointUrl, undefined);
        return url !== null && scoped.inScopeUrls.has(url);
      });
      if (novelFindingsFiltered.length > 0) {
        findings = [...findings, ...novelFindingsFiltered];
      }
      await saveNovelPlans({
        findingsForSurface: novelFindingsFiltered,
        hints,
        draftSignals: novelSignalsFiltered,
      });
    };

    /**
     * M1 — truthful failed/inconclusive step record for a hypothesis that
     * cannot proceed: either because no authorization token could be
     * established (pre-existing behavior, any denial reason), or because no
     * active-execution capability is configured for this composition (new).
     * Never marks the step as completed/successful and never fabricates an
     * authorization or execution result — it simply records that the step
     * did not happen, exactly like the pre-existing authorization-denial path.
     */
    const recordCapabilityUnavailableStep = (args: {
      readonly plan: AttackPlan;
      readonly blastRadiusClass: ReadObservationBlastRadiusClass;
      readonly hypothesis: SecurityHypothesis;
      readonly reasonCode: string;
    }): void => {
      executedSteps.push({
        planId: args.plan.planId,
        capability: args.plan.capability,
        blastRadiusClass: args.blastRadiusClass,
        status: 'failed',
        reasonCode: args.reasonCode,
      });
      transcriptSteps.push({
        capability: args.plan.capability,
        url: transcriptTargetForPlan(args.plan),
        blastRadiusClass: args.blastRadiusClass,
        outcome: 'failed',
        invocation: { kind: 'not_invoked' },
      });
      hypothesesMap.set(args.hypothesis.hypothesisId, {
        ...args.hypothesis,
        state: 'inconclusive',
        investigationCount: (args.hypothesis.investigationCount ?? 0) + 1,
        blocked: true,
        blockReason: 'none',
      });
    };

    // Main Canonical Investigation Feedback Loop
    while (true) {
      await absorbNewlyReachableTargets();

      // 1. Hard invariant checks
      if (input.coordinator.isCircuitOpen(input.circuitHost)) {
        await correlateOnce();
        return finish('circuit_open');
      }
      if (nowMs() - startedMs >= timeBudgetMs) {
        await correlateOnce();
        return finish('time_budget_exhausted');
      }
      if (executedSteps.filter((s) => s.status === 'preflight_denied').length >= READ_INVESTIGATION_PREFLIGHT_DENIED_CAP) {
        await correlateOnce();
        return finish('preflight_denied');
      }
      const budgetConsumed = executedSteps.filter((s) => s.status !== 'preflight_denied').length;
      if (budgetConsumed >= stepBudget) {
        await correlateOnce();
        return finish('step_budget_exhausted');
      }

      // 2. Pure deterministic scheduler selects the top actionable hypothesis & plan
      const currentHypothesesList = [...hypothesesMap.values()];
      const nextSelection = scheduleNextInvestigation(currentHypothesesList, {
        identityCount,
        hasJwt,
        nowIso: new Date(nowMs()).toISOString(),
      });

      // Bounded termination: If no actionable hypothesis remains, terminate cleanly
      // NO SILENT FALLBACK TO STATIC PRECOMPUTED PLANS
      if (!nextSelection) {
        if (!correlated) {
          await correlateOnce();
          continue;
        }
        return finish(
          inventoryHasScreen(inventory.entries)
            ? 'no_app_routes_remaining'
            : 'no_read_plans_remaining'
        );
      }

      // 3. Just-In-Time Plan Synthesis from InvestigationPlan
      const candidateBlast = READ_CLASS_BY_CAPABILITY[nextSelection.plan.capability] ?? 'read_public';
      const blastRadiusClass: ReadObservationBlastRadiusClass = candidateBlast;

      // Check if plan already exists in repository (preferring refined child/dependent plans), otherwise synthesize JIT
      const existingPlans = await input.planRepository.listByAssessmentId(input.assessmentId);
      let targetPlan: AttackPlan | undefined = existingPlans.find(
        (p) =>
          !executedPlanIds.has(p.planId) &&
          RUNNABLE_STATUSES.has(p.status) &&
          (p.planId === nextSelection.plan.planId ||
            (p.capability === nextSelection.plan.capability &&
              p.targetUrl === nextSelection.plan.targetUrl &&
              Array.isArray(p.dependsOn) &&
              p.dependsOn.length > 0))
      );
      if (!targetPlan) {
        targetPlan = existingPlans.find(
          (p) =>
            !executedPlanIds.has(p.planId) &&
            RUNNABLE_STATUSES.has(p.status) &&
            (p.planId === nextSelection.plan.planId ||
              (p.capability === nextSelection.plan.capability && p.targetUrl === nextSelection.plan.targetUrl))
        );
      }

      if (!targetPlan) {
        targetPlan = {
          contractVersion: 'fixguard-attack-planning/v0',
          kind: 'attack_plan',
          planId: nextSelection.plan.planId,
          assessmentId: input.assessmentId,
          scanId: input.lineage.scanId,
          capability: nextSelection.plan.capability,
          title: nextSelection.selectedHypothesis.title,
          reasoning: nextSelection.selectedHypothesis.rationale,
          status: 'ready_for_authorization',
          blastRadius: 'single_endpoint',
          capabilityGained: 'none',
          authorizationBlastRadiusClass: candidateBlast,
          sourceFindingIds: nextSelection.selectedHypothesis.sourceFindingIds,
          sourceFindingTypes: ['observed_surface'],
          prerequisites: [],
          steps: [
            {
              stepId: `${nextSelection.plan.planId}_step_1`,
              ordinal: 1,
              title: 'Controlled probe',
              description: nextSelection.plan.requestPurpose,
              status: 'ready',
              requiredPermissions: ['activeValidation'],
            },
          ],
          targetUrl: nextSelection.plan.targetUrl,
          planOrigin: 'observed_surface',
          lineage: { ...input.lineage },
          createdAt: nextSelection.plan.createdAt,
          executable: false,
        };
        await input.planRepository.savePlans([targetPlan]);
      }

      // 4. Mint read observation authorization token — only if an
      // authorization capability is configured for this composition. A
      // read-only composition that omits it never mints a token and never
      // reaches step 5; the hypothesis is reported as failed/inconclusive,
      // exactly like any other authorization-denial reason below.
      if (!input.authorizationService) {
        executedPlanIds.add(targetPlan.planId);
        recordCapabilityUnavailableStep({
          plan: targetPlan,
          blastRadiusClass,
          hypothesis: nextSelection.selectedHypothesis,
          reasonCode: 'active_authorization_capability_not_configured',
        });
        continue;
      }

      const minted = await input.authorizationService.authorizeReadObservationFromVerifiedDecision({
        contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
        kind: AUTHORIZE_READ_OBSERVATION_REQUEST_KIND,
        planId: targetPlan.planId,
        assessmentId: input.assessmentId,
        blastRadiusClass,
        operatorId: input.lineage.actorId,
        verifiedAuthorizationDecision: decision,
      });

      executedPlanIds.add(targetPlan.planId);

      if (minted.status !== 'established') {
        recordCapabilityUnavailableStep({
          plan: targetPlan,
          blastRadiusClass,
          hypothesis: nextSelection.selectedHypothesis,
          reasonCode: minted.reasonCode,
        });
        continue;
      }

      // 5. Execute probe through AttackExecutionService and capture full
      // response — only if an execution capability is configured.
      // Authorization is already established at this point; execution is
      // simply never attempted when this is absent (never fabricated as
      // completed, never silently dropped).
      if (!input.executionService) {
        recordCapabilityUnavailableStep({
          plan: targetPlan,
          blastRadiusClass,
          hypothesis: nextSelection.selectedHypothesis,
          reasonCode: 'active_execution_capability_not_configured',
        });
        continue;
      }
      // Narrowed to a local const: the guard above only narrows
      // `input.executionService` within this synchronous block — the
      // closure passed to captureStepInvocation below is a separate function
      // scope, so TypeScript cannot carry that narrowing into it otherwise.
      const executionService = input.executionService;

      let capturedResponse: {
        statusCode: number;
        headers: Readonly<Record<string, string>>;
        bodyText: string;
        responseTimeMs: number;
      } | undefined;

      const reqStarted = nowMs();
      const scopedTransport: IdorHttpProbeTransport = async (request) => {
        noteHttpProbeReceipt(request.method, request.url);
        const resp = await input.transport(request);
        capturedResponse = {
          statusCode: resp.statusCode,
          headers: { ...(resp.headers ?? {}) },
          bodyText: resp.bodyText ?? '',
          responseTimeMs: nowMs() - reqStarted,
        };
        return resp;
      };

      const captured = await captureStepInvocation(() =>
        executionService.execute({
          contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
          kind: 'attack_execution_request',
          planId: targetPlan.planId,
          assessmentId: input.assessmentId,
          token: minted.token,
          scopeGrant: input.scopeGrant,
          coordinator: input.coordinator,
          dnsResolver: input.dnsResolver,
          findings: findings.map((f) => f),
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
          planId: targetPlan.planId,
          executionRecord: result.record,
        });
        findings = result.record.updatedFindings.map((f) => f);
      }

      // 6. Evaluate Test Validity with Full Response Facets (Corrected 403 Semantics)
      const testSignals: HttpResponseDefenseSignals = {
        statusCode: capturedResponse?.statusCode,
        targetHost: input.circuitHost,
        headerNames: capturedResponse ? Object.keys(capturedResponse.headers) : undefined,
        headerValues: capturedResponse?.headers,
        bodyExcerpt: capturedResponse?.bodyText?.slice(0, 500),
      };

      const validityEval = evaluateTestValidity({
        probe: testSignals,
        observedAt: new Date(nowMs()).toISOString(),
      });

      const recorded = loopStepOutcome(result);

      executedSteps.push({
        planId: targetPlan.planId,
        capability: targetPlan.capability,
        blastRadiusClass,
        status: recorded.status,
        reasonCode: recorded.reasonCode,
      });

      transcriptSteps.push({
        capability: targetPlan.capability,
        url: transcriptTargetForPlan(targetPlan),
        blastRadiusClass,
        outcome: recorded.status,
        invocation: captured.invocation,
      });

      if (result.reasonCode === 'gate_circuit_open') {
        await correlateOnce();
        return finish('circuit_open');
      }

      // 7. Genuinely Integrate ResponseComparatorService for Comparative Differential Evidence
      let comparisonSignificance: string | undefined;
      let statusDifference = false;
      const targetUrl = targetPlan.targetUrl ?? `https://${input.circuitHost}/`;

      if (capturedResponse) {
        const currentSnap = buildSafeSnapshot({
          scanId: input.lineage.scanId,
          role: 'validation',
          url: targetUrl,
          statusCode: capturedResponse.statusCode,
          headers: capturedResponse.headers,
          bodyText: capturedResponse.bodyText,
          responseTimeMs: capturedResponse.responseTimeMs,
        });

        const baseline = baselineSnapshots.get(targetUrl);
        if (baseline) {
          const comparisonReq: ResponseComparisonRequest = {
            contractVersion: RESPONSE_COMPARATOR_CONTRACT_VERSION,
            kind: 'response_comparison_request',
            comparisonId: `cmp_${nextSelection.selectedHypothesis.hypothesisId}_${executedSteps.length}`,
            scanId: input.lineage.scanId,
            requestedAt: new Date(nowMs()).toISOString(),
            baseline,
            validation: currentSnap,
            comparisonMode: nextSelection.selectedHypothesis.dependencies?.requiresAuth
              ? 'authorization_difference'
              : 'http_difference',
            thresholds: {
              contentLengthDeltaPercentSignificant: 15,
              responseTimeDeltaMsSignificant: 3000,
            },
            classification: {
              createsRealFindings: false,
              createsPersistedEvidence: false,
              confirmsVulnerabilities: false,
              makesRiskClaims: false,
              makesSeverityClaims: false,
              makesImpactClaims: false,
              executesNetwork: false,
              executesTools: false,
              persistsData: false,
            },
          };
          const compResult = compareResponses(comparisonReq, new Date(nowMs()).toISOString());
          comparisonSignificance = compResult.significance
            ? `${compResult.significance.comparisonSignalStrength}_diff_${compResult.significance.strongestSignal}`
            : undefined;
          statusDifference = compResult.difference ? compResult.difference.statusCodeChanged : false;
        } else {
          baselineSnapshots.set(targetUrl, currentSnap);
        }
      }

      // 8. Formulate Closed-Loop Investigation Execution Result
      let outcome: 'supported' | 'weakened' | 'refuted' | 'inconclusive' = 'inconclusive';
      let safeEvidenceMessage = 'Probe completed with inconclusive result';

      const stepRecord = result.record?.stepRecords[result.record.stepRecords.length - 1];
      const stepOutcome = stepRecord?.outcome;
      const stepReason = stepRecord?.reasonCode;

      if (validityEval.verdict === 'interfered' || stepReason === 'waf_or_challenge_interfered') {
        outcome = 'inconclusive';
        safeEvidenceMessage = 'WAF/edge challenge interfered with probe; cannot claim application denial';
      } else if (result.status === 'completed') {
        if (stepOutcome === 'refuted') {
          outcome = 'refuted';
          safeEvidenceMessage = `Target response refutes hypothesis (access control properly enforced on ${targetUrl})`;
        } else if (
          capturedResponse?.statusCode === 403 &&
          (nextSelection.selectedHypothesis.hypothesisKind === 'auth_bypass' ||
            nextSelection.selectedHypothesis.hypothesisKind === 'auth_boundary_differential')
        ) {
          outcome = 'refuted';
          safeEvidenceMessage = `Target returned application 403 Forbidden; auth boundary hypothesis refuted on ${targetUrl}`;
        } else if (stepOutcome === 'succeeded' || stepOutcome === 'observed') {
          outcome = 'supported';
          safeEvidenceMessage = `Observation corroborates hypothesis on ${targetUrl}${comparisonSignificance ? ` (comparison: ${comparisonSignificance})` : ''}`;
        } else {
          outcome = 'weakened';
          safeEvidenceMessage = `Weakened hypothesis: ${stepReason ?? result.reasonCode}`;
        }
      } else {
        outcome = 'inconclusive';
        safeEvidenceMessage = `Investigation step ended with status ${result.status} (${result.reasonCode})`;
      }

      // 9. Update Canonical Hypothesis State via Feedback State Machine
      const activeHyp = nextSelection.selectedHypothesis;
      const executionResult: InvestigationExecutionResult = {
        contractVersion: 'fixguard-investigation-feedback/v0',
        kind: 'investigation_execution_result',
        planId: targetPlan.planId,
        hypothesisId: activeHyp.hypothesisId,
        targetUrl,
        executedAt: new Date(nowMs()).toISOString(),
        status: result.status === 'completed' ? 'completed' : 'failed',
        statusCode: capturedResponse?.statusCode,
        testValidityVerdict: validityEval.verdict,
        outcome,
        reasonCode: recorded.reasonCode,
        safeEvidenceMessage,
      };

      const feedbackRes = applyInvestigationFeedback(activeHyp, executionResult, maxRequestsPerHyp);
      hypothesesMap.set(activeHyp.hypothesisId, feedbackRes.updatedHypothesis);
      feedbackSteps.push(feedbackRes.stepRecord);

      // 10. Discover Newly Reachable Targets & Expand Surface
      await absorbNewlyReachableTargets();
    }
  }
}
