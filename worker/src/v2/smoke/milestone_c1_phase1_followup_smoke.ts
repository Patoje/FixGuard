/**
 * C1 — When recon closes, the assessment proposes advisory children and
 * runs the read loop. The loop is not started from a smoke-only caller.
 */
import assert from 'node:assert/strict';
import { ACTIVE_INVESTIGATION_CONTRACT_VERSION } from '../active-investigation/ActiveInvestigationContracts.js';
import { ActiveInvestigationRuntimeService } from '../active-investigation/ActiveInvestigationRuntimeService.js';
import type {
  ReadOnlyLoopRequest,
  ReadOnlyLoopResult,
  ReadOnlyLoopStep,
} from '../active-investigation/ActiveInvestigationRuntimeService.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import type {
  OrchestratedAssessmentStatusDto,
  OrchestratedAssessmentSummaryDto,
} from '../application/OrchestratedAssessmentContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import type {
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../attack-execution/AttackExecutionContracts.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackCapabilityKind,
  type AttackPlan,
} from '../attack-planning/AttackPlanContracts.js';
import {
  proposeAuthBoundaryResourceRead,
  proposeSessionBDifferential,
} from '../attack-planning/F3ChainProposal.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import { tryBuildObservedFact } from '../observation/ObservedFactCatalogService.js';
import { buildPhase1ReadLoopSection } from '../reporting-boundary/ReportSectionBuilders.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

const TOKEN = 'session-bearer-must-not-enter-fact';
const ENDPOINT = 'https://app.example.com/api/orders/ord_123';
const READ_LOOP_CAPABILITIES = new Set<AttackCapabilityKind>([
  'auth_boundary_differential',
  'supabase_rls_read_confirm',
]);

class RecordingInvestigationRuntime extends ActiveInvestigationRuntimeService {
  readonly loopRequests: ReadOnlyLoopRequest[] = [];
  readonly loopResults: ReadOnlyLoopResult[] = [];

  public override async runReadOnlyLoop(request: ReadOnlyLoopRequest): Promise<ReadOnlyLoopResult> {
    this.loopRequests.push(request);
    const result = await super.runReadOnlyLoop(request);
    this.loopResults.push(result);
    return result;
  }
}

class CancellingBeforeLoopRuntime extends RecordingInvestigationRuntime {
  public override async runReadOnlyLoop(request: ReadOnlyLoopRequest): Promise<ReadOnlyLoopResult> {
    const snapshot = this.getSnapshot(request.investigationId);
    assert.ok(snapshot);
    const cancelled = this.cancelInvestigation({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'cancel_active_investigation_request',
      investigationId: request.investigationId,
      operatorId: snapshot.lineage.actorId,
      mode: 'cancel',
    });
    assert.equal(cancelled.status, 'cancelled');
    return super.runReadOnlyLoop(request);
  }
}

function hermeticTransport(): (request: HttpProbeRequest) => Promise<HttpProbeResponse> {
  return async (request: HttpProbeRequest): Promise<HttpProbeResponse> => {
    if (request.headers['authorization']) {
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: '{"order":"ord_123"}',
        responseTimeMs: 1,
      };
    }
    return {
      statusCode: 401,
      headers: { 'content-type': 'application/json' },
      bodyText: '{"error":"unauthorized"}',
      responseTimeMs: 1,
    };
  };
}

const SKIP_STAGES = [
  'stage_1_domain_zone',
  'stage_2_port_service',
  'stage_3_web_tls',
  'stage_4_crawling_parameters',
  'stage_deep_recon',
  'stage_5_secret_inspection',
] as const;

const PUBLISHABLE_KEY = 'sb_publishable_HermeticObservedKey99';

function challengeResponse(): HttpProbeResponse {
  return {
    statusCode: 403,
    headers: {
      'content-type': 'text/html',
      'cf-ray': 'abc123',
      server: 'cloudflare',
    },
    bodyText: '<html>Just a moment... cf-browser-verification</html>',
    responseTimeMs: 1,
  };
}

function jwtWithRole(role: string): string {
  const part = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${part({ alg: 'none', typ: 'JWT' })}.${part({ role, iss: 'supabase' })}.sig`;
}

class LoopProbeRuntime extends RecordingInvestigationRuntime {
  inLoop = false;

  public override async runReadOnlyLoop(request: ReadOnlyLoopRequest): Promise<ReadOnlyLoopResult> {
    this.inLoop = true;
    try {
      return await super.runReadOnlyLoop(request);
    } finally {
      this.inLoop = false;
    }
  }
}

function directScope(host: string): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_c1_direct_001',
    scanId: 'scan_c1_direct_001',
    issuedAt: '2026-09-30T12:00:00.000Z',
    expiresAt: '2027-09-28T00:00:00.000Z',
    subject: {
      targetKind: 'origin',
      normalizedOrigin: `https://${host}`,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for C1 read-loop smoke',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: true,
      lightValidation: true,
      activeValidation: true,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: [host, 'other.example.com'],
      allowedHosts: [host, 'other.example.com'],
      allowedOrigins: [`https://${host}`, 'https://other.example.com'],
      allowedMethods: ['GET', 'HEAD'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: false,
      allowCredentialUse: false,
      allowOobCallbacks: false,
      allowThirdPartyTargets: false,
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
}

function directDecision(host: string): VerifiedAuthorizationDecision {
  const nowIso = new Date().toISOString();
  const auth = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asmt_c1_direct_001',
      scanId: 'scan_c1_direct_001',
      authorizationDecisionId: 'dec_c1_direct_001',
      authorizedActor: { actorId: 'usr_secops_api', actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant: directScope(host),
    },
    nowIso
  );
  assert.equal(auth.status, 'established');
  if (auth.status !== 'established' || !auth.decision) {
    throw new Error('verified authorization was not established');
  }
  return auth.decision;
}

function directPlan(planId: string, capability: AttackCapabilityKind, targetUrl: string): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId,
    assessmentId: 'asmt_c1_direct_001',
    scanId: 'scan_c1_direct_001',
    capability,
    title: 'Advisory plan',
    reasoning: 'Hermetic advisory plan.',
    status: 'ready_for_authorization',
    blastRadius: 'single_endpoint',
    capabilityGained: 'read_authenticated',
    sourceFindingIds: [],
    sourceFindingTypes: ['observed_surface'],
    prerequisites: [],
    steps: [
      {
        stepId: `step_${planId}`,
        ordinal: 1,
        title: 'Read',
        description: 'GET',
        status: 'blocked',
        requiredPermissions: ['activeValidation'],
      },
    ],
    planOrigin: 'observed_surface',
    lineage: {
      assessmentId: 'asmt_c1_direct_001',
      scanId: 'scan_c1_direct_001',
      authorizationGrantId: 'grant_c1_direct_001',
      authorizationDecisionId: 'dec_c1_direct_001',
      actorId: 'usr_secops_api',
    },
    createdAt: '2026-09-30T12:00:00.000Z',
    targetUrl,
    ...(capability === 'supabase_rls_read_confirm' ? { parameterName: 'widgets' } : {}),
    executable: false,
  };
}

function directStep(
  decision: VerifiedAuthorizationDecision,
  capability: AttackCapabilityKind,
  targetUrl: string
): ReadOnlyLoopStep {
  const plan = directPlan(`plan_${capability}_${targetUrl.replace(/[^a-z0-9]+/gi, '_').slice(-40)}`, capability, targetUrl);
  const context: AttackCapabilityInvocationContext = {
    plan,
    step: {
      ...plan.steps[0]!,
      blastRadiusClass: 'read_authenticated',
    },
    targetHost: new URL(targetUrl).hostname,
    targetUrl,
    scopeGrant: decision.scopeGrant,
    findings: [],
    primaryIdentity: {
      identityId: 'id_session_a',
      headers: {
        authorization: 'Bearer pasted-session',
        cookie: 'cf_clearance=pasted-clearance',
      },
    },
    verifiedAuthorizationDecision: decision,
  };
  return {
    stepId: plan.planId,
    capability,
    blastRadiusClass: 'read_authenticated',
    context,
  };
}

async function assertWafDoesNotBurnTheReadLoop(): Promise<void> {
  const nowIso = new Date().toISOString();
  const host = 'waf.example.com';
  const myaccount = `https://${host}/myaccount`;
  const otherPath = `https://${host}/a/b`;
  const decision = directDecision(host);
  const runtime = new ActiveInvestigationRuntimeService();
  const started = runtime.startInvestigation({
    contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
    kind: 'start_active_investigation_request',
    investigationId: 'inv_c1_waf_cap',
    lineage: {
      assessmentId: 'asmt_c1_direct_001',
      scanId: 'scan_c1_direct_001',
      authorizationGrantId: 'grant_c1_direct_001',
      authorizationDecisionId: 'dec_c1_direct_001',
      actorId: 'usr_secops_api',
    },
    verifiedAuthorizationDecision: decision,
    budget: {
      maxRequests: 10,
      maxDurationMs: 600_000,
      maxConcurrentSteps: 1,
      requestsPerSecondCeiling: 5,
      maxConcurrencyCeiling: 2,
    },
    openHypothesisRefs: [],
    startedAt: nowIso,
  });
  assert.equal(started.status, 'started');
  const calls: string[] = [];
  const cookies: string[] = [];
  const registry = new AttackCapabilityRegistry([
    {
      capability: 'auth_boundary_differential',
      async execute(ctx) {
        calls.push(ctx.targetUrl);
        cookies.push(ctx.primaryIdentity?.headers?.cookie ?? '');
        if (ctx.targetHost === 'other.example.com') {
          return { outcome: 'observed', reasonCode: 'read_observed', safeMessage: 'other host' };
        }
        return {
          outcome: 'failed',
          reasonCode: 'waf_or_challenge_interfered',
          safeMessage: 'challenge',
        };
      },
    },
    {
      capability: 'supabase_rls_read_confirm',
      async execute() {
        calls.push('supabase');
        return { outcome: 'observed', reasonCode: 'read_observed', safeMessage: 'rls' };
      },
    } satisfies AttackCapabilityPort,
  ]);
  const coordinator = new TargetExecutionCoordinator({ requestsPerSecond: 5, maxConcurrency: 2 });
  const sameHostPaths = [myaccount, otherPath, `https://${host}/a/c`, `https://${host}/a/d`];
  for (let i = 0; i < 16; i += 1) sameHostPaths.push(`https://${host}/a/x${i}`);
  const loop = await runtime.runReadOnlyLoop({
    investigationId: 'inv_c1_waf_cap',
    registry,
    steps: [
      ...sameHostPaths.map((url) => directStep(decision, 'auth_boundary_differential', url)),
      directStep(decision, 'supabase_rls_read_confirm', `https://${host}/rest/v1/widgets`),
      directStep(decision, 'auth_boundary_differential', 'https://other.example.com/myaccount'),
    ],
    nowIso,
    allowAssessmentAuthForCapabilities: READ_LOOP_CAPABILITIES,
    coordinator,
  });
  assert.equal(loop.status, 'completed');
  assert.equal(loop.reasonCode, 'read_loop_completed');
  assert.notEqual(loop.reasonCode, 'budget_exceeded');
  const accountCalls = calls.filter((url) => url === myaccount);
  assert.equal(accountCalls.length, 3);
  assert.equal(calls.filter((url) => url.includes('/a/')).length, 0);
  assert.equal(calls.filter((url) => url === 'supabase').length, 1);
  assert.equal(calls.filter((url) => url.includes('other.example.com')).length, 1);
  assert.equal(cookies.length, 4);
  assert.ok(cookies.slice(0, 3).every((cookie) => cookie === 'cf_clearance=pasted-clearance'));
  assert.equal(coordinator.getObservedWaf(host), 'waf_or_challenge_interfered');
  const skipped = loop.steps.filter(
    (step) => step.capability === 'auth_boundary_differential' && step.stepId.includes('_a_')
  );
  assert.ok(skipped.length > 0);
  for (const step of skipped) {
    assert.equal(step.disposition, 'recommended');
    assert.equal(step.reasonCode, 'waf_or_challenge_interfered');
  }
  const executedAccount = loop.steps.find((step) => step.stepId.includes('myaccount') && step.stepId.includes(host.replace(/\./g, '_')));
  assert.ok(executedAccount);
  assert.equal(executedAccount.disposition, 'executed');
  assert.equal(executedAccount.reasonCode, 'waf_or_challenge_interfered');

  const plainRuntime = new ActiveInvestigationRuntimeService();
  const plainStarted = plainRuntime.startInvestigation({
    contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
    kind: 'start_active_investigation_request',
    investigationId: 'inv_c1_waf_plain',
    lineage: {
      assessmentId: 'asmt_c1_direct_001',
      scanId: 'scan_c1_direct_001',
      authorizationGrantId: 'grant_c1_direct_001',
      authorizationDecisionId: 'dec_c1_direct_001',
      actorId: 'usr_secops_api',
    },
    verifiedAuthorizationDecision: decision,
    budget: {
      maxRequests: 10,
      maxDurationMs: 600_000,
      maxConcurrentSteps: 1,
    },
    openHypothesisRefs: [],
    startedAt: nowIso,
  });
  assert.equal(plainStarted.status, 'started');
  const plainCalls: string[] = [];
  const plainLoop = await plainRuntime.runReadOnlyLoop({
    investigationId: 'inv_c1_waf_plain',
    registry: new AttackCapabilityRegistry([
      {
        capability: 'auth_boundary_differential',
        async execute(ctx) {
          plainCalls.push(ctx.targetUrl);
          return {
            outcome: 'failed',
            reasonCode: 'waf_or_challenge_interfered',
            safeMessage: 'challenge',
          };
        },
      },
    ]),
    steps: [
      directStep(decision, 'auth_boundary_differential', otherPath),
      directStep(decision, 'auth_boundary_differential', `https://${host}/a/c`),
    ],
    nowIso,
    allowAssessmentAuthForCapabilities: READ_LOOP_CAPABILITIES,
    coordinator: new TargetExecutionCoordinator({ requestsPerSecond: 5, maxConcurrency: 2 }),
  });
  assert.deepEqual(plainCalls, [otherPath]);
  assert.equal(plainLoop.status, 'completed');
  assert.equal(plainLoop.steps[1]?.disposition, 'recommended');
  assert.equal(plainLoop.steps[1]?.reasonCode, 'waf_or_challenge_interfered');

  const budgetRuntime = new ActiveInvestigationRuntimeService();
  const budgetStarted = budgetRuntime.startInvestigation({
    contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
    kind: 'start_active_investigation_request',
    investigationId: 'inv_c1_budget_1',
    lineage: {
      assessmentId: 'asmt_c1_direct_001',
      scanId: 'scan_c1_direct_001',
      authorizationGrantId: 'grant_c1_direct_001',
      authorizationDecisionId: 'dec_c1_direct_001',
      actorId: 'usr_secops_api',
    },
    verifiedAuthorizationDecision: decision,
    budget: {
      maxRequests: 1,
      maxDurationMs: 600_000,
      maxConcurrentSteps: 1,
    },
    openHypothesisRefs: [],
    startedAt: nowIso,
  });
  assert.equal(budgetStarted.status, 'started');
  const budgetCalls: string[] = [];
  const budgetLoop = await budgetRuntime.runReadOnlyLoop({
    investigationId: 'inv_c1_budget_1',
    registry: new AttackCapabilityRegistry([
      {
        capability: 'auth_boundary_differential',
        async execute() {
          budgetCalls.push('auth_boundary_differential');
          return { outcome: 'observed', reasonCode: 'read_observed', safeMessage: 'ok' };
        },
      },
      {
        capability: 'supabase_rls_read_confirm',
        async execute() {
          budgetCalls.push('supabase_rls_read_confirm');
          return { outcome: 'observed', reasonCode: 'read_observed', safeMessage: 'ok' };
        },
      },
    ]),
    steps: [
      directStep(decision, 'auth_boundary_differential', myaccount),
      directStep(decision, 'supabase_rls_read_confirm', `https://${host}/rest/v1/widgets`),
    ],
    nowIso,
    allowAssessmentAuthForCapabilities: READ_LOOP_CAPABILITIES,
  });
  assert.equal(budgetLoop.status, 'stopped');
  assert.equal(budgetLoop.reasonCode, 'budget_exceeded');
  assert.deepEqual(budgetCalls, ['auth_boundary_differential']);

  const probeRuntime = new LoopProbeRuntime();
  const plans = new InMemoryAttackPlanRepository();
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const service = new OrchestratedAssessmentApplicationService({
    repository,
    attackPlanRepository: plans,
    activeInvestigationRuntime: probeRuntime,
    dnsResolver: async () => ['93.184.216.34'],
    httpTransport: async (): Promise<HttpProbeResponse> => challengeResponse(),
  });
  const startedAssessment = await service.startAssessment({
    targetDomain: host,
    actorId: 'usr_secops_api',
    seedUrls: [
      myaccount,
      otherPath,
      `https://${host}/a/c`,
      `https://${host}/orders`,
    ],
    sessionIdentities: {
      identityA: {
        identityId: 'id_session_a',
        injectHeaders: { authorization: `Bearer ${TOKEN}` },
        injectCookies: { cf_clearance: 'pasted-clearance' },
      },
    },
    config: { skipStages: [...SKIP_STAGES] },
  });
  const record = await service.awaitAssessment(startedAssessment.assessmentId);
  assert.ok(record);
  assert.equal(record.status, 'completed');
  assert.equal(probeRuntime.loopRequests.length, 0);
  assert.ok(record.readInvestigationLoop);
  const saved = await plans.listByAssessmentId(startedAssessment.assessmentId);
  assert.equal(saved.some((plan) => (plan.targetUrl ?? '').startsWith('tls:')), false);
  assert.equal(saved.some((plan) => (plan.targetUrl ?? '').startsWith('dns:')), false);
  assert.equal(JSON.stringify(record.readInvestigationLoop).includes('tls:'), false);
  assert.equal(JSON.stringify(record.readInvestigationLoop).includes('dns:'), false);
  for (const step of record.readInvestigationLoop.executedSteps) {
    assert.equal(step.planId.includes('tls:'), false);
  }
}

function assertNonHttpFactsEmitNoPlan(): void {
  const lineage = {
    assessmentId: 'asmt_c1_scheme_001',
    scanId: 'scan_c1_scheme_001',
    authorizationGrantId: 'grant_c1_scheme_001',
    authorizationDecisionId: 'dec_c1_scheme_001',
    actorId: 'usr_secops_api',
  };
  const observedAt = '2026-09-30T12:00:00.000Z';
  const tlsFact = tryBuildObservedFact({
    factKind: 'observed_related_host',
    value: 'edge.cdn.example.com',
    observationText: 'edge.cdn.example.com',
    sourceUrl: 'tls://waf.example.com',
    observationKind: 'tls_certificate',
    lineage,
    observedAt,
    sourceLabel: 'tls_san',
  });
  assert.ok(tlsFact);
  const tlsPlan = proposeAuthBoundaryResourceRead({
    prior: {
      planId: 'plan_c1_parent',
      producedFactIds: [tlsFact.factId],
      capabilityGained: 'none',
    },
    fact: tlsFact,
    identities: [{ identityId: 'id_session_a' }],
    lineage,
    createdAt: observedAt,
  });
  assert.equal(tlsPlan.status, 'not_emitted');
  const dnsFact = tryBuildObservedFact({
    factKind: 'observed_related_host',
    value: 'edge.cdn.example.com',
    observationText: 'edge.cdn.example.com',
    sourceUrl: 'dns://waf.example.com',
    observationKind: 'dns_json',
    lineage,
    observedAt,
    sourceLabel: 'dnsx',
  });
  assert.ok(dnsFact);
  const dnsPlan = proposeAuthBoundaryResourceRead({
    prior: {
      planId: 'plan_c1_parent',
      producedFactIds: [dnsFact.factId],
      capabilityGained: 'none',
    },
    fact: dnsFact,
    identities: [{ identityId: 'id_session_a' }],
    lineage,
    createdAt: observedAt,
  });
  assert.equal(dnsPlan.status, 'not_emitted');
  const objectFact = tryBuildObservedFact({
    factKind: 'observed_object_id',
    value: 'ord_1001',
    observationText: 'dns://waf.example.com ord_1001',
    sourceUrl: 'dns://waf.example.com',
    observationKind: 'url',
    lineage,
    observedAt,
    sourceLabel: 'byot_network_harvest',
  });
  assert.ok(objectFact);
  const child = proposeSessionBDifferential({
    prior: {
      planId: 'plan_c1_parent',
      producedFactIds: [objectFact.factId],
      capabilityGained: 'none',
    },
    fact: objectFact,
    identities: [{ identityId: 'id_session_a' }, { identityId: 'id_session_b' }],
    lineage,
    createdAt: observedAt,
  });
  assert.equal(child.status, 'not_emitted');
}

async function assertObservedSupabaseApikey(): Promise<void> {
  const host = 'proj.supabase.co';
  const tableUrl = `https://${host}/rest/v1/widgets`;
  const serviceRole = jwtWithRole('service_role');

  async function run(body: string): Promise<{
    readonly reasons: readonly string[];
    readonly loopApikeys: readonly string[];
    readonly loopJson: string;
    readonly factsJson: string;
    readonly report: string;
  }> {
    const runtime = new LoopProbeRuntime();
    const loopApikeys: string[] = [];
    const service = new OrchestratedAssessmentApplicationService({
      repository: new InMemoryOrchestratedAssessmentRepository(),
      attackPlanRepository: new InMemoryAttackPlanRepository(),
      activeInvestigationRuntime: runtime,
      dnsResolver: async () => ['93.184.216.34'],
      httpTransport: async (request: HttpProbeRequest): Promise<HttpProbeResponse> => {
        const pathname = new URL(request.url).pathname;
        if (pathname.includes('/rest/v1/')) {
          const apikey = request.headers['apikey'] ?? request.headers['Apikey'] ?? '';
          if (apikey.length > 0) loopApikeys.push(apikey);
        }
        if (pathname.includes('/rest/v1/')) {
          return {
            statusCode: 200,
            headers: { 'content-type': 'application/json' },
            bodyText: '[]',
            responseTimeMs: 1,
          };
        }
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/javascript' },
          bodyText: body,
          responseTimeMs: 1,
        };
      },
    });
    const started = await service.startAssessment({
      targetDomain: host,
      actorId: 'usr_secops_api',
      seedUrls: [tableUrl],
      sessionIdentities: {
        identityA: {
          identityId: 'id_session_a',
          injectHeaders: { authorization: `Bearer ${TOKEN}` },
        },
      },
      config: {
        skipStages: SKIP_STAGES.filter((stage) => stage !== 'stage_3_web_tls'),
      },
    });
    const record = await service.awaitAssessment(started.assessmentId);
    assert.ok(record);
    assert.equal(record.status, 'completed');
    assert.equal(runtime.loopRequests.length, 0);
    const reasons = (record.readInvestigationLoop?.executedSteps ?? [])
      .filter((step) => step.capability === 'supabase_rls_read_confirm')
      .map((step) => step.reasonCode);
    const loopJson = JSON.stringify(record.readInvestigationLoop ?? {});
    const factsJson = JSON.stringify(record.observedFacts ?? []);
    const report = buildPhase1ReadLoopSection(record.phase1ReadLoop);
    return { reasons, loopApikeys, loopJson, factsJson, report };
  }

  const observed = await run(`window.key="${PUBLISHABLE_KEY}"`);
  assert.ok(observed.reasons.length > 0);
  assert.equal(observed.reasons.includes('supabase_anon_key_missing'), false);
  assert.ok(observed.loopApikeys.includes(PUBLISHABLE_KEY));
  assert.equal(observed.loopJson.includes(PUBLISHABLE_KEY), false);
  assert.equal(observed.factsJson.includes(PUBLISHABLE_KEY), false);
  assert.equal(observed.report.includes(PUBLISHABLE_KEY), false);

  const missing = await run('window.key="none"');
  assert.ok(missing.reasons.includes('supabase_anon_key_missing'));
  assert.equal(missing.loopApikeys.length, 0);

  const serviceOnly = await run(serviceRole);
  assert.ok(serviceOnly.reasons.includes('supabase_anon_key_missing'));
  assert.equal(serviceOnly.loopApikeys.length, 0);
  assert.equal(serviceOnly.loopJson.includes(serviceRole), false);
  assert.equal(serviceOnly.factsJson.includes(serviceRole), false);
  assert.equal(serviceOnly.report.includes(serviceRole), false);
}

async function main(): Promise<void> {
  process.env.FIXGUARD_V2_HERMETIC_RECON = '1';

  let graphqlGets = 0;
  const runtime = new RecordingInvestigationRuntime();
  const plans = new InMemoryAttackPlanRepository();
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const service = new OrchestratedAssessmentApplicationService({
    repository,
    attackPlanRepository: plans,
    activeInvestigationRuntime: runtime,
    dnsResolver: async () => ['93.184.216.34'],
    httpTransport: async (request: HttpProbeRequest): Promise<HttpProbeResponse> => {
      const pathname = new URL(request.url).pathname;
      if (pathname.includes('/graphql')) graphqlGets += 1;
      return hermeticTransport()(request);
    },
  });

  const started = await service.startAssessment({
    targetDomain: 'app.example.com',
    actorId: 'usr_secops_api',
    seedUrls: [ENDPOINT],
    sessionIdentities: {
      identityA: {
        identityId: 'id_session_a',
        injectHeaders: { authorization: `Bearer ${TOKEN}` },
      },
    },
    config: {
      skipStages: [
        'stage_1_domain_zone',
        'stage_2_port_service',
        'stage_3_web_tls',
        'stage_4_crawling_parameters',
        'stage_deep_recon',
        'stage_5_secret_inspection',
      ],
    },
  });

  const record = await service.awaitAssessment(started.assessmentId);
  assert.ok(record);
  if (record.status !== 'completed') {
    throw new Error(`assessment status ${record.status}: ${record.error ?? ''}`);
  }

  const facts = record.observedFacts ?? [];
  assert.ok(facts.some((fact) => fact.factKind === 'anon_session_get_delta'));
  assert.equal(
    facts.some((fact) => fact.factKind === 'observed_public_advisory'),
    false
  );

  const saved = await plans.listByAssessmentId(started.assessmentId);
  const surfaceIds = new Set(
    saved.filter((plan) => plan.planOrigin === 'observed_surface').map((plan) => plan.planId)
  );
  assert.ok(surfaceIds.size > 0);
  const child = saved.find(
    (plan) =>
      plan.capability === 'auth_boundary_differential' &&
      plan.executable === false &&
      (plan.dependsOn ?? []).some((planId) => surfaceIds.has(planId))
  );
  assert.ok(child);

  assert.equal(runtime.loopRequests.length, 0);
  assert.ok(record.readInvestigationLoop);
  const executed = record.readInvestigationLoop.executedSteps;
  assert.ok(executed.length > 0);
  assert.ok(executed.some((step) => step.capability === 'auth_boundary_differential'));
  assert.ok(executed.some((step) => step.planId === child.planId));
  for (const capability of [
    'idor_read_differential',
    'next_server_action_diff',
    'supabase_rls_write_probe',
    'supabase_authz_write_matrix',
    'credential_reuse',
  ] as const) {
    assert.equal(executed.some((step) => step.capability === capability), false);
  }
  for (const step of executed) {
    assert.equal(
      step.blastRadiusClass === 'read_public' ||
        step.blastRadiusClass === 'read_authenticated' ||
        step.blastRadiusClass === 'read_escalated',
      true
    );
  }
  for (const plan of saved) {
    assert.equal(plan.executable, false);
    assert.notEqual(plan.status, 'authorized');
  }
  assert.equal(facts.some((fact) => fact.factKind === 'schema_relation'), false);
  assert.equal(graphqlGets, 0);
  assert.equal(JSON.stringify(record).includes(TOKEN), false);
  assert.equal(JSON.stringify(record.readInvestigationLoop).includes(TOKEN), false);

  const status = await service.getStatus(started.assessmentId);
  const summary = await service.getSummary(started.assessmentId);
  const assertChainVisible = (
    view: OrchestratedAssessmentStatusDto | OrchestratedAssessmentSummaryDto
  ): void => {
    const listed = view.plans.find((plan) => plan.planId === child.planId);
    assert.ok(listed);
    assert.equal(listed.capability, 'auth_boundary_differential');
    assert.equal(listed.executable, false);
    assert.ok(listed.dependsOn.some((planId: string) => surfaceIds.has(planId)));
    assert.ok(listed.steps.length > 0);
    assert.equal(view.investigationId, `inv_${started.assessmentId}`);
    assert.equal(view.phase1ReadLoop, undefined);
  };
  assertChainVisible(status);
  assertChainVisible(summary);

  const cancelRuntime = new CancellingBeforeLoopRuntime();
  const cancelNow = new Date().toISOString();
  const cancelDecision = directDecision('app.example.com');
  const cancelStarted = cancelRuntime.startInvestigation({
    contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
    kind: 'start_active_investigation_request',
    investigationId: 'inv_c1_cancel_direct',
    lineage: {
      assessmentId: 'asmt_c1_direct_001',
      scanId: 'scan_c1_direct_001',
      authorizationGrantId: 'grant_c1_direct_001',
      authorizationDecisionId: 'dec_c1_direct_001',
      actorId: 'usr_secops_api',
    },
    verifiedAuthorizationDecision: cancelDecision,
    budget: {
      maxRequests: 10,
      maxDurationMs: 600_000,
      maxConcurrentSteps: 1,
    },
    openHypothesisRefs: [],
    startedAt: cancelNow,
  });
  assert.equal(cancelStarted.status, 'started');
  const cancelLoop = await cancelRuntime.runReadOnlyLoop({
    investigationId: 'inv_c1_cancel_direct',
    registry: new AttackCapabilityRegistry([
      {
        capability: 'auth_boundary_differential',
        async execute() {
          throw new Error('cancelled read loop executed a capability');
        },
      },
    ]),
    steps: [directStep(cancelDecision, 'auth_boundary_differential', ENDPOINT)],
    nowIso: cancelNow,
    allowAssessmentAuthForCapabilities: READ_LOOP_CAPABILITIES,
  });
  assert.equal(cancelLoop.status, 'stopped');
  assert.deepEqual(cancelLoop.executedCapabilities, []);

  await assertWafDoesNotBurnTheReadLoop();
  assertNonHttpFactsEmitNoPlan();
  await assertObservedSupabaseApikey();

  console.log('[milestone_c1_phase1_followup_smoke] ALL PASSED');
}

main().catch((err) => {
  console.error('[milestone_c1_phase1_followup_smoke] FAILED', err);
  process.exit(1);
});
