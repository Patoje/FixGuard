/**
 * Phase 4 — read-investigation loop.
 * Hermetic transport only. No public network. No operator POST /execute.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import process from 'node:process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import { ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION } from '../application/OrchestratedAssessmentContracts.js';
import type { OrchestratedAssessmentRecord } from '../application/OrchestratedAssessmentContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackPlan,
  type AttackPlanGeneratorInput,
  type AttackPlanGeneratorResult,
} from '../attack-planning/AttackPlanContracts.js';
import { AttackPlanGeneratorService } from '../attack-planning/AttackPlanGeneratorService.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import type { Finding } from '../core/Evidence.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { runReadInvestigationLoop } from '../investigation/ReadInvestigationLoop.js';
import {
  parseReadInvestigationLoopRecord,
  READ_INVESTIGATION_DEFAULT_STEP_BUDGET,
  READ_INVESTIGATION_DEFAULT_TIME_BUDGET_MS,
} from '../investigation/ReadInvestigationLoopContracts.js';
import { PROBE_INVENTORY_CONTRACT_VERSION } from '../investigation/ProbeInventoryContracts.js';
import type { ProbeInventory } from '../investigation/ProbeInventoryContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

const HOST = 'app.example.com';
const ACTOR = 'act_ril_op';
const SCAN = 'scan_ril_main';
const GRANT = 'grant_ril_main';
const DECISION = 'dec_ril_main';
const ASSESSMENT = 'asmt_ril_main';
const IN_SCOPE = `https://${HOST}/health`;
const NEW_PATH = `https://${HOST}/api/orders/ord_9`;
const OUTSIDE = 'https://outsider.example/hidden';
const METADATA = 'http://169.254.169.254/latest/meta-data';

function fail(error: unknown): never {
  const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function scopeGrant(scanId = SCAN): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: GRANT,
    scanId,
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: { targetKind: 'domain', domain: HOST },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized read investigation loop smoke',
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
      allowedOrigins: [`https://${HOST}`],
      allowedHosts: [HOST],
      allowedDomains: [HOST],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
      deniedPathPatterns: [],
    },
    constraints: {
      allowLoginRequiredAreas: false,
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

function lineage(): AuthorizedActiveReconRequestLineage {
  return {
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    authorizationGrantId: GRANT,
    authorizationDecisionId: DECISION,
    actorId: ACTOR,
  };
}

function brandedDecision(): VerifiedAuthorizationDecision {
  const grant = scopeGrant();
  const nowIso = new Date().toISOString();
  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: ASSESSMENT,
      scanId: grant.scanId,
      authorizationDecisionId: DECISION,
      authorizedActor: { actorId: ACTOR, actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant: grant,
    },
    nowIso
  );
  if (authRes.status !== 'established') {
    throw new Error(`authorization was not established: ${authRes.reasonCode}`);
  }
  return authRes.decision;
}

function inventory(): ProbeInventory {
  return {
    contractVersion: PROBE_INVENTORY_CONTRACT_VERSION,
    kind: 'probe_inventory',
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    authorizationGrantId: GRANT,
    authorizationDecisionId: DECISION,
    actorId: ACTOR,
    entries: [
      {
        origin: `https://${HOST}`,
        path: '/health',
        method: 'GET',
        parameters: [],
        sources: ['web_inspection'],
      },
    ],
  };
}

function plan(args: {
  readonly planId: string;
  readonly targetUrl: string;
  readonly createdAt: string;
  readonly capability?: AttackPlan['capability'];
  readonly capabilityGained?: AttackPlan['capabilityGained'];
  readonly authorizationBlastRadiusClass?: AttackPlan['authorizationBlastRadiusClass'];
}): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: args.planId,
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    capability: args.capability ?? 'security_header_probe',
    title: 'Hermetic read plan',
    reasoning: 'Read observation for the investigation loop smoke',
    status: 'ready_for_authorization',
    blastRadius: 'single_endpoint',
    capabilityGained: args.capabilityGained ?? 'none',
    ...(args.authorizationBlastRadiusClass
      ? { authorizationBlastRadiusClass: args.authorizationBlastRadiusClass }
      : {}),
    sourceFindingIds: [],
    sourceFindingTypes: [],
    prerequisites: [],
    steps: [
      {
        stepId: `step_${args.planId}`,
        ordinal: 1,
        title: 'GET the target URL',
        description: 'Observation read of the plan URL',
        status: 'ready',
        requiredPermissions: ['active_http_get'],
      },
    ],
    targetUrl: args.targetUrl,
    lineage: lineage(),
    createdAt: args.createdAt,
    executable: false,
  };
}

function discoveryFinding(url: string): Finding {
  return {
    id: 'fnd_ril_surface',
    type: 'DISCOVERY',
    severity: 'info',
    title: 'Observed URL',
    description: 'URL carried on the execution result',
    target: HOST,
    evidence: 'hermetic',
    confidence: 1,
    verificationState: 'observed_anomaly',
    metadata: {
      kind: 'discovery_finding_metadata',
      endpointUrl: url,
    },
  };
}

function countingTransport(): { transport: (request: HttpProbeRequest) => Promise<HttpProbeResponse>; calls: string[] } {
  const calls: string[] = [];
  const transport = async (request: HttpProbeRequest): Promise<HttpProbeResponse> => {
    calls.push(request.url);
    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      bodyText: '{"ok":true}',
      responseTimeMs: 1,
    };
  };
  return { transport, calls };
}

class CountingAuthorization extends AttackAuthorizationService {
  readonly planIds: string[] = [];

  public override async authorizeReadObservationFromVerifiedDecision(
    request: unknown
  ): Promise<Awaited<ReturnType<AttackAuthorizationService['authorizeReadObservationFromVerifiedDecision']>>> {
    if (request && typeof request === 'object' && !Array.isArray(request)) {
      const planId = Reflect.get(request, 'planId');
      if (typeof planId === 'string') this.planIds.push(planId);
    }
    return super.authorizeReadObservationFromVerifiedDecision(request);
  }
}

async function seedAssessment(
  repository: InMemoryOrchestratedAssessmentRepository
): Promise<void> {
  const record: OrchestratedAssessmentRecord = {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    targetDomain: HOST,
    status: 'running',
    lineage: lineage(),
    stages: [],
    timing: { startedAt: '2026-09-30T12:00:00.000Z' },
    errorCount: 0,
    warningCount: 0,
    findings: [],
    recommendations: [],
  };
  await repository.save(record);
}

interface LoopHarness {
  readonly plans: InMemoryAttackPlanRepository;
  readonly auth: CountingAuthorization;
  readonly service: OrchestratedAssessmentApplicationService;
  readonly calls: string[];
}

async function harness(): Promise<LoopHarness> {
  const plans = new InMemoryAttackPlanRepository();
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const counted = countingTransport();
  const service = new OrchestratedAssessmentApplicationService({
    repository,
    attackPlanRepository: plans,
    dnsResolver: async () => ['93.184.216.34'],
    httpTransport: counted.transport,
  });
  await seedAssessment(repository);
  return {
    plans,
    auth: new CountingAuthorization(plans),
    service,
    calls: counted.calls,
  };
}

async function main(): Promise<void> {
  const pipelineSource = readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      '../application/OrchestratedAssessmentApplicationService.ts'
    ),
    'utf8'
  );
  assert.equal(pipelineSource.includes('runReadOnlyLoop'), false);
  assert.equal(pipelineSource.includes('authorizeReadObservationFromVerifiedDecision'), false);
  assert.equal(pipelineSource.includes('runReadInvestigationLoop'), true);
  assert.equal(READ_INVESTIGATION_DEFAULT_STEP_BUDGET > 0, true);
  assert.equal(READ_INVESTIGATION_DEFAULT_STEP_BUDGET <= 8, true);
  assert.equal(READ_INVESTIGATION_DEFAULT_TIME_BUDGET_MS > 0, true);
  assert.equal(READ_INVESTIGATION_DEFAULT_TIME_BUDGET_MS <= 30_000, true);

  const decision = brandedDecision();

  // In-scope read plan runs in-process. Outcome is stored. Nothing remains.
  {
    const box = await harness();
    const counted = countingTransport();
    await box.plans.savePlans([
      plan({ planId: 'plan_ril_one', targetUrl: IN_SCOPE, createdAt: '2026-09-30T12:00:00.000Z' }),
    ]);
    const execution = new AttackExecutionService({
      planRepository: box.plans,
      capabilityRegistry: registryFor(counted.transport),
    });
    const result = await runReadInvestigationLoop({
      assessmentId: ASSESSMENT,
      lineage: lineage(),
      verifiedAuthorizationDecision: decision,
      scopeGrant: scopeGrant(),
      coordinator: new TargetExecutionCoordinator({ requestsPerSecond: 5, maxConcurrency: 2 }),
      dnsResolver: async () => ['93.184.216.34'],
      transport: counted.transport,
      circuitHost: HOST,
      findings: [],
      probeInventory: inventory(),
      planRepository: box.plans,
      planGenerator: new AttackPlanGeneratorService(),
      authorizationService: box.auth,
      executionService: execution,
      recordOutcome: (outcome) => box.service.recordAttackExecutionOutcome(outcome),
    });
    assert.equal(result.record.stopReason, 'no_read_plans_remaining');
    assert.equal(result.record.stepsExecuted, 1);
    assert.deepEqual(counted.calls, [IN_SCOPE]);
    assert.equal(box.auth.planIds.length, 1);
    const stored = await box.plans.getPlan('plan_ril_one');
    assert.equal(stored?.executable, false);
    const refresh = await box.service.getAttackModeRefresh(ASSESSMENT);
    assert.ok(refresh.attackChains.length >= 1);
    assert.ok(parseReadInvestigationLoopRecord(result.record));
    const extra: Record<string, unknown> = { ...result.record, unexpected: true };
    assert.equal(parseReadInvestigationLoopRecord(extra), null);
  }

  // Step cap 1 runs one plan and stops while another read plan is queued.
  {
    const box = await harness();
    const counted = countingTransport();
    await box.plans.savePlans([
      plan({ planId: 'plan_ril_first', targetUrl: IN_SCOPE, createdAt: '2026-09-30T12:00:00.000Z' }),
      plan({
        planId: 'plan_ril_second',
        targetUrl: `https://${HOST}/second`,
        createdAt: '2026-09-30T12:01:00.000Z',
      }),
    ]);
    const result = await runWithTransport(box, decision, counted.transport, { stepBudget: 1 });
    assert.equal(result.record.stopReason, 'step_budget_exhausted');
    assert.equal(result.record.stepsExecuted, 1);
    assert.deepEqual(counted.calls, [IN_SCOPE]);
    assert.deepEqual(box.auth.planIds, ['plan_ril_first']);
    assert.equal(box.auth.getRuntimeToken('plan_ril_second', ASSESSMENT), null);
  }

  // A new in-scope path on the result produces a second read step in the same run.
  {
    const box = await harness();
    const counted = countingTransport();
    await box.plans.savePlans([
      plan({ planId: 'plan_ril_hop', targetUrl: IN_SCOPE, createdAt: '2026-09-30T12:00:00.000Z' }),
    ]);
    const result = await runWithTransport(box, decision, counted.transport, {
      stepBudget: 4,
      findings: [discoveryFinding(NEW_PATH)],
      identities: true,
    });
    assert.ok(result.record.stepsExecuted >= 2);
    assert.equal(result.record.stopReason, 'no_read_plans_remaining');
    assert.ok(result.record.executedSteps.some((step) => step.planId === 'plan_ril_hop'));
    assert.ok(
      result.record.executedSteps.some((step) => step.capability === 'auth_boundary_differential')
    );
    assert.ok(result.probeInventory.entries.some((entry) => entry.path === '/api/orders/ord_9'));
    assert.ok(counted.calls.includes(IN_SCOPE));
    assert.ok(counted.calls.some((url) => url.includes('/api/orders/ord_9')));
    const hop = await box.plans.getPlan('plan_ril_hop');
    assert.equal(hop?.executable, false);
  }

  // Host outside scope, and an internal metadata address, produce zero transport calls.
  {
    const box = await harness();
    const counted = countingTransport();
    await box.plans.savePlans([
      plan({
        planId: 'plan_ril_outside',
        targetUrl: OUTSIDE,
        createdAt: '2026-09-30T12:00:00.000Z',
      }),
      plan({
        planId: 'plan_ril_meta',
        targetUrl: METADATA,
        createdAt: '2026-09-30T12:01:00.000Z',
      }),
    ]);
    const result = await runWithTransport(box, decision, counted.transport, {});
    assert.deepEqual(counted.calls, []);
    assert.equal(result.record.stepsExecuted, 2);
    assert.equal(result.record.stopReason, 'no_read_plans_remaining');
  }

  // A completed step that reveals an outside host records it and does not request it.
  {
    const box = await harness();
    const counted = countingTransport();
    await box.plans.savePlans([
      plan({ planId: 'plan_ril_seen', targetUrl: IN_SCOPE, createdAt: '2026-09-30T12:00:00.000Z' }),
    ]);
    const result = await runWithTransport(box, decision, counted.transport, {
      findings: [discoveryFinding(OUTSIDE)],
    });
    assert.ok(result.record.seenOutOfScopeUrls.some((url) => url.includes('outsider.example')));
    assert.equal(counted.calls.some((url) => url.includes('outsider.example')), false);
    assert.equal(counted.calls.some((url) => url.includes('169.254.169.254')), false);
  }

  // persistence and destructive plans are not executed and do not get a token.
  {
    const box = await harness();
    const counted = countingTransport();
    await box.plans.savePlans([
      plan({
        planId: 'plan_ril_keep',
        targetUrl: IN_SCOPE,
        createdAt: '2026-09-30T12:00:00.000Z',
      }),
      plan({
        planId: 'plan_ril_persist',
        targetUrl: `https://${HOST}/persist-path`,
        createdAt: '2026-09-30T12:02:00.000Z',
        authorizationBlastRadiusClass: 'persistence',
      }),
      plan({
        planId: 'plan_ril_destroy',
        targetUrl: `https://${HOST}/destroy-path`,
        createdAt: '2026-09-30T12:03:00.000Z',
        capability: 'information_disclosure_probe',
        authorizationBlastRadiusClass: 'destructive',
      }),
    ]);
    const result = await runWithTransport(box, decision, counted.transport, {});
    assert.deepEqual(box.auth.planIds, ['plan_ril_keep']);
    assert.equal(box.auth.getRuntimeToken('plan_ril_persist', ASSESSMENT), null);
    assert.equal(box.auth.getRuntimeToken('plan_ril_destroy', ASSESSMENT), null);
    assert.ok(result.record.skippedNonReadPlanIds.includes('plan_ril_persist'));
    assert.ok(result.record.skippedNonReadPlanIds.includes('plan_ril_destroy'));
    assert.equal(counted.calls.some((url) => url.includes('persist-path')), false);
    assert.equal(counted.calls.some((url) => url.includes('destroy-path')), false);
    assert.deepEqual(counted.calls, [IN_SCOPE]);
  }

  // Missing verified decision: zero executions.
  {
    const box = await harness();
    const counted = countingTransport();
    await box.plans.savePlans([
      plan({ planId: 'plan_ril_nodec', targetUrl: IN_SCOPE, createdAt: '2026-09-30T12:00:00.000Z' }),
    ]);
    const missing = await runWithTransport(box, undefined, counted.transport, {});
    assert.equal(missing.record.stopReason, 'verified_decision_missing');
    assert.equal(missing.record.stepsExecuted, 0);
    assert.deepEqual(counted.calls, []);
    assert.deepEqual(box.auth.planIds, []);
    const lookalike = await runWithTransport(
      box,
      { ...decision },
      counted.transport,
      {}
    );
    assert.equal(lookalike.record.stepsExecuted, 0);
    assert.deepEqual(box.auth.planIds, []);
  }

  // Time budget and an open circuit stop before transport.
  {
    const box = await harness();
    const counted = countingTransport();
    await box.plans.savePlans([
      plan({ planId: 'plan_ril_time', targetUrl: IN_SCOPE, createdAt: '2026-09-30T12:00:00.000Z' }),
    ]);
    const timed = await runWithTransport(box, decision, counted.transport, { timeBudgetMs: 0 });
    assert.equal(timed.record.stopReason, 'time_budget_exhausted');
    assert.equal(timed.record.stepsExecuted, 0);
    assert.deepEqual(counted.calls, []);

    const coordinator = new TargetExecutionCoordinator({ requestsPerSecond: 5, maxConcurrency: 2 });
    coordinator.recordTargetResponse(HOST, 500);
    coordinator.recordTargetResponse(HOST, 500);
    coordinator.recordTargetResponse(HOST, 500);
    coordinator.recordTargetResponse(HOST, 500);
    coordinator.recordTargetResponse(HOST, 500);
    assert.equal(coordinator.isCircuitOpen(HOST), true);
    const opened = await runWithTransport(box, decision, counted.transport, {
      coordinator,
      timeBudgetMs: READ_INVESTIGATION_DEFAULT_TIME_BUDGET_MS,
    });
    assert.equal(opened.record.stopReason, 'circuit_open');
    assert.equal(opened.record.stepsExecuted, 0);
    assert.deepEqual(counted.calls, []);
  }

  await pipelineRunsMarkerWithoutOperatorPost();
}

function registryFor(transport: (request: HttpProbeRequest) => Promise<HttpProbeResponse>): AttackCapabilityRegistry {
  const ports = AttackCapabilityRegistry.createDefault();
  ports.register({
    capability: 'security_header_probe',
    async execute(ctx) {
      const hop = ctx.transport ?? transport;
      await hop({
        url: ctx.targetUrl,
        method: 'GET',
        headers: { accept: 'application/json' },
      });
      return {
        outcome: 'observed',
        reasonCode: 'hermetic_read_observed',
        safeMessage: 'Hermetic in-scope read completed',
      };
    },
  });
  return ports;
}

async function runWithTransport(
  box: LoopHarness,
  decision: VerifiedAuthorizationDecision | undefined,
  transport: (request: HttpProbeRequest) => Promise<HttpProbeResponse>,
  args: {
    readonly stepBudget?: number;
    readonly timeBudgetMs?: number;
    readonly findings?: readonly Finding[];
    readonly identities?: boolean;
    readonly coordinator?: TargetExecutionCoordinator;
  }
) {
  const execution = new AttackExecutionService({
    planRepository: box.plans,
    capabilityRegistry: registryFor(transport),
  });
  return runReadInvestigationLoop({
    assessmentId: ASSESSMENT,
    lineage: lineage(),
    verifiedAuthorizationDecision: decision,
    scopeGrant: scopeGrant(),
    coordinator: args.coordinator ?? new TargetExecutionCoordinator({ requestsPerSecond: 5, maxConcurrency: 2 }),
    dnsResolver: async () => ['93.184.216.34'],
    transport,
    circuitHost: HOST,
    findings: args.findings ?? [],
    probeInventory: inventory(),
    planRepository: box.plans,
    planGenerator: new AttackPlanGeneratorService(),
    authorizationService: box.auth,
    executionService: execution,
    recordOutcome: (outcome) => box.service.recordAttackExecutionOutcome(outcome),
    ...(args.identities
      ? {
          identities: [{ identityId: 'id_session_a', hasJwt: false }],
          primaryIdentity: { identityId: 'id_session_a' },
        }
      : {}),
    ...(args.stepBudget !== undefined ? { stepBudget: args.stepBudget } : {}),
    ...(args.timeBudgetMs !== undefined ? { timeBudgetMs: args.timeBudgetMs } : {}),
  });
}

class MarkerPlanGenerator extends AttackPlanGeneratorService {
  public override generate(input: AttackPlanGeneratorInput): AttackPlanGeneratorResult {
    const marker = `https://${HOST}/api/orders/rilmarker`;
    const created: AttackPlan = {
      contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
      kind: 'attack_plan',
      planId: 'plan_ril_marker',
      assessmentId: input.assessmentId,
      scanId: input.scanId,
      capability: 'auth_boundary_differential',
      title: 'Hermetic marker read',
      reasoning: 'Pipeline read plan for the investigation loop',
      status: 'ready_for_authorization',
      blastRadius: 'single_endpoint',
      capabilityGained: 'read_authenticated',
      sourceFindingIds: [],
      sourceFindingTypes: [],
      prerequisites: [],
      steps: [
        {
          stepId: 'step_ril_marker',
          ordinal: 1,
          title: 'GET the marker URL',
          description: 'Observation read',
          status: 'ready',
          requiredPermissions: ['active_http_get'],
        },
      ],
      targetUrl: marker,
      lineage: { ...input.lineage },
      createdAt: '2026-09-30T12:00:00.000Z',
      executable: false,
    };
    return {
      contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
      kind: 'attack_plan_generator_result',
      assessmentId: input.assessmentId,
      scanId: input.scanId,
      plans: [created],
      generatedAt: '2026-09-30T12:00:00.000Z',
      lineage: input.lineage,
    };
  }
}

async function pipelineRunsMarkerWithoutOperatorPost(): Promise<void> {
  process.env.FIXGUARD_V2_HERMETIC_RECON = '1';
  const originalFetch = globalThis.fetch;
  const publicCalls: string[] = [];
  globalThis.fetch = async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    publicCalls.push(url);
    return new Response('', { status: 404 });
  };
  const calls: string[] = [];
  try {
    const plans = new InMemoryAttackPlanRepository();
    const service = new OrchestratedAssessmentApplicationService({
      repository: new InMemoryOrchestratedAssessmentRepository(),
      attackPlanRepository: plans,
      attackPlanGenerator: new MarkerPlanGenerator(),
      dnsResolver: async () => ['93.184.216.34'],
      httpTransport: async (request) => {
        calls.push(request.url);
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: '{"ok":true}',
          responseTimeMs: 1,
        };
      },
      heartbeatIntervalMs: 60_000,
    });
    const started = await service.startAssessment({
      targetDomain: HOST,
      actorId: ACTOR,
      sessionIdentities: {
        identityA: {
          identityId: 'id_session_a',
          injectHeaders: { accept: 'application/json' },
        },
      },
      config: {
        enableDeepRecon: false,
        enableSpaDiscovery: false,
        skipStages: [
          'stage_1_domain_zone',
          'stage_2_port_service',
          'stage_4_crawling_parameters',
          'stage_5_secret_inspection',
        ],
      },
    });
    const record = await service.awaitAssessment(started.assessmentId);
    assert.ok(record);
    assert.equal(record.status, 'completed');
    assert.ok(record.readInvestigationLoop);
    assert.equal(record.readInvestigationLoop.stopReason, 'no_read_plans_remaining');
    assert.ok(record.readInvestigationLoop.stepsExecuted >= 1);
    assert.ok(calls.some((url) => url.includes('/api/orders/rilmarker')));
    const stored = await plans.getPlan('plan_ril_marker');
    assert.equal(stored?.executable, false);
    assert.ok(publicCalls.every((url) => url.startsWith(`https://${HOST}/`)));
  } finally {
    globalThis.fetch = originalFetch;
  }
}

main().catch(fail);
