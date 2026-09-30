/**
 * Phase 6 — assessment transcript on the orchestrated status and summary reads.
 * Hermetic transport only. No public network.
 */
import assert from 'node:assert/strict';
import process from 'node:process';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackPlan,
} from '../attack-planning/AttackPlanContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import {
  ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
  type OrchestratedAssessmentRecord,
} from '../application/OrchestratedAssessmentContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { noteProcessRunnerReceipt } from '../core/StepInvocationCapture.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { PROBE_INVENTORY_CONTRACT_VERSION } from '../investigation/ProbeInventoryContracts.js';
import type { ProbeInventory } from '../investigation/ProbeInventoryContracts.js';
import { runReadInvestigationLoop } from '../investigation/ReadInvestigationLoop.js';
import { AttackPlanGeneratorService } from '../attack-planning/AttackPlanGeneratorService.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { validateOrchestratedAssessmentRecord } from '../storage/OrchestratedAssessmentPersistenceValidation.js';

const HOST = 'app.example.com';
const ACTOR = 'act_tx_op';
const SCAN = 'scan_tx_main';
const GRANT = 'grant_tx_main';
const DECISION = 'dec_tx_main';
const ASSESSMENT = 'asmt_tx_main';
const HEALTH = `https://${HOST}/health`;
const HTTP_URL = `https://${HOST}/api/status`;
const META = 'http://169.254.169.254/latest/meta-data';
const PERSIST = `https://${HOST}/persist-chain`;
const ADAPTER_BINARY = 'httpx';
const ADAPTER_ARGS = ['-silent', '-u', HEALTH, '-json'] as const;

function fail(error: unknown): never {
  const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function scopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: GRANT,
    scanId: SCAN,
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: { targetKind: 'domain', domain: HOST },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized transcript smoke',
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

function finding(): Finding {
  return {
    id: 'fnd_tx_surface',
    type: 'DISCOVERY',
    severity: 'info',
    title: 'Observed health URL',
    description: 'Stored finding already on the assessment',
    target: HEALTH,
    evidence: 'hermetic',
    confidence: 1,
    verificationState: 'observed_anomaly',
    metadata: {
      kind: 'discovery_finding_metadata',
      endpointUrl: HEALTH,
    },
  };
}

function plan(args: {
  readonly planId: string;
  readonly capability: AttackPlan['capability'];
  readonly targetUrl: string;
  readonly createdAt: string;
  readonly authorizationBlastRadiusClass?: AttackPlan['authorizationBlastRadiusClass'];
}): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: args.planId,
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    capability: args.capability,
    title: args.planId,
    reasoning: 'Hermetic transcript plan',
    status: 'ready_for_authorization',
    blastRadius: 'single_endpoint',
    capabilityGained: 'none',
    sourceFindingIds: [],
    sourceFindingTypes: [],
    prerequisites: [],
    steps: [
      {
        stepId: `${args.planId}_step`,
        ordinal: 1,
        title: 'Read step',
        description: 'Observation',
        status: 'ready',
        requiredPermissions: ['active_http_get'],
      },
    ],
    targetUrl: args.targetUrl,
    lineage: lineage(),
    createdAt: args.createdAt,
    executable: false,
    ...(args.authorizationBlastRadiusClass
      ? { authorizationBlastRadiusClass: args.authorizationBlastRadiusClass }
      : {}),
  };
}

async function main(): Promise<void> {
  const decision = brandedDecision();
  const plans = new InMemoryAttackPlanRepository();
  const calls: string[] = [];
  let runnerCalls = 0;
  let receivedArgs: readonly string[] | null = null;
  const runner: ProcessRunner = {
    async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
      runnerCalls += 1;
      receivedArgs = request.args;
      noteProcessRunnerReceipt(request);
      return { stdout: '', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
    },
  };
  const transport = async (request: HttpProbeRequest): Promise<HttpProbeResponse> => {
    calls.push(request.url);
    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      bodyText: '{"ok":true}',
      responseTimeMs: 1,
    };
  };
  const registry = AttackCapabilityRegistry.createDefault();
  registry.register({
    capability: 'security_header_probe',
    async execute(ctx) {
      const request: ExecutionRequest = {
        binary: ADAPTER_BINARY,
        args: [...ADAPTER_ARGS],
        timeoutMs: 500,
      };
      if (ctx.targetUrl === HEALTH) {
        await runner.execute(request);
      }
      return {
        outcome: 'observed',
        reasonCode: 'hermetic_process_observed',
        safeMessage: 'Process receipt copied from the adapter request',
      };
    },
  });
  registry.register({
    capability: 'information_disclosure_probe',
    async execute(ctx) {
      const hop = ctx.transport ?? transport;
      await hop({
        url: ctx.targetUrl,
        method: 'GET',
        headers: { accept: 'application/json' },
      });
      return {
        outcome: 'observed',
        reasonCode: 'hermetic_http_observed',
        safeMessage: 'HTTP probe after execution preflight',
      };
    },
  });

  await plans.savePlans([
    plan({
      planId: 'plan_tx_bin',
      capability: 'security_header_probe',
      targetUrl: HEALTH,
      createdAt: '2026-09-30T12:00:00.000Z',
    }),
    plan({
      planId: 'plan_tx_http',
      capability: 'information_disclosure_probe',
      targetUrl: HTTP_URL,
      createdAt: '2026-09-30T12:01:00.000Z',
    }),
    plan({
      planId: 'plan_tx_meta',
      capability: 'security_header_probe',
      targetUrl: META,
      createdAt: '2026-09-30T12:02:00.000Z',
    }),
    plan({
      planId: 'plan_tx_persist',
      capability: 'credential_reuse',
      targetUrl: PERSIST,
      createdAt: '2026-09-30T12:03:00.000Z',
      authorizationBlastRadiusClass: 'persistence',
    }),
  ]);

  const execution = new AttackExecutionService({
    planRepository: plans,
    capabilityRegistry: registry,
  });
  const loop = await runReadInvestigationLoop({
    assessmentId: ASSESSMENT,
    lineage: lineage(),
    verifiedAuthorizationDecision: decision,
    scopeGrant: scopeGrant(),
    coordinator: new TargetExecutionCoordinator({ requestsPerSecond: 5, maxConcurrency: 2 }),
    dnsResolver: async () => ['93.184.216.34'],
    transport,
    circuitHost: HOST,
    findings: [finding()],
    probeInventory: inventory(),
    planRepository: plans,
    planGenerator: new AttackPlanGeneratorService(),
    authorizationService: new AttackAuthorizationService(plans),
    executionService: execution,
    recordOutcome: async () => undefined,
    stepBudget: 4,
  });

  assert.equal(loop.record.executedSteps.some((step) => step.planId === 'plan_tx_persist'), false);
  assert.equal(calls.some((url) => url.includes('169.254.169.254')), false);
  assert.equal(runnerCalls, 1);
  assert.deepEqual(receivedArgs, [...ADAPTER_ARGS]);

  const storedFinding = finding();
  const record: OrchestratedAssessmentRecord = {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    targetDomain: HOST,
    status: 'completed',
    lineage: lineage(),
    stages: [],
    timing: { startedAt: '2026-09-30T12:00:00.000Z' },
    errorCount: 0,
    warningCount: 0,
    findings: [storedFinding],
    recommendations: [],
    probeInventory: loop.probeInventory,
    readInvestigationLoop: loop.record,
    transcript: loop.transcript,
  };
  assert.equal(validateOrchestratedAssessmentRecord(record), true);
  const { transcript: _storedTranscript, ...withoutTranscript } = record;
  assert.equal(validateOrchestratedAssessmentRecord(withoutTranscript), true);
  assert.equal(
    validateOrchestratedAssessmentRecord({
      ...record,
      transcript: { ...loop.transcript, unexpected: true },
    }),
    false
  );

  const repository = new InMemoryOrchestratedAssessmentRepository();
  await repository.save(record);
  const service = new OrchestratedAssessmentApplicationService({
    repository,
    attackPlanRepository: plans,
    dnsResolver: async () => ['93.184.216.34'],
    httpTransport: transport,
    heartbeatIntervalMs: 60_000,
  });
  const status = await service.getStatus(ASSESSMENT);
  const summary = await service.getSummary(ASSESSMENT);
  for (const body of [status, summary]) {
    const transcript = body.transcript;
    assert.ok(transcript);
    assert.ok(transcript.discoveries);
    assert.ok(transcript.discoveries.entries.length >= 1);
    assert.equal(transcript.findings.length, 1);
    assert.equal(transcript.findings[0]?.id, storedFinding.id);
    assert.ok(transcript.executedSteps.length >= 1);
    assert.ok(transcript.withheldPlans.length >= 1);
    assert.equal(typeof transcript.stopReason, 'string');
    assert.equal(transcript.stopReason.length > 0, true);
  }

  const transcript = status.transcript;
  assert.ok(transcript);
  const binaryStep = transcript.executedSteps.find(
    (step) => step.invocation.kind === 'process'
  );
  assert.ok(binaryStep);
  assert.equal(binaryStep.invocation.kind, 'process');
  if (binaryStep.invocation.kind === 'process') {
    assert.equal(binaryStep.invocation.binary, ADAPTER_BINARY);
    assert.deepEqual(binaryStep.invocation.args, [...ADAPTER_ARGS]);
    assert.deepEqual(binaryStep.invocation.args, receivedArgs);
  }
  const httpStep = transcript.executedSteps.find((step) => step.invocation.kind === 'http');
  assert.ok(httpStep);
  assert.equal(httpStep.invocation.kind, 'http');
  if (httpStep.invocation.kind === 'http') {
    assert.equal(httpStep.invocation.method, 'GET');
    assert.equal(httpStep.invocation.url, HTTP_URL);
  }
  assert.ok(
    transcript.withheldPlans.some(
      (plan) => plan.capability === 'credential_reuse' && plan.target === PERSIST
    )
  );
  assert.equal(
    transcript.executedSteps.some((step) => step.url === PERSIST),
    false
  );
  assert.equal(calls.filter((url) => url.includes('169.254.169.254')).length, 0);
}

main().catch(fail);
