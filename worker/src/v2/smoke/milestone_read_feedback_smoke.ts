/**
 * Phase 5 — read-step feedback stays inside the read-class boundary.
 * Hermetic transport only. No public network.
 */
import assert from 'node:assert/strict';
import process from 'node:process';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { AttackChainService } from '../attack-chain/AttackChainService.js';
import { InMemoryAttackChainRepository } from '../attack-chain/InMemoryAttackChainRepository.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackPlan,
  type AttackPlanGeneratorInput,
  type AttackPlanGeneratorResult,
} from '../attack-planning/AttackPlanContracts.js';
import { AttackPlanGeneratorService } from '../attack-planning/AttackPlanGeneratorService.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { runReadInvestigationLoop } from '../investigation/ReadInvestigationLoop.js';
import { PROBE_INVENTORY_CONTRACT_VERSION } from '../investigation/ProbeInventoryContracts.js';
import type { ProbeInventory } from '../investigation/ProbeInventoryContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';

const HOST = 'app.example.com';
const ACTOR = 'act_rf_op';
const SCAN = 'scan_rf_main';
const GRANT = 'grant_rf_main';
const DECISION = 'dec_rf_main';
const ASSESSMENT = 'asmt_rf_main';
const IN_SCOPE = `https://${HOST}/health`;
const REACHABLE = `https://${HOST}/api/orders/reachable`;
const OUTSIDE = 'https://outsider.example/hidden';
const METADATA = 'http://169.254.169.254/latest/meta-data';
const CORRELATION_READ = `https://${HOST}/api/orders/from-correlation`;
const PERSIST = `https://${HOST}/persist-chain`;
const DESTROY = `https://${HOST}/destroy-chain`;

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
      authorizationText: 'Authorized read feedback smoke',
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

function seedPlan(): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: 'plan_rf_seed',
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    capability: 'security_header_probe',
    title: 'Hermetic seed read',
    reasoning: 'First read step for feedback',
    status: 'ready_for_authorization',
    blastRadius: 'single_endpoint',
    capabilityGained: 'none',
    sourceFindingIds: [],
    sourceFindingTypes: [],
    prerequisites: [],
    steps: [
      {
        stepId: 'step_rf_seed',
        ordinal: 1,
        title: 'GET the seed URL',
        description: 'Observation read',
        status: 'ready',
        requiredPermissions: ['active_http_get'],
      },
    ],
    targetUrl: IN_SCOPE,
    lineage: lineage(),
    createdAt: '2026-09-30T12:00:00.000Z',
    executable: false,
  };
}

function makePlan(args: {
  readonly input: AttackPlanGeneratorInput;
  readonly planId: string;
  readonly targetUrl: string;
  readonly authorizationBlastRadiusClass?: AttackPlan['authorizationBlastRadiusClass'];
}): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: args.planId,
    assessmentId: args.input.assessmentId,
    scanId: args.input.scanId,
    capability: 'security_header_probe',
    title: 'Hermetic follow-up read',
    reasoning: 'Read plan for a newly accepted surface',
    status: 'ready_for_authorization',
    blastRadius: 'single_endpoint',
    capabilityGained: 'none',
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
        title: 'GET the follow-up URL',
        description: 'Observation read',
        status: 'ready',
        requiredPermissions: ['active_http_get'],
      },
    ],
    targetUrl: args.targetUrl,
    lineage: { ...args.input.lineage },
    createdAt: args.input.generatedAt ?? '2026-09-30T12:05:00.000Z',
    executable: false,
  };
}

class FeedbackGenerator extends AttackPlanGeneratorService {
  public override generate(input: AttackPlanGeneratorInput): AttackPlanGeneratorResult {
    const plans: AttackPlan[] = [];
    for (const hint of input.surfaceHints ?? []) {
      if (
        hint.endpointUrl.includes('outsider.example') ||
        hint.endpointUrl.includes('169.254.169.254')
      ) {
        throw new Error(`out-of-scope surface reached the planner: ${hint.endpointUrl}`);
      }
      const slug = hint.endpointUrl.replace(/[^A-Za-z0-9]/g, '').slice(-20);
      plans.push(
        makePlan({
          input,
          planId: `plan_rf_h_${slug}`,
          targetUrl: hint.endpointUrl,
        })
      );
    }
    for (const signal of input.draftSignals ?? []) {
      if (signal.detectionKind !== 'cors_idor_compound') continue;
      plans.push(
        makePlan({
          input,
          planId: 'plan_rf_corr_read',
          targetUrl: CORRELATION_READ,
        })
      );
      plans.push(
        makePlan({
          input,
          planId: 'plan_rf_persist',
          targetUrl: PERSIST,
          authorizationBlastRadiusClass: 'persistence',
        })
      );
      plans.push(
        makePlan({
          input,
          planId: 'plan_rf_destroy',
          targetUrl: DESTROY,
          authorizationBlastRadiusClass: 'destructive',
        })
      );
    }
    return {
      contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
      kind: 'attack_plan_generator_result',
      assessmentId: input.assessmentId,
      scanId: input.scanId,
      plans,
      generatedAt: input.generatedAt ?? '2026-09-30T12:05:00.000Z',
      lineage: input.lineage,
    };
  }
}

function countingTransport(): {
  transport: (request: HttpProbeRequest) => Promise<HttpProbeResponse>;
  calls: string[];
} {
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

function registryFor(
  transport: (request: HttpProbeRequest) => Promise<HttpProbeResponse>
): AttackCapabilityRegistry {
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

function corsFinding(): Finding {
  return {
    id: 'fnd_rf_cors',
    type: 'SECURITY_MISCONFIGURATION',
    severity: 'high',
    title: 'Credentialed CORS',
    description: 'Reflects an origin with credentials',
    target: `https://${HOST}/api/user`,
    evidence: 'hermetic',
    confidence: 1,
    verificationState: 'validated_vulnerability',
    metadata: {
      kind: 'credentialed_cors_metadata',
      category: 'SECURITY_MISCONFIGURATION',
      endpointUrl: `https://${HOST}/api/user`,
      httpMethod: 'GET',
      suppliedOrigin: 'https://canary.example',
      reflectedOrigin: 'https://canary.example',
      allowCredentialsHeader: true,
      acaoHeader: 'https://canary.example',
      observedAt: '2026-09-30T12:00:00.000Z',
    },
  };
}

function idorFinding(): Finding {
  return {
    id: 'fnd_rf_access',
    type: 'BROKEN_ACCESS_CONTROL',
    severity: 'high',
    title: 'Differential access',
    description: 'Observed access difference',
    target: `https://${HOST}/api/orders/corr`,
    evidence: 'hermetic',
    confidence: 1,
    verificationState: 'validated_vulnerability',
    metadata: {
      kind: 'broken_access_control_metadata',
      category: 'BROKEN_ACCESS_CONTROL',
      candidateId: 'cnd_rf_access',
      evidenceRecordId: 'evd_rf_access',
      lineage: { assessmentId: ASSESSMENT },
      endpointUrl: `https://${HOST}/api/orders/corr`,
      resourceParamName: 'orderId',
      baselineResourceId: '1',
      unauthorizedActorId: 'act_rf_other',
    },
  };
}

async function runLoop(args: {
  readonly decision: VerifiedAuthorizationDecision;
  readonly transport: (request: HttpProbeRequest) => Promise<HttpProbeResponse>;
  readonly plans: InMemoryAttackPlanRepository;
  readonly targets: readonly string[];
  readonly findings?: readonly Finding[];
  readonly stepBudget?: number;
}) {
  const execution = new AttackExecutionService({
    planRepository: args.plans,
    capabilityRegistry: registryFor(args.transport),
  });
  return runReadInvestigationLoop({
    assessmentId: ASSESSMENT,
    lineage: lineage(),
    verifiedAuthorizationDecision: args.decision,
    scopeGrant: scopeGrant(),
    coordinator: new TargetExecutionCoordinator({ requestsPerSecond: 5, maxConcurrency: 2 }),
    dnsResolver: async () => ['93.184.216.34'],
    transport: args.transport,
    circuitHost: HOST,
    findings: args.findings ?? [],
    probeInventory: inventory(),
    planRepository: args.plans,
    planGenerator: new FeedbackGenerator(),
    authorizationService: new AttackAuthorizationService(args.plans),
    executionService: execution,
    recordOutcome: async () => undefined,
    listNewlyReachableTargets: async () => args.targets,
    ...(args.stepBudget !== undefined ? { stepBudget: args.stepBudget } : {}),
  });
}

async function assertChainStatusDistinction(): Promise<void> {
  const nowIso = '2026-09-30T12:00:00.000Z';
  const assessmentId = 'asmt_rf_chain';
  const scanId = 'scan_rf_chain';
  const chainLineage = {
    assessmentId,
    scanId,
    authorizationGrantId: 'grant_rf_chain',
    authorizationDecisionId: 'dec_rf_chain',
    actorId: 'act_rf_chain',
  };
  const service = new AttackChainService(new InMemoryAttackChainRepository());
  const evidence = {
    reasonCode: 'hermetic_step',
    safeMessage: 'Hermetic chain step',
    recordedAt: nowIso,
  };

  let validated = await service.initHypothesis({
    chainId: 'chain_rf_ok_001',
    assessmentId,
    scanId,
    hypothesis: 'Two successful reads validate the chain',
    objectiveKind: 'information_disclosure',
    impactLevel: 'information_exposure',
    lineage: chainLineage,
    createdAt: nowIso,
  });
  validated = await service.appendExecutedStep({
    chainId: validated.chainId,
    assessmentId,
    scanId,
    stepId: 'step_rf_ok_1',
    capabilityKind: 'security_header_probe',
    epistemicStatus: 'VERIFIED',
    capabilityGained: 'none',
    outcome: 'succeeded',
    evidence,
  });
  validated = await service.appendExecutedStep({
    chainId: validated.chainId,
    assessmentId,
    scanId,
    stepId: 'step_rf_ok_2',
    capabilityKind: 'information_disclosure_probe',
    epistemicStatus: 'VERIFIED',
    capabilityGained: 'none',
    outcome: 'succeeded',
    evidence,
  });
  assert.equal(validated.status, 'fully_validated');
  assert.equal(validated.overallEpistemicStatus, 'VERIFIED');
  assert.equal(validated.impactLevel, 'information_exposure');

  let failed = await service.initHypothesis({
    chainId: 'chain_rf_fail_001',
    assessmentId,
    scanId,
    hypothesis: 'A transport failure is not a refutation',
    objectiveKind: 'privilege_escalation',
    impactLevel: 'privilege_escalation',
    lineage: chainLineage,
    createdAt: nowIso,
  });
  failed = await service.appendExecutedStep({
    chainId: failed.chainId,
    assessmentId,
    scanId,
    stepId: 'step_rf_fail_1',
    capabilityKind: 'security_header_probe',
    epistemicStatus: 'OBSERVED',
    capabilityGained: 'none',
    outcome: 'failed',
    evidence: {
      ...evidence,
      reasonCode: 'transport_failed',
      safeMessage: 'Transport failed before a conclusion',
    },
  });
  assert.equal(failed.status, 'failed');
  assert.notEqual(failed.status, 'refuted');
  assert.notEqual(failed.status, 'fully_validated');
  assert.equal(failed.overallEpistemicStatus, 'OBSERVED');
  assert.equal(failed.impactLevel, 'information_exposure');

  let refuted = await service.initHypothesis({
    chainId: 'chain_rf_refute_001',
    assessmentId,
    scanId,
    hypothesis: 'The target refuted the hypothesis',
    objectiveKind: 'privilege_escalation',
    impactLevel: 'privilege_escalation',
    lineage: chainLineage,
    createdAt: nowIso,
  });
  refuted = await service.appendExecutedStep({
    chainId: refuted.chainId,
    assessmentId,
    scanId,
    stepId: 'step_rf_refute_1',
    capabilityKind: 'security_header_probe',
    epistemicStatus: 'REFUTED',
    capabilityGained: 'none',
    outcome: 'refuted',
    evidence: {
      ...evidence,
      reasonCode: 'target_refuted',
      safeMessage: 'Target refuted the step',
    },
  });
  assert.equal(refuted.status, 'refuted');
  assert.equal(refuted.overallEpistemicStatus, 'REFUTED');
  assert.equal(refuted.impactLevel, 'information_exposure');

  let mixed = await service.initHypothesis({
    chainId: 'chain_rf_mix_001',
    assessmentId,
    scanId,
    hypothesis: 'A refutation stays refuted beside a failure',
    objectiveKind: 'information_disclosure',
    impactLevel: 'information_exposure',
    lineage: chainLineage,
    createdAt: nowIso,
  });
  mixed = await service.appendExecutedStep({
    chainId: mixed.chainId,
    assessmentId,
    scanId,
    stepId: 'step_rf_mix_fail',
    capabilityKind: 'security_header_probe',
    epistemicStatus: 'OBSERVED',
    capabilityGained: 'none',
    outcome: 'failed',
    evidence,
  });
  mixed = await service.appendExecutedStep({
    chainId: mixed.chainId,
    assessmentId,
    scanId,
    stepId: 'step_rf_mix_refute',
    capabilityKind: 'information_disclosure_probe',
    epistemicStatus: 'REFUTED',
    capabilityGained: 'none',
    outcome: 'refuted',
    evidence,
  });
  assert.equal(mixed.status, 'refuted');
  assert.equal(mixed.overallEpistemicStatus, 'REFUTED');
}

async function main(): Promise<void> {
  await assertChainStatusDistinction();
  const decision = brandedDecision();

  {
    const plans = new InMemoryAttackPlanRepository();
    await plans.savePlans([seedPlan()]);
    const counted = countingTransport();
    const result = await runLoop({
      decision,
      transport: counted.transport,
      plans,
      targets: [REACHABLE],
      stepBudget: 4,
    });
    assert.ok(result.record.stepsExecuted >= 2);
    assert.equal(result.record.stopReason, 'no_read_plans_remaining');
    assert.ok(counted.calls.includes(IN_SCOPE));
    assert.ok(counted.calls.some((url) => url.includes('/api/orders/reachable')));
    assert.equal(counted.calls.some((url) => url.includes('outsider.example')), false);
    assert.equal(counted.calls.some((url) => url.includes('169.254.169.254')), false);
  }

  {
    const plans = new InMemoryAttackPlanRepository();
    await plans.savePlans([seedPlan()]);
    const counted = countingTransport();
    const result = await runLoop({
      decision,
      transport: counted.transport,
      plans,
      targets: [OUTSIDE, METADATA, '169.254.169.254'],
      stepBudget: 4,
    });
    assert.deepEqual(counted.calls, [IN_SCOPE]);
    assert.ok(result.record.seenOutOfScopeUrls.some((url) => url.includes('outsider.example')));
    assert.ok(result.record.seenOutOfScopeUrls.some((url) => url.includes('169.254.169.254')));
    assert.equal(counted.calls.some((url) => url.includes('169.254.169.254')), false);
    assert.equal(counted.calls.some((url) => url.includes('outsider.example')), false);
  }

  {
    const plans = new InMemoryAttackPlanRepository();
    await plans.savePlans([seedPlan()]);
    const counted = countingTransport();
    const result = await runLoop({
      decision,
      transport: counted.transport,
      plans,
      targets: [],
      findings: [corsFinding(), idorFinding()],
      stepBudget: 4,
    });
    assert.ok(counted.calls.includes(CORRELATION_READ));
    assert.equal(counted.calls.some((url) => url.includes('persist-chain')), false);
    assert.equal(counted.calls.some((url) => url.includes('destroy-chain')), false);
    const persist = await plans.getPlan('plan_rf_persist');
    const destroy = await plans.getPlan('plan_rf_destroy');
    assert.equal(persist?.executable, false);
    assert.equal(destroy?.executable, false);
    assert.equal(persist?.authorizationBlastRadiusClass, 'persistence');
    assert.equal(destroy?.authorizationBlastRadiusClass, 'destructive');
    assert.ok(result.record.skippedNonReadPlanIds.includes('plan_rf_persist'));
    assert.ok(result.record.skippedNonReadPlanIds.includes('plan_rf_destroy'));
    assert.equal(
      result.record.executedSteps.some((step) => step.planId === 'plan_rf_persist'),
      false
    );
    assert.equal(
      result.record.executedSteps.some((step) => step.planId === 'plan_rf_destroy'),
      false
    );
  }

  {
    const plans = new InMemoryAttackPlanRepository();
    await plans.savePlans([seedPlan()]);
    const counted = countingTransport();
    const result = await runLoop({
      decision,
      transport: counted.transport,
      plans,
      targets: [],
      findings: [corsFinding(), idorFinding()],
      stepBudget: 1,
    });
    assert.equal(result.record.stopReason, 'step_budget_exhausted');
    assert.equal(result.record.stepsExecuted, 1);
    assert.deepEqual(counted.calls, [IN_SCOPE]);
    assert.equal(counted.calls.includes(CORRELATION_READ), false);
    assert.equal(counted.calls.some((url) => url.includes('persist-chain')), false);
    assert.equal(counted.calls.some((url) => url.includes('destroy-chain')), false);
    const unread = await plans.getPlan('plan_rf_corr_read');
    assert.ok(unread);
    assert.equal(unread.executable, false);
    assert.equal(
      result.record.executedSteps.some((step) => step.planId === 'plan_rf_corr_read'),
      false
    );
  }
}

main().catch(fail);
