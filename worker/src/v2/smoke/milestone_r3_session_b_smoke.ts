/**
 * R3 — Session B is attached by the same actor after a harvest object id.
 * The IDOR plan leaves prerequisite_missing and is not executed without B.
 */
import assert from 'node:assert/strict';
import { UnauthorizedGatewayError } from '../api/ApiErrors.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import { ATTACK_EXECUTION_CONTRACT_VERSION } from '../attack-execution/AttackExecutionContracts.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import type { ByotIdentity, HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { ActiveInvestigationRuntimeService } from '../active-investigation/ActiveInvestigationRuntimeService.js';
import type {
  ReadOnlyLoopRequest,
  ReadOnlyLoopResult,
} from '../active-investigation/ActiveInvestigationRuntimeService.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

const ACTOR_ID = 'usr_secops_api';
const TOKEN_A = 'session-a-must-not-enter-json';
const TOKEN_B = 'session-b-must-not-enter-json';
const ENDPOINT = 'https://app.example.com/api/orders/ord_123';

class RecordingInvestigationRuntime extends ActiveInvestigationRuntimeService {
  readonly loopRequests: ReadOnlyLoopRequest[] = [];

  public override async runReadOnlyLoop(request: ReadOnlyLoopRequest): Promise<ReadOnlyLoopResult> {
    this.loopRequests.push(request);
    return super.runReadOnlyLoop(request);
  }
}

function identityA(): ByotIdentity {
  return {
    identityId: 'id_session_a',
    injectHeaders: { authorization: `Bearer ${TOKEN_A}` },
  };
}

function identityB(): ByotIdentity {
  return {
    identityId: 'id_session_b',
    injectHeaders: { authorization: `Bearer ${TOKEN_B}` },
  };
}

async function startCase(input: {
  readonly withB: boolean;
}): Promise<{
  readonly service: OrchestratedAssessmentApplicationService;
  readonly plans: InMemoryAttackPlanRepository;
  readonly runtime: RecordingInvestigationRuntime;
  readonly assessmentId: string;
}> {
  const runtime = new RecordingInvestigationRuntime();
  const plans = new InMemoryAttackPlanRepository();
  const service = new OrchestratedAssessmentApplicationService({
    repository: new InMemoryOrchestratedAssessmentRepository(),
    attackPlanRepository: plans,
    activeInvestigationRuntime: runtime,
    dnsResolver: async () => ['93.184.216.34'],
    httpTransport: async (_request: HttpProbeRequest): Promise<HttpProbeResponse> => ({
      statusCode: 200,
      headers: { 'content-type': 'text/html' },
      bodyText: 'fetch("/api/orders/ord_123")',
      responseTimeMs: 1,
    }),
  });
  const started = await service.startAssessment({
    targetDomain: 'app.example.com',
    actorId: ACTOR_ID,
    seedUrls: [ENDPOINT],
    sessionIdentities: {
      identityA: identityA(),
      ...(input.withB ? { identityB: identityB() } : {}),
    },
    config: {
      enableByotHarvest: true,
      byotHarvestHttpOnly: true,
      deepReconMaxRequests: 50,
      skipStages: [
        'stage_1_domain_zone',
        'stage_2_port_service',
        'stage_3_web_tls',
        'stage_4_crawling_parameters',
        'stage_5_secret_inspection',
      ],
    },
  });
  const record = await service.awaitAssessment(started.assessmentId);
  assert.ok(record);
  if (record.status !== 'completed') {
    throw new Error(`assessment status ${record.status}: ${record.error ?? ''}`);
  }
  assert.equal(JSON.stringify(record).includes(TOKEN_A), false);
  assert.equal(JSON.stringify(record).includes(TOKEN_B), false);
  return { service, plans, runtime, assessmentId: started.assessmentId };
}

async function main(): Promise<void> {
  process.env.FIXGUARD_V2_HERMETIC_RECON = '1';

  const first = await startCase({ withB: false });
  const saved = await first.plans.listByAssessmentId(first.assessmentId);
  const record = await first.service.awaitAssessment(first.assessmentId);
  assert.ok(record);
  const fact = (record.observedFacts ?? []).find(
    (item) => item.factKind === 'observed_object_id' && item.sourceLabel === 'byot_network_harvest'
  );
  assert.ok(fact, 'harvest must record observed_object_id');
  const planId = `plan_f3b_${fact.factId}`;
  const idor = saved.find((plan) => plan.planId === planId);
  assert.ok(idor);
  assert.equal(idor.capability, 'idor_read_differential');
  assert.equal(idor.status, 'prerequisite_missing');
  assert.equal(idor.executable, false);
  assert.equal(saved.filter((plan) => plan.planId.startsWith('plan_f3b_')).length, 1);

  const status = await first.service.getStatus(first.assessmentId);
  const summary = await first.service.getSummary(first.assessmentId);
  assert.ok(status.identityBMissingPlanIds.includes(planId));
  assert.ok(summary.identityBMissingPlanIds.includes(planId));

  assert.equal(first.runtime.loopRequests.length, 0);
  assert.ok(record.readInvestigationLoop);
  for (const step of record.readInvestigationLoop.executedSteps) {
    assert.notEqual(step.capability, 'idor_read_differential');
  }

  await assert.rejects(
    () =>
      first.service.attachSessionIdentityB({
        assessmentId: first.assessmentId,
        operatorId: 'usr_other_operator',
        identityB: identityB(),
      }),
    (err: unknown) => err instanceof UnauthorizedGatewayError
  );

  const attached = await first.service.attachSessionIdentityB({
    assessmentId: first.assessmentId,
    operatorId: ACTOR_ID,
    identityB: identityB(),
  });
  assert.equal(attached.identityCount, 2);
  assert.deepEqual(attached.updatedPlanIds, [planId]);
  assert.equal(JSON.stringify(attached).includes(TOKEN_B), false);

  const after = await first.plans.getPlan(planId);
  assert.ok(after);
  assert.equal(after.status, 'ready_for_authorization');
  assert.equal(after.executable, false);
  assert.equal(
    after.prerequisites.find((item) => item.kind === 'identity_count_at_least_2')?.satisfied,
    true
  );
  assert.ok(after.steps.some((step) => step.status === 'ready'));
  assert.equal(
    (await first.plans.listByAssessmentId(first.assessmentId)).filter((plan) => plan.planId === planId)
      .length,
    1
  );

  const afterStatus = await first.service.getStatus(first.assessmentId);
  const afterSummary = await first.service.getSummary(first.assessmentId);
  assert.deepEqual(afterStatus.identityBMissingPlanIds, []);
  assert.deepEqual(afterSummary.identityBMissingPlanIds, []);
  const leaked = JSON.stringify({
    afterStatus,
    afterSummary,
    record: await first.service.awaitAssessment(first.assessmentId),
  });
  assert.equal(leaked.includes(TOKEN_B), false);
  assert.equal(leaked.includes(TOKEN_A), false);

  const auth = new AttackAuthorizationService(first.plans);
  const authorized = await auth.authorizePlan(
    planId,
    first.assessmentId,
    'read_escalated',
    ACTOR_ID
  );
  assert.equal(authorized.status, 'established');
  if (authorized.status !== 'established') return;
  const decision = first.service.getRuntimeVerifiedAuthorizationDecision(first.assessmentId);
  assert.ok(decision);
  const identities = first.service.getEphemeralByotExecuteIdentities(first.assessmentId);
  assert.ok(identities);
  const execution = new AttackExecutionService({
    planRepository: first.plans,
    capabilityRegistry: AttackCapabilityRegistry.createDefault(),
  });
  const executed = await execution.execute({
    contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
    kind: 'attack_execution_request',
    planId,
    assessmentId: first.assessmentId,
    token: authorized.token,
    scopeGrant: decision.scopeGrant,
    coordinator: new TargetExecutionCoordinator(),
    dnsResolver: first.service.getRuntimeDnsResolver(),
    findings: [],
    operatorId: ACTOR_ID,
    primaryIdentity: identities.primaryIdentity,
    verifiedAuthorizationDecision: decision,
    transport: first.service.getRuntimeHttpTransport(),
  });
  const executedText = JSON.stringify(executed);
  assert.equal(executedText.includes('idor_identities_missing'), true);
  assert.equal(executedText.includes(TOKEN_B), false);

  const born = await startCase({ withB: true });
  const bornRecord = await born.service.awaitAssessment(born.assessmentId);
  assert.ok(bornRecord);
  const bornFact = (bornRecord.observedFacts ?? []).find(
    (item) => item.factKind === 'observed_object_id' && item.sourceLabel === 'byot_network_harvest'
  );
  assert.ok(bornFact);
  const bornPlan = (await born.plans.listByAssessmentId(born.assessmentId)).find(
    (plan) => plan.planId === `plan_f3b_${bornFact.factId}`
  );
  assert.ok(bornPlan);
  assert.equal(bornPlan.status, 'ready_for_authorization');
  assert.deepEqual((await born.service.getStatus(born.assessmentId)).identityBMissingPlanIds, []);
  assert.equal(JSON.stringify(bornRecord).includes(TOKEN_B), false);

  console.log('[milestone_r3_session_b_smoke] ALL PASSED');
}

main().catch((err) => {
  console.error('[milestone_r3_session_b_smoke] FAILED', err);
  process.exit(1);
});
