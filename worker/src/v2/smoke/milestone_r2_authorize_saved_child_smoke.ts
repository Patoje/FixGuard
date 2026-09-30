/**
 * R2 — The same operator authorizes the saved read child, then execute.
 * The phase-1 hook does not authorize. prerequisite_missing plans are not executed.
 */
import assert from 'node:assert/strict';
import { ActiveInvestigationRuntimeService } from '../active-investigation/ActiveInvestigationRuntimeService.js';
import type {
  ReadOnlyLoopRequest,
  ReadOnlyLoopResult,
} from '../active-investigation/ActiveInvestigationRuntimeService.js';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import type { AuthorizableBlastRadiusClass } from '../attack-authorization/AttackAuthorizationContracts.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import { ATTACK_EXECUTION_CONTRACT_VERSION } from '../attack-execution/AttackExecutionContracts.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import type { AttackCapabilityKind } from '../attack-planning/AttackPlanContracts.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

const ACTOR_ID = 'usr_secops_api';
const TOKEN = 'session-bearer-must-not-enter-fact';
const ENDPOINT = 'https://app.example.com/api/orders/ord_123';
const OUTSIDE_LOOP = new Set<AttackCapabilityKind>([
  'next_server_action_diff',
  'idor_read_differential',
  'supabase_authz_write_matrix',
  'credential_reuse',
]);

class RecordingInvestigationRuntime extends ActiveInvestigationRuntimeService {
  readonly loopRequests: ReadOnlyLoopRequest[] = [];

  public override async runReadOnlyLoop(request: ReadOnlyLoopRequest): Promise<ReadOnlyLoopResult> {
    this.loopRequests.push(request);
    return super.runReadOnlyLoop(request);
  }
}

function readBlast(plan: AttackPlan): 'read_authenticated' | 'read_escalated' {
  if (plan.capabilityGained === 'read_authenticated' || plan.capabilityGained === 'read_escalated') {
    return plan.capabilityGained;
  }
  throw new Error(`read child capabilityGained is ${plan.capabilityGained}`);
}

async function main(): Promise<void> {
  process.env.FIXGUARD_V2_HERMETIC_RECON = '1';

  const runtime = new RecordingInvestigationRuntime();
  const plans = new InMemoryAttackPlanRepository();
  const service = new OrchestratedAssessmentApplicationService({
    repository: new InMemoryOrchestratedAssessmentRepository(),
    attackPlanRepository: plans,
    activeInvestigationRuntime: runtime,
    dnsResolver: async () => ['93.184.216.34'],
    httpTransport: async (request: HttpProbeRequest): Promise<HttpProbeResponse> => {
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
    },
  });

  const started = await service.startAssessment({
    targetDomain: 'app.example.com',
    actorId: ACTOR_ID,
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
  assert.equal(record.status, 'completed');

  const saved = await plans.listByAssessmentId(started.assessmentId);
  const child = saved.find(
    (plan) => plan.capability === 'auth_boundary_differential' && plan.executable === false
  );
  assert.ok(child);
  assert.equal(child.status, 'ready_for_authorization');

  assert.equal(runtime.loopRequests.length, 0);
  assert.ok(record.readInvestigationLoop);
  const storedSteps = record.readInvestigationLoop.executedSteps;
  assert.ok(storedSteps.length > 0);
  for (const step of storedSteps) {
    assert.equal(OUTSIDE_LOOP.has(step.capability), false);
  }

  const auth = new AttackAuthorizationService(plans);
  assert.equal(auth.getRuntimeToken(child.planId, started.assessmentId), null);

  const blast: AuthorizableBlastRadiusClass = readBlast(child);
  const authorized = await auth.authorizePlan(
    child.planId,
    started.assessmentId,
    blast,
    ACTOR_ID
  );
  assert.equal(authorized.status, 'established');
  if (authorized.status !== 'established') return;
  assert.equal(authorized.token.blastRadiusClass, blast);
  assert.equal(authorized.token.authorizedBy, ACTOR_ID);
  assert.equal(authorized.token.planId, child.planId);

  const otherAssessment = await auth.authorizePlan(
    child.planId,
    'asmt_other_r2',
    blast,
    ACTOR_ID
  );
  assert.equal(otherAssessment.status, 'failed');
  if (otherAssessment.status === 'failed') {
    assert.equal(otherAssessment.reasonCode, 'plan_not_found');
  }

  const persistence = await auth.authorizePlan(
    child.planId,
    started.assessmentId,
    'persistence',
    ACTOR_ID
  );
  assert.equal(persistence.status, 'failed');
  if (persistence.status === 'failed') {
    assert.equal(persistence.reasonCode, 'blast_radius_class_prohibited');
  }

  const stillAdvisory = await plans.getPlan(child.planId);
  assert.equal(stillAdvisory?.executable, false);
  assert.equal(stillAdvisory?.status, 'ready_for_authorization');

  const decision = service.getRuntimeVerifiedAuthorizationDecision(started.assessmentId);
  assert.ok(decision);
  const identities = service.getEphemeralByotExecuteIdentities(started.assessmentId);
  assert.ok(identities);
  const execution = new AttackExecutionService({
    planRepository: plans,
    capabilityRegistry: AttackCapabilityRegistry.createDefault(),
  });
  const executed = await execution.execute({
    contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
    kind: 'attack_execution_request',
    planId: child.planId,
    assessmentId: started.assessmentId,
    token: authorized.token,
    scopeGrant: decision.scopeGrant,
    coordinator: new TargetExecutionCoordinator(),
    dnsResolver: service.getRuntimeDnsResolver(),
    findings: [],
    operatorId: ACTOR_ID,
    primaryIdentity: identities.primaryIdentity,
    verifiedAuthorizationDecision: decision,
    transport: service.getRuntimeHttpTransport(),
  });
  assert.equal(executed.status, 'completed');
  assert.equal(JSON.stringify(executed).includes(TOKEN), false);
  assert.equal((await plans.getPlan(child.planId))?.executable, false);

  const existingBlocked = saved.find((plan) => plan.status === 'prerequisite_missing');
  const blocked =
    existingBlocked ??
    ({
      ...child,
      planId: 'plan_r2_prereq_block',
      status: 'prerequisite_missing',
      steps: child.steps.map((step) => ({ ...step, status: 'blocked' as const })),
    } satisfies AttackPlan);
  if (!existingBlocked) {
    await plans.savePlan(blocked);
  }
  const blockedAuth = await auth.authorizePlan(
    blocked.planId,
    started.assessmentId,
    blocked.capabilityGained === 'read_escalated' ? 'read_escalated' : 'read_authenticated',
    ACTOR_ID
  );
  assert.equal(blockedAuth.status, 'established');
  if (blockedAuth.status !== 'established') return;

  let blockedCalls = 0;
  const blockedExec = await execution.execute({
    contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
    kind: 'attack_execution_request',
    planId: blocked.planId,
    assessmentId: started.assessmentId,
    token: blockedAuth.token,
    scopeGrant: decision.scopeGrant,
    coordinator: new TargetExecutionCoordinator(),
    dnsResolver: async () => ['93.184.216.34'],
    findings: [],
    operatorId: ACTOR_ID,
    verifiedAuthorizationDecision: decision,
    transport: async () => {
      blockedCalls += 1;
      return {
        statusCode: 200,
        headers: {},
        bodyText: '',
        responseTimeMs: 1,
      };
    },
  });
  assert.equal(blockedExec.status, 'preflight_denied');
  if (blockedExec.status === 'preflight_denied') {
    assert.equal(blockedExec.reasonCode, 'prerequisite_missing');
  }
  assert.equal(blockedCalls, 0);
  assert.notEqual(
    blockedExec.status === 'preflight_denied' ? blockedExec.reasonCode : '',
    'idor_identities_missing'
  );

  console.log('[milestone_r2_authorize_saved_child_smoke] ALL PASSED');
}

main().catch((err) => {
  console.error('[milestone_r2_authorize_saved_child_smoke] FAILED', err);
  process.exit(1);
});
