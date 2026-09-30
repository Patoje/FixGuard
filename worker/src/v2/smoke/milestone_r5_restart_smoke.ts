/**
 * R5 — Postgres repositories survive a new process. The attack token does not.
 * Without the orchestrated Postgres env, composition stays in memory.
 */
import assert from 'node:assert/strict';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackPlan,
} from '../attack-planning/AttackPlanContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import {
  ATTACK_CHAIN_CONTRACT_VERSION,
  type AttackChain,
} from '../attack-chain/AttackChainContracts.js';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION } from '../application/OrchestratedAssessmentContracts.js';
import type { OrchestratedAssessmentRecord } from '../application/OrchestratedAssessmentContracts.js';
import {
  adaptOrchestratedAssessmentDb,
  PostgresOrchestratedAssessmentRepository,
} from '../storage/postgres/PostgresOrchestratedAssessmentRepository.js';
import {
  adaptAttackPlanDb,
  PostgresAttackPlanRepository,
} from '../storage/postgres/PostgresAttackPlanRepository.js';
import {
  adaptAttackChainDb,
  PostgresAttackChainRepository,
} from '../storage/postgres/PostgresAttackChainRepository.js';
import { createDurableV2CompositionFromEnv } from '../storage/composition/PostgresOrchestratedComposition.js';
import { MockPlanChainDb } from './phaseD2_durable_plans_chains_smoke.js';
import { MockDurableDb } from './phaseD2_durable_assessment_asg_smoke.js';

const ASSESSMENT_ID = 'asmt_r5_restart';
const SCAN_ID = 'scan_r5_restart';
const ACTOR_ID = 'act_r5_operator';
const PLAN_ID = 'plan_r5_restart';
const CHAIN_ID = 'chain_r5_restart';
const LINEAGE = {
  assessmentId: ASSESSMENT_ID,
  scanId: SCAN_ID,
  authorizationGrantId: 'grn_r5_001',
  authorizationDecisionId: 'dec_r5_001',
  actorId: ACTOR_ID,
} as const;

function buildRecord(): OrchestratedAssessmentRecord {
  const nowIso = '2026-09-28T12:00:00.000Z';
  return {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId: ASSESSMENT_ID,
    scanId: SCAN_ID,
    targetDomain: 'app.example.com',
    status: 'completed',
    lineage: LINEAGE,
    stages: [],
    timing: { startedAt: nowIso, completedAt: nowIso, durationMs: 12 },
    errorCount: 0,
    warningCount: 0,
    findings: [],
    recommendations: [],
  };
}

function buildPlan(): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: PLAN_ID,
    assessmentId: ASSESSMENT_ID,
    scanId: SCAN_ID,
    capability: 'auth_boundary_differential',
    title: 'Read the observed endpoint as identity A',
    reasoning: 'Advisory GET. It stays non-executable until the same actor authorizes it.',
    status: 'ready_for_authorization',
    blastRadius: 'single_endpoint',
    capabilityGained: 'read_authenticated',
    sourceFindingIds: [],
    sourceFindingTypes: ['observed_surface'],
    prerequisites: [
      {
        kind: 'identity_present',
        description: 'Requires identity A',
        satisfied: true,
      },
    ],
    steps: [
      {
        stepId: 'step_r5_1',
        ordinal: 1,
        title: 'GET as identity A',
        description: 'Advisory read step',
        status: 'ready',
        requiredPermissions: ['activeValidation'],
      },
    ],
    planOrigin: 'observed_surface',
    targetUrl: 'https://app.example.com/api/orders/ord_123',
    dependsOn: ['plan_r5_surface'],
    lineage: LINEAGE,
    createdAt: '2026-09-28T12:00:00.000Z',
    executable: false,
  };
}

function buildChain(): AttackChain {
  return {
    contractVersion: ATTACK_CHAIN_CONTRACT_VERSION,
    kind: 'attack_chain',
    chainId: CHAIN_ID,
    assessmentId: ASSESSMENT_ID,
    scanId: SCAN_ID,
    hypothesis: 'A later read can cite the saved plan',
    objectiveKind: 'data_access',
    steps: [
      {
        stepId: 'cstep_r5_1',
        sequence: 1,
        capabilityKind: 'auth_boundary_differential',
        epistemicStatus: 'OBSERVED',
        evidence: {
          reasonCode: 'read_completed',
          safeMessage: 'GET completed inside the authorized budget',
          recordedAt: '2026-09-28T12:01:00.000Z',
        },
        capabilityGained: 'read_authenticated',
        outcome: 'succeeded',
      },
    ],
    overallEpistemicStatus: 'OBSERVED',
    status: 'partially_validated',
    impactLevel: 'information_exposure',
    declaredImpactLevel: 'information_exposure',
    lineage: LINEAGE,
    createdAt: '2026-09-28T12:00:00.000Z',
  };
}

async function main(): Promise<void> {
  const previousRepo = process.env.FIXGUARD_V2_ORCHESTRATED_REPOSITORY;
  const previousEnable = process.env.FIXGUARD_V2_ENABLE_POSTGRES_ORCHESTRATED;
  delete process.env.FIXGUARD_V2_ORCHESTRATED_REPOSITORY;
  delete process.env.FIXGUARD_V2_ENABLE_POSTGRES_ORCHESTRATED;
  try {
    const memory = await createDurableV2CompositionFromEnv();
    assert.equal(memory.mode, 'memory');
    assert.ok(memory.root.attackPlanRepository instanceof InMemoryAttackPlanRepository);
    await memory.close();
  } finally {
    if (previousRepo === undefined) delete process.env.FIXGUARD_V2_ORCHESTRATED_REPOSITORY;
    else process.env.FIXGUARD_V2_ORCHESTRATED_REPOSITORY = previousRepo;
    if (previousEnable === undefined) delete process.env.FIXGUARD_V2_ENABLE_POSTGRES_ORCHESTRATED;
    else process.env.FIXGUARD_V2_ENABLE_POSTGRES_ORCHESTRATED = previousEnable;
  }

  const planMock = new MockPlanChainDb();
  const assessmentMock = new MockDurableDb();
  const records = new PostgresOrchestratedAssessmentRepository(
    adaptOrchestratedAssessmentDb(assessmentMock)
  );
  const plans = new PostgresAttackPlanRepository(adaptAttackPlanDb(planMock));
  const chains = new PostgresAttackChainRepository(adaptAttackChainDb(planMock));

  await records.save(buildRecord());
  await plans.savePlan(buildPlan());
  await chains.saveChain(buildChain());

  const stored = JSON.stringify({
    plans: Array.from(planMock.plans.values()),
    chains: Array.from(planMock.chains.values()),
    assessments: Array.from(assessmentMock.assessments.values()),
  });
  assert.equal(stored.includes('Bearer'), false);
  assert.equal(stored.includes('cookie'), false);
  assert.equal(stored.includes('sessionToken'), false);

  const recordsAgain = new PostgresOrchestratedAssessmentRepository(
    adaptOrchestratedAssessmentDb(assessmentMock)
  );
  const plansAgain = new PostgresAttackPlanRepository(adaptAttackPlanDb(planMock));
  const chainsAgain = new PostgresAttackChainRepository(adaptAttackChainDb(planMock));

  const reloaded = await recordsAgain.findById(ASSESSMENT_ID);
  assert.ok(reloaded);
  assert.equal(reloaded.assessmentId, ASSESSMENT_ID);
  assert.deepEqual(reloaded.lineage, LINEAGE);
  assert.equal((await chainsAgain.getChain(CHAIN_ID))?.assessmentId, ASSESSMENT_ID);
  assert.equal((await plansAgain.getPlan(PLAN_ID))?.executable, false);

  const firstAuth = new AttackAuthorizationService(plans);
  const established = await firstAuth.authorizePlan(
    PLAN_ID,
    ASSESSMENT_ID,
    'read_authenticated',
    ACTOR_ID
  );
  assert.equal(established.status, 'established');
  const restartedAuth = new AttackAuthorizationService(plansAgain);
  assert.equal(restartedAuth.getRuntimeToken(PLAN_ID, ASSESSMENT_ID), null);
  const otherAssessment = await restartedAuth.authorizePlan(
    PLAN_ID,
    'asmt_other_r5',
    'read_authenticated',
    ACTOR_ID
  );
  assert.equal(otherAssessment.status, 'failed');
  if (otherAssessment.status === 'failed') {
    assert.equal(otherAssessment.reasonCode, 'plan_not_found');
  }

  console.log('[milestone_r5_restart_smoke] ALL PASSED');
}

main().catch((err) => {
  console.error('[milestone_r5_restart_smoke] FAILED', err);
  process.exit(1);
});
