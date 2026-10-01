/**
 * Milestone Execution Epistemic Loop Smoke Suite
 *
 * Verifies that the post-execution loop is completely closed:
 * 1. Step execution via recordAttackExecutionOutcome records enriched producedFacts
 * 2. NextStepEngine automatically emits dependent child plan into AttackPlanRepository
 * 3. getAttackModeRefresh includes nextRecommendations populated with 1-click flags for the operator
 */

import assert from 'node:assert/strict';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { InMemoryAttackChainRepository } from '../attack-chain/InMemoryAttackChainRepository.js';
import { AttackChainService } from '../attack-chain/AttackChainService.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { AttackPlanGeneratorService } from '../attack-planning/AttackPlanGeneratorService.js';
import { LateralMovementService } from '../attack-planning/LateralMovementService.js';
import { ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION } from '../application/OrchestratedAssessmentContracts.js';
import type { AttackExecutionRecord } from '../attack-execution/AttackExecutionContracts.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import type { Finding } from '../core/Evidence.js';

const ASSESSMENT_ID = 'asmt_loop_smoke_001';
const SCAN_ID = 'scan_loop_smoke_001';
const HOST = 'supabase.target.com';

const LINEAGE = {
  assessmentId: ASSESSMENT_ID,
  scanId: SCAN_ID,
  authorizationGrantId: 'grant_loop_smoke_001',
  authorizationDecisionId: 'decision_loop_smoke_001',
  actorId: 'operator_loop_smoke',
} as const;

async function runSmoke(): Promise<void> {
  console.log('=== Epistemic Loop Smoke Suite: Execution ➔ Next Step ➔ Next Recommendations ===');

  const assessmentRepo = new InMemoryOrchestratedAssessmentRepository();
  const planRepo = new InMemoryAttackPlanRepository();
  const chainRepo = new InMemoryAttackChainRepository();
  const chainService = new AttackChainService(chainRepo);
  const planGenerator = new AttackPlanGeneratorService();
  const lateralService = new LateralMovementService();
  const appService = new OrchestratedAssessmentApplicationService({
    repository: assessmentRepo,
    attackPlanRepository: planRepo,
    attackChainRepository: chainRepo,
    attackChainService: chainService,
    attackPlanGenerator: planGenerator,
    lateralMovementService: lateralService,
  });

  const finding: Finding = {
    id: 'fnd_supabase_001',
    type: 'BROKEN_ACCESS_CONTROL',
    title: 'Public table profiles exposed',
    target: `https://${HOST}/rest/v1/profiles`,
    severity: 'high',
    evidence: 'observed',
    confidence: 0.9,
    verificationState: 'observed_anomaly',
    description: 'Supabase RLS read confirm candidate',
    metadata: {
      kind: 'supabase_rls_abuse_metadata',
      category: 'BROKEN_ACCESS_CONTROL',
      claimKind: 'SUPABASE_RLS_WORLD_READABLE',
      tableName: 'profiles',
      tableUrl: `https://${HOST}/rest/v1/profiles`,
      anonStatusCode: 200,
      anonBodyHash: 'hash_abc123',
      topLevelJsonKeys: ['id', 'username', 'role'],
      anonEqualsAuth: true,
      observedAt: new Date().toISOString(),
      candidateId: 'cand_supa_1',
      evidenceRecordId: 'evr_supa_1',
      lineage: {},
    },
  };

  const initialPlan: AttackPlan = {
    contractVersion: 'fixguard-attack-planning/v0',
    kind: 'attack_plan',
    planId: 'plan_supa_read_001',
    assessmentId: ASSESSMENT_ID,
    scanId: SCAN_ID,
    capability: 'supabase_rls_read_confirm',
    title: 'Confirm world-readable profiles table',
    reasoning: 'Verify RLS policy by reading 1 record',
    status: 'authorized',
    blastRadius: 'single_endpoint',
    capabilityGained: 'read_authenticated',
    sourceFindingIds: [finding.id],
    sourceFindingTypes: [finding.type],
    targetUrl: `https://${HOST}/rest/v1/profiles`,
    prerequisites: [],
    steps: [
      {
        stepId: 'step_supa_read_001',
        ordinal: 1,
        title: 'Read 1 record',
        description: 'Read 1 record without mutation',
        status: 'ready',
        requiredPermissions: ['activeValidation'],
      },
    ],
    planOrigin: 'observed_surface',
    lineage: LINEAGE,
    createdAt: new Date().toISOString(),
    executable: false,
  };

  await planRepo.savePlans([initialPlan]);

  // Seed orchestrated assessment record
  await assessmentRepo.save({
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId: ASSESSMENT_ID,
    scanId: SCAN_ID,
    targetDomain: HOST,
    status: 'running',
    lineage: LINEAGE,
    timing: { startedAt: new Date().toISOString() },
    stages: [],
    errorCount: 0,
    warningCount: 0,
    recommendations: [],
    findings: [finding],
    observedFacts: [],
  });

  // Simulate execution of plan_supa_read_001 returning success
  const executionRecord: AttackExecutionRecord = {
    contractVersion: 'fixguard-attack-execution/v0',
    kind: 'attack_execution_record',
    executionId: 'exec_loop_001',
    planId: initialPlan.planId,
    assessmentId: ASSESSMENT_ID,
    capability: initialPlan.capability,
    operatorId: LINEAGE.actorId,
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    status: 'completed',
    stepRecords: [
      {
        stepId: 'step_supa_read_001',
        ordinal: 1,
        capability: initialPlan.capability,
        blastRadiusClass: 'read_public',
        targetHost: HOST,
        outcome: 'succeeded',
        reasonCode: 'rls_read_confirmed',
        safeMessage: 'Read succeeded, 1 record returned',
        gatesPassed: true,
        verificationStateBefore: 'observed_anomaly',
        verificationStateAfter: 'validated_vulnerability',
        completedAt: new Date().toISOString(),
      },
    ],
    updatedFindings: [
      {
        ...finding,
        verificationState: 'validated_vulnerability',
      },
    ],
  };

  console.log('[*] Testing recordAttackExecutionOutcome...');
  const refresh = await appService.recordAttackExecutionOutcome({
    assessmentId: ASSESSMENT_ID,
    planId: initialPlan.planId,
    executionRecord,
  });

  // Assertion 1: Attack chain updated and partially_validated
  assert.equal(refresh.attackChains.length, 1);
  const chain = refresh.attackChains[0]!;
  assert.equal(chain.status, 'partially_validated');
  assert.equal(chain.steps.length, 1);
  const recordedStep = chain.steps[0]!;
  console.log('    Recorded facts on chain:', recordedStep.producedFacts);
  assert.ok(recordedStep.producedFacts?.some((f) => f.includes('capability_gained=read_authenticated')));
  assert.ok(recordedStep.producedFacts?.some((f) => f.includes('schema_relation:supabase_rls_confirmed')));
  console.log('✓ Assertion 1 Passed: Enriched facts recorded on chain');

  // Assertion 2: NextStepEngine emitted dependent child plan
  const allPlans = await planRepo.listByAssessmentId(ASSESSMENT_ID);
  console.log('    All plans in repo after execution:', allPlans.map((p) => `${p.planId} (${p.capability})`));
  const childPlan = allPlans.find((p) => p.dependsOn?.includes(initialPlan.planId));
  assert.ok(childPlan !== undefined, 'Dependent child plan should have been emitted by NextStepEngine');
  assert.equal(childPlan.capability, 'auth_boundary_differential');
  assert.deepEqual(childPlan.dependsOn, [initialPlan.planId]);
  console.log('✓ Assertion 2 Passed: Dependent child plan automatically emitted into repo');

  // Assertion 3: Refresh includes 1-click nextRecommendations for operator
  assert.ok(refresh.nextRecommendations !== undefined, 'Refresh should include nextRecommendations');
  assert.ok(refresh.nextRecommendations.length > 0, 'nextRecommendations should have at least 1 recommendation');
  const recA = refresh.nextRecommendations.find((r) => r.rank === 'A');
  assert.ok(recA !== undefined, 'Option A recommendation should be present');
  console.log(`    Next Recommendation A: ${recA.humanLabel}`);
  console.log(`    Command: ${recA.commandSummary}`);
  console.log(`    Flags: ${JSON.stringify(recA.suggestedFlags)}`);
  console.log('✓ Assertion 3 Passed: 1-Click nextRecommendations populated with exact flags');

  console.log('\n=== ALL EPISTEMIC LOOP TESTS PASSED SUCCESSFULLY ===');
}

runSmoke().catch((err) => {
  console.error('FAIL in epistemic loop smoke:', err);
  process.exit(1);
});
