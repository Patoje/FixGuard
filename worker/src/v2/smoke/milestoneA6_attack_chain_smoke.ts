/**
 * Milestone A6 Smoke Suite — Attack Chain Tracker
 *
 * Verifies:
 * 1. Step1 succeeded → partially_validated; Step2 succeeded → fully_validated
 * 2. INFERRED step → overallEpistemicStatus INFERRED even if others VERIFIED
 * 3. Refuted/failed step preserves evidence, blocks fully_validated
 * 4. Cross-assessment injection fails closed
 *
 * Hermetic. process.exit(1) on failure.
 */

import assert from 'node:assert/strict';
import type { Request, Response, NextFunction } from 'express';
import {
  EPISTEMIC_RANK,
  minEpistemicStatus,
  type AttackChain,
} from '../attack-chain/AttackChainContracts.js';
import { InMemoryAttackChainRepository } from '../attack-chain/InMemoryAttackChainRepository.js';
import {
  AttackChainIsolationError,
  AttackChainService,
} from '../attack-chain/AttackChainService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import {
  ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
  type OrchestratedAssessmentRecord,
} from '../application/OrchestratedAssessmentContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';
import { OrchestratedAssessmentController } from '../api/controllers/OrchestratedAssessmentController.js';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

async function runSmokeTests(): Promise<void> {
  console.log('=== Milestone A6: Attack Chain Tracker Smoke Suite ===');

  const nowIso = '2026-09-23T20:00:00.000Z';
  const assessmentId = 'assess_a6_chain_001';
  const scanId = 'scan_a6_chain_001';
  const otherAssessmentId = 'assess_a6_chain_other';
  const otherScanId = 'scan_a6_chain_other';

  const lineage = {
    assessmentId,
    scanId,
    authorizationGrantId: 'grant_a6_chain_001',
    authorizationDecisionId: 'decision_a6_chain_001',
    actorId: 'actor_a6_chain_001',
  };

  // --- Epistemic rank contract ---
  assert.ok(EPISTEMIC_RANK.REFUTED < EPISTEMIC_RANK.INFERRED);
  assert.ok(EPISTEMIC_RANK.INFERRED < EPISTEMIC_RANK.OBSERVED);
  assert.ok(EPISTEMIC_RANK.OBSERVED < EPISTEMIC_RANK.VERIFIED);
  assert.equal(minEpistemicStatus(['VERIFIED', 'INFERRED', 'OBSERVED']), 'INFERRED');
  assert.equal(minEpistemicStatus(['VERIFIED', 'REFUTED']), 'REFUTED');

  // --- Test 1: Step1 → partially_validated; Step2 → fully_validated ---
  const repo1 = new InMemoryAttackChainRepository();
  const service1 = new AttackChainService(repo1);

  let chain = await service1.initHypothesis({
    chainId: 'chain_a6_happy_001',
    assessmentId,
    scanId,
    hypothesis: 'Cross-identity read may escalate to authenticated data access',
    objectiveKind: 'data_access',
    impactLevel: 'data_access',
    lineage,
    createdAt: nowIso,
  });
  assert.equal(chain.status, 'hypothesis');
  assert.equal(chain.overallEpistemicStatus, 'INFERRED');
  assert.equal(chain.steps.length, 0);
  assert.equal(chain.declaredImpactLevel, 'data_access');
  assert.equal(
    chain.impactLevel,
    'information_exposure',
    'Hypothesis must bound high impactLevel until VERIFIED evidence'
  );

  chain = await service1.appendExecutedStep({
    chainId: chain.chainId,
    assessmentId,
    scanId,
    stepId: 'step_a6_1',
    capabilityKind: 'idor_read_differential',
    epistemicStatus: 'VERIFIED',
    capabilityGained: 'read_escalated',
    outcome: 'succeeded',
    evidence: {
      evidenceId: 'ev_a6_1',
      reasonCode: 'idor_differential_confirmed',
      safeMessage: 'Observed differential read between identities',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
  });
  assert.equal(chain.status, 'partially_validated');
  assert.equal(chain.overallEpistemicStatus, 'VERIFIED');
  assert.equal(chain.steps.length, 1);
  assert.equal(chain.steps[0]?.outcome, 'succeeded');
  assert.equal(
    chain.impactLevel,
    'information_exposure',
    'partially_validated must still bound high impactLevel'
  );

  chain = await service1.appendExecutedStep({
    chainId: chain.chainId,
    assessmentId,
    scanId,
    stepId: 'step_a6_2',
    capabilityKind: 'auth_bypass_probe',
    epistemicStatus: 'VERIFIED',
    capabilityGained: 'read_authenticated',
    outcome: 'succeeded',
    sourceStepId: 'step_a6_1',
    evidence: {
      evidenceId: 'ev_a6_2',
      reasonCode: 'auth_bypass_confirmed',
      safeMessage: 'Observed authenticated access after prior step',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
  });
  assert.equal(chain.status, 'fully_validated');
  assert.equal(chain.overallEpistemicStatus, 'VERIFIED');
  assert.equal(chain.steps.length, 2);
  assert.ok(typeof chain.completedAt === 'string');
  assert.equal(
    chain.impactLevel,
    'data_access',
    'fully_validated + VERIFIED restores declared high impact'
  );

  console.log('✓ Test 1 Passed: Step1 partial → Step2 fully_validated');

  // --- Test 2: INFERRED step forces overall INFERRED ---
  const repo2 = new InMemoryAttackChainRepository();
  const service2 = new AttackChainService(repo2);

  let inferredChain = await service2.initHypothesis({
    chainId: 'chain_a6_inferred_001',
    assessmentId,
    scanId,
    hypothesis: 'Mixed epistemic chain must not inflate to VERIFIED',
    objectiveKind: 'information_disclosure',
    impactLevel: 'information_exposure',
    lineage,
    createdAt: nowIso,
  });

  inferredChain = await service2.appendExecutedStep({
    chainId: inferredChain.chainId,
    assessmentId,
    scanId,
    stepId: 'step_inf_1',
    capabilityKind: 'parameter_reflection_probe',
    epistemicStatus: 'VERIFIED',
    capabilityGained: 'active_validation',
    outcome: 'succeeded',
    evidence: {
      reasonCode: 'reflection_verified',
      safeMessage: 'Verified reflection evidence',
      recordedAt: nowIso,
    },
  });

  inferredChain = await service2.appendExecutedStep({
    chainId: inferredChain.chainId,
    assessmentId,
    scanId,
    stepId: 'step_inf_2',
    capabilityKind: 'cors_chain_exploit',
    epistemicStatus: 'INFERRED',
    capabilityGained: 'none',
    outcome: 'succeeded',
    sourceStepId: 'step_inf_1',
    evidence: {
      reasonCode: 'cors_chain_inferred',
      safeMessage: 'Inferred CORS chain link without direct verification',
      recordedAt: nowIso,
    },
  });

  assert.equal(inferredChain.status, 'fully_validated');
  assert.equal(inferredChain.overallEpistemicStatus, 'INFERRED');
  assert.equal(inferredChain.steps[0]?.epistemicStatus, 'VERIFIED');
  assert.equal(inferredChain.steps[1]?.epistemicStatus, 'INFERRED');

  console.log('✓ Test 2 Passed: INFERRED step keeps overallEpistemicStatus INFERRED');

  // --- Test 3: Refuted/failed preserves evidence, blocks fully_validated ---
  const repo3 = new InMemoryAttackChainRepository();
  const service3 = new AttackChainService(repo3);

  let refutedChain = await service3.initHypothesis({
    chainId: 'chain_a6_refute_001',
    assessmentId,
    scanId,
    hypothesis: 'Failed step must not be discarded to force fully_validated',
    objectiveKind: 'privilege_escalation',
    impactLevel: 'privilege_escalation',
    lineage,
    createdAt: nowIso,
  });

  refutedChain = await service3.appendExecutedStep({
    chainId: refutedChain.chainId,
    assessmentId,
    scanId,
    stepId: 'step_ref_1',
    capabilityKind: 'idor_read_differential',
    epistemicStatus: 'VERIFIED',
    capabilityGained: 'read_escalated',
    outcome: 'succeeded',
    evidence: {
      evidenceId: 'ev_ref_1',
      reasonCode: 'idor_ok',
      safeMessage: 'First step succeeded',
      recordedAt: nowIso,
    },
  });

  refutedChain = await service3.appendExecutedStep({
    chainId: refutedChain.chainId,
    assessmentId,
    scanId,
    stepId: 'step_ref_2',
    capabilityKind: 'jwt_alg_none_probe',
    epistemicStatus: 'REFUTED',
    capabilityGained: 'none',
    outcome: 'refuted',
    sourceStepId: 'step_ref_1',
    evidence: {
      evidenceId: 'ev_ref_2',
      reasonCode: 'jwt_alg_none_refuted',
      safeMessage: 'Alg=none probe refuted by target',
      recordedAt: nowIso,
    },
  });

  assert.equal(refutedChain.status, 'refuted');
  assert.notEqual(refutedChain.status, 'fully_validated');
  assert.equal(refutedChain.overallEpistemicStatus, 'REFUTED');
  assert.equal(refutedChain.steps.length, 2);
  assert.equal(refutedChain.steps[1]?.outcome, 'refuted');
  assert.equal(refutedChain.steps[1]?.evidence.evidenceId, 'ev_ref_2');
  assert.equal(refutedChain.steps[1]?.evidence.reasonCode, 'jwt_alg_none_refuted');

  // Failed path via recordOutcome also blocks fully_validated and preserves prior evidence
  let failedChain = await service3.initHypothesis({
    chainId: 'chain_a6_fail_001',
    assessmentId,
    scanId,
    hypothesis: 'Failed outcome blocks full validation',
    objectiveKind: 'lateral_movement',
    impactLevel: 'lateral_movement',
    lineage,
    createdAt: nowIso,
  });
  failedChain = await service3.appendExecutedStep({
    chainId: failedChain.chainId,
    assessmentId,
    scanId,
    stepId: 'step_fail_1',
    capabilityKind: 'method_manipulation_probe',
    epistemicStatus: 'OBSERVED',
    capabilityGained: 'active_validation',
    outcome: 'succeeded',
    evidence: {
      evidenceId: 'ev_fail_1',
      reasonCode: 'method_ok',
      safeMessage: 'Method probe observed',
      recordedAt: nowIso,
    },
  });
  failedChain = await service3.appendExecutedStep({
    chainId: failedChain.chainId,
    assessmentId,
    scanId,
    stepId: 'step_fail_2',
    capabilityKind: 'session_fixation_probe',
    epistemicStatus: 'OBSERVED',
    capabilityGained: 'none',
    outcome: 'succeeded',
    sourceStepId: 'step_fail_1',
    evidence: {
      evidenceId: 'ev_fail_2',
      reasonCode: 'session_pending',
      safeMessage: 'Session step initially recorded',
      recordedAt: nowIso,
    },
  });
  assert.equal(failedChain.status, 'fully_validated');

  failedChain = await service3.recordOutcome({
    chainId: failedChain.chainId,
    assessmentId,
    scanId,
    stepId: 'step_fail_2',
    outcome: 'failed',
    epistemicStatus: 'REFUTED',
    evidence: {
      evidenceId: 'ev_fail_2',
      reasonCode: 'session_fixation_failed',
      safeMessage: 'Session fixation step failed; evidence retained',
      recordedAt: nowIso,
    },
  });
  assert.equal(failedChain.status, 'refuted');
  assert.notEqual(failedChain.status, 'fully_validated');
  assert.equal(failedChain.steps.length, 2);
  assert.equal(failedChain.steps[1]?.outcome, 'failed');
  assert.equal(failedChain.steps[1]?.evidence.reasonCode, 'session_fixation_failed');

  console.log('✓ Test 3 Passed: Refuted/failed evidence retained; fully_validated blocked');

  // --- Test 4: Cross-assessment injection fails closed ---
  const repo4 = new InMemoryAttackChainRepository();
  const service4 = new AttackChainService(repo4);

  const isolated = await service4.initHypothesis({
    chainId: 'chain_a6_iso_001',
    assessmentId,
    scanId,
    hypothesis: 'Isolation boundary must reject foreign assessment steps',
    objectiveKind: 'authentication_bypass',
    impactLevel: 'authentication_bypass',
    lineage,
    createdAt: nowIso,
  });

  let isolationThrown = false;
  try {
    await service4.appendExecutedStep({
      chainId: isolated.chainId,
      assessmentId: otherAssessmentId,
      scanId: otherScanId,
      stepId: 'step_iso_foreign',
      capabilityKind: 'auth_bypass_probe',
      epistemicStatus: 'VERIFIED',
      capabilityGained: 'read_authenticated',
      outcome: 'succeeded',
      evidence: {
        reasonCode: 'foreign_injection',
        safeMessage: 'Should never be accepted',
        recordedAt: nowIso,
      },
    });
  } catch (err) {
    isolationThrown = true;
    assert.ok(err instanceof AttackChainIsolationError);
    assert.equal(err.reasonCode, 'attack_chain_isolation_violation');
  }
  assert.equal(isolationThrown, true);

  const afterReject = await service4.getChain(isolated.chainId);
  assert.ok(afterReject);
  assert.equal(afterReject.steps.length, 0);
  assert.equal(afterReject.status, 'hypothesis');

  // Application + API list path
  const orchestratedRepo = new InMemoryOrchestratedAssessmentRepository();
  const record: OrchestratedAssessmentRecord = {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId,
    scanId,
    targetDomain: 'example.test',
    status: 'completed',
    lineage,
    stages: [],
    timing: { startedAt: nowIso, completedAt: nowIso, durationMs: 1 },
    errorCount: 0,
    warningCount: 0,
    findings: [],
    recommendations: [],
  };
  await orchestratedRepo.save(record);

  const chainRepo = new InMemoryAttackChainRepository();
  const chainService = new AttackChainService(chainRepo);
  await chainService.initHypothesis({
    chainId: 'chain_a6_api_001',
    assessmentId,
    scanId,
    hypothesis: 'API list returns stored chains with lineage',
    objectiveKind: 'data_access',
    impactLevel: 'data_access',
    lineage,
    createdAt: nowIso,
  });

  const appService = new OrchestratedAssessmentApplicationService({
    repository: orchestratedRepo,
    attackChainRepository: chainRepo,
    attackChainService: chainService,
  });
  const listed = await appService.getAttackChains(assessmentId);
  assert.equal(listed.assessmentId, assessmentId);
  assert.equal(listed.scanId, scanId);
  assert.equal(listed.chainCount, 1);
  assert.equal(listed.chains[0]?.chainId, 'chain_a6_api_001');
  assert.equal(listed.lineage.assessmentId, assessmentId);

  const root = V2CompositionRoot.withDependencies({
    orchestratedRepository: orchestratedRepo,
    attackChainRepository: chainRepo,
    attackChainService: chainService,
    orchestratedService: appService,
  });
  assert.equal(root.attackChainRepository, chainRepo);
  assert.equal(root.attackChainService, chainService);

  const controller = new OrchestratedAssessmentController(root.orchestratedService);
  let statusCode = 0;
  let body: unknown = null;
  const req = { params: { assessmentId } } as unknown as Request;
  const res = {
    status(code: number) {
      statusCode = code;
      return this;
    },
    json(payload: unknown) {
      body = payload;
      return this;
    },
  } as unknown as Response;
  const next: NextFunction = (err?: unknown) => {
    if (err) throw err;
  };
  await controller.getAttackChains(req, res, next);
  assert.equal(statusCode, 200);
  assert.ok(body && typeof body === 'object');
  const payload = body as { chainCount: number; chains: AttackChain[] };
  assert.equal(payload.chainCount, 1);
  assert.equal(payload.chains[0]?.kind, 'attack_chain');

  console.log('✓ Test 4 Passed: Cross-assessment injection fail-closed + API list');

  console.log('=== Milestone A6 Attack Chain Tracker: ALL TESTS PASSED ===');
}

runSmokeTests().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  fail(message);
});
