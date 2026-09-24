/**
 * Milestone A12 Smoke Suite — Impact Assessment & Adversarial Report
 *
 * Verifies:
 * 1. Completed chain → honest ImpactAssessment matching epistemic status
 * 2. HTML renders new adversarial sections (chains, acquired access, refuted defenses)
 * 3. Epistemic labels explicitly present ([VERIFIED], [INFERRED - NOT VERIFIED], [REFUTED - TARGET RESISTED])
 * 4. Report serialization contains zero vault secret strings
 *
 * Hermetic. process.exit(1) on failure. No secret logging.
 */

import assert from 'node:assert/strict';
import type { Request, Response, NextFunction } from 'express';
import { InMemoryAttackChainRepository } from '../attack-chain/InMemoryAttackChainRepository.js';
import { AttackChainService } from '../attack-chain/AttackChainService.js';
import { ImpactAssessmentService } from '../reporting-boundary/ImpactAssessmentService.js';
import {
  formatEpistemicBadge,
  validateImpactAssessment,
} from '../reporting-boundary/ImpactAssessmentContracts.js';
import { generateDefensiveHtmlReport } from '../reporting-boundary/ReportGeneratorService.js';
import { InMemoryPostExploitationRepository } from '../post-exploitation/InMemoryPostExploitationRepository.js';
import { CredentialVaultService } from '../post-exploitation/CredentialVaultService.js';
import { PostExploitationService } from '../post-exploitation/PostExploitationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import {
  ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
  type OrchestratedAssessmentRecord,
} from '../application/OrchestratedAssessmentContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';
import { OrchestratedAssessmentController } from '../api/controllers/OrchestratedAssessmentController.js';
import { ATTACK_PLANNING_CONTRACT_VERSION, type AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';

const SECRET_MARKER = 'supersecret-session-cookie-value-a12-do-not-leak';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function buildRecord(
  assessmentId: string,
  scanId: string,
  lineage: OrchestratedAssessmentRecord['lineage']
): OrchestratedAssessmentRecord {
  return {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId,
    scanId,
    targetDomain: 'example.com',
    status: 'completed',
    timing: {
      startedAt: '2026-09-24T10:00:00.000Z',
      completedAt: '2026-09-24T10:30:00.000Z',
      durationMs: 1_800_000,
    },
    lineage,
    stages: [],
    errorCount: 0,
    warningCount: 0,
    findings: [],
    pendingEvidenceDrafts: [],
    recommendations: [],
  };
}

async function runSmokeTests(): Promise<void> {
  console.log('=== Milestone A12: Impact Assessment & Adversarial Report Smoke Suite ===');

  const nowIso = '2026-09-24T11:00:00.000Z';
  const assessmentId = 'assess_a12_impact_001';
  const scanId = 'scan_a12_impact_001';
  const lineage = {
    assessmentId,
    scanId,
    authorizationGrantId: 'grant_a12_impact_001',
    authorizationDecisionId: 'decision_a12_impact_001',
    actorId: 'actor_a12_impact_001',
  };

  // Badge contract
  assert.equal(formatEpistemicBadge('VERIFIED'), '[VERIFIED]');
  assert.equal(formatEpistemicBadge('INFERRED'), '[INFERRED - NOT VERIFIED]');
  assert.equal(formatEpistemicBadge('REFUTED'), '[REFUTED - TARGET RESISTED]');

  const chainRepo = new InMemoryAttackChainRepository();
  const chainService = new AttackChainService(chainRepo);
  const impactService = new ImpactAssessmentService();
  const vault = new CredentialVaultService();
  const postRepo = new InMemoryPostExploitationRepository();
  const postService = new PostExploitationService(postRepo, vault);
  const planRepo = new InMemoryAttackPlanRepository();

  // --- Build VERIFIED completed chain ---
  let verifiedChain = await chainService.initHypothesis({
    chainId: 'chain_a12_verified_001',
    assessmentId,
    scanId,
    hypothesis: 'Authenticated differential read may yield data access',
    objectiveKind: 'data_access',
    impactLevel: 'data_access',
    lineage,
    createdAt: nowIso,
  });
  verifiedChain = await chainService.appendExecutedStep({
    chainId: verifiedChain.chainId,
    assessmentId,
    scanId,
    stepId: 'step_a12_v1',
    capabilityKind: 'idor_read_differential',
    epistemicStatus: 'VERIFIED',
    capabilityGained: 'read_escalated',
    outcome: 'succeeded',
    evidence: {
      evidenceId: 'ev_a12_v1',
      reasonCode: 'idor_differential_confirmed',
      safeMessage: 'Observed differential read between identities',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
  });
  verifiedChain = await chainService.appendExecutedStep({
    chainId: verifiedChain.chainId,
    assessmentId,
    scanId,
    stepId: 'step_a12_v2',
    capabilityKind: 'auth_bypass_probe',
    epistemicStatus: 'VERIFIED',
    capabilityGained: 'read_authenticated',
    outcome: 'succeeded',
    sourceStepId: 'step_a12_v1',
    evidence: {
      evidenceId: 'ev_a12_v2',
      reasonCode: 'auth_access_confirmed',
      safeMessage: 'Observed authenticated access after prior step',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
  });
  assert.equal(verifiedChain.status, 'fully_validated');
  assert.equal(verifiedChain.overallEpistemicStatus, 'VERIFIED');

  // --- Build INFERRED completed chain (must not inflate) ---
  let inferredChain = await chainService.initHypothesis({
    chainId: 'chain_a12_inferred_001',
    assessmentId,
    scanId,
    hypothesis: 'Possible privilege escalation remains unverified',
    objectiveKind: 'privilege_escalation',
    impactLevel: 'privilege_escalation',
    lineage,
    createdAt: nowIso,
  });
  inferredChain = await chainService.appendExecutedStep({
    chainId: inferredChain.chainId,
    assessmentId,
    scanId,
    stepId: 'step_a12_i1',
    capabilityKind: 'parameter_reflection_probe',
    epistemicStatus: 'INFERRED',
    capabilityGained: 'none',
    outcome: 'succeeded',
    evidence: {
      evidenceId: 'ev_a12_i1',
      reasonCode: 'reflection_hint_only',
      safeMessage: 'Parameter reflection observed without confirmation',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
  });
  inferredChain = await chainService.appendExecutedStep({
    chainId: inferredChain.chainId,
    assessmentId,
    scanId,
    stepId: 'step_a12_i2',
    capabilityKind: 'jwt_alg_none_probe',
    epistemicStatus: 'INFERRED',
    capabilityGained: 'none',
    outcome: 'succeeded',
    sourceStepId: 'step_a12_i1',
    evidence: {
      evidenceId: 'ev_a12_i2',
      reasonCode: 'jwt_hint_only',
      safeMessage: 'JWT alg hint observed without verification',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
  });
  assert.equal(inferredChain.status, 'fully_validated');
  assert.equal(inferredChain.overallEpistemicStatus, 'INFERRED');

  // --- Build REFUTED chain ---
  let refutedChain = await chainService.initHypothesis({
    chainId: 'chain_a12_refuted_001',
    assessmentId,
    scanId,
    hypothesis: 'Auth bypass should be blocked by target controls',
    objectiveKind: 'authentication_bypass',
    impactLevel: 'authentication_bypass',
    lineage,
    createdAt: nowIso,
  });
  refutedChain = await chainService.appendExecutedStep({
    chainId: refutedChain.chainId,
    assessmentId,
    scanId,
    stepId: 'step_a12_r1',
    capabilityKind: 'auth_bypass_probe',
    epistemicStatus: 'REFUTED',
    capabilityGained: 'none',
    outcome: 'refuted',
    evidence: {
      evidenceId: 'ev_a12_r1',
      reasonCode: 'target_blocked_auth_bypass',
      safeMessage: 'Target returned 401 and blocked unauthorized access',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
  });
  assert.equal(refutedChain.status, 'refuted');
  assert.equal(refutedChain.overallEpistemicStatus, 'REFUTED');

  // Store credential in vault — must NEVER appear in report serialization
  const credRef = postService.storeCredentialReference({
    credentialId: 'cred_a12_001',
    credentialKind: 'session_cookie',
    source: 'idor_session_capture',
    associatedHostname: 'example.com',
    discoveredAt: nowIso,
    secret: SECRET_MARKER,
  });
  await postService.recordAcquiredAccess({
    accessId: 'access_a12_001',
    assessmentId,
    scanId,
    accessKind: 'authenticated_session',
    description: 'Session handle acquired after verified differential read',
    epistemicStatus: 'VERIFIED',
    sourceStepId: 'step_a12_v2',
    sourceChainId: 'chain_a12_verified_001',
    credentialRefId: credRef.credentialId,
    newlyReachableTargets: [],
    acquiredAt: nowIso,
  });

  const plan: AttackPlan = {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: 'plan_a12_001',
    assessmentId,
    scanId,
    capability: 'idor_read_differential',
    title: 'IDOR differential validation',
    reasoning: 'Validate cross-identity read under human authorization.',
    status: 'authorized',
    blastRadius: 'single_endpoint',
    capabilityGained: 'read_escalated',
    sourceFindingIds: [],
    sourceFindingTypes: [],
    prerequisites: [],
    steps: [
      {
        stepId: 'plan_step_1',
        ordinal: 1,
        title: 'Differential read',
        description: 'Compare identity A vs B responses',
        status: 'completed',
        requiredPermissions: ['activeValidation'],
      },
    ],
    lineage,
    createdAt: nowIso,
    executable: false,
  };
  await planRepo.savePlan(plan);

  const postState = await postService.getSnapshot(assessmentId);
  const chains = await chainService.listByAssessmentId(assessmentId);

  // --- Test 1: Honest ImpactAssessment matching epistemic ---
  const impacts = impactService.deriveImpactAssessments({
    chains,
    postExploitationState: postState,
    assessedAt: nowIso,
  });
  assert.ok(impacts.length >= 3, 'Expected impact assessments for completed chains');
  for (const impact of impacts) {
    assert.ok(validateImpactAssessment(impact), 'ImpactAssessment must pass exact-key validation');
  }

  const verifiedImpact = impacts.find((i) => i.chainId === 'chain_a12_verified_001');
  const inferredImpact = impacts.find((i) => i.chainId === 'chain_a12_inferred_001');
  const refutedImpact = impacts.find((i) => i.chainId === 'chain_a12_refuted_001');
  assert.ok(verifiedImpact, 'Verified chain must produce impact assessment');
  assert.ok(inferredImpact, 'Inferred chain must produce impact assessment');
  assert.ok(refutedImpact, 'Refuted chain must produce impact assessment');
  assert.equal(verifiedImpact.epistemicStatus, 'VERIFIED');
  assert.equal(inferredImpact.epistemicStatus, 'INFERRED');
  assert.equal(refutedImpact.epistemicStatus, 'REFUTED');
  assert.equal(verifiedImpact.impactLevel, 'data_access');
  assert.equal(inferredImpact.impactLevel, 'information_exposure');
  assert.equal(refutedImpact.impactLevel, 'information_exposure');
  assert.equal(inferredChain.impactLevel, 'information_exposure');
  assert.equal(inferredChain.declaredImpactLevel, 'privilege_escalation');
  assert.equal(refutedChain.impactLevel, 'information_exposure');
  assert.ok(
    inferredImpact.impactDescription.includes('impact_confirmed') === true ||
      inferredImpact.impactDescription.includes('not verified') ||
      inferredImpact.impactDescription.includes('INFERRED'),
    'INFERRED high-impact assessment must not claim verified confirmation without gating language'
  );
  assert.ok(
    inferredImpact.impactDescription.includes('cannot be claimed as impact_confirmed') ||
      inferredImpact.impactDescription.includes('not verified'),
    'High-impact INFERRED chain must refuse impact_confirmed claim'
  );
  assert.ok(verifiedImpact.evidenceBasis.includes('ev_a12_v1'));
  assert.ok(verifiedImpact.evidenceBasis.includes('ev_a12_v2'));
  console.log('[+] Test 1: Completed chains produce honest ImpactAssessments matching epistemic');

  // --- Test 2+3: HTML adversarial sections + epistemic badges ---
  const record = buildRecord(assessmentId, scanId, lineage);
  const html = generateDefensiveHtmlReport({
    record,
    operatorId: 'operator_a12_lead',
    attestationText: 'Factual defensive assessment performed in authorized scope without synthetic data.',
    generatedAt: nowIso,
    adversarialContext: {
      attackPlans: [plan],
      attackChains: chains,
      impactAssessments: impacts,
      postExploitationState: postState,
      credentialReferences: [credRef],
    },
  });

  assert.ok(html.includes('Attack Execution Record'), 'Section 4 title must render');
  assert.ok(html.includes('Attack Chains &amp; Impact') || html.includes('Attack Chains & Impact'), 'Section 5 title must render');
  assert.ok(html.includes('Acquired Access &amp; Credentials') || html.includes('Acquired Access & Credentials'), 'Section 6 title must render');
  assert.ok(html.includes('Target Defenses (What Failed &amp; Resisted)') || html.includes('Target Defenses (What Failed & Resisted)'), 'Section 7 title must render');
  assert.ok(html.includes('Assessment Limitations (What Was Not Attempted)'), 'Section 8 title must render');
  assert.ok(html.includes('chain_a12_verified_001'), 'Verified chain id must appear');
  assert.ok(html.includes('cred_a12_001'), 'Credential reference id must appear');
  assert.ok(html.includes('session_cookie'), 'Credential kind must appear');
  assert.ok(html.includes('Target returned 401') || html.includes('refuted'), 'Refuted defense evidence must appear');

  assert.ok(html.includes('[VERIFIED]'), 'Epistemic badge [VERIFIED] must render');
  assert.ok(html.includes('[INFERRED - NOT VERIFIED]'), 'Epistemic badge [INFERRED - NOT VERIFIED] must render');
  assert.ok(html.includes('[REFUTED - TARGET RESISTED]'), 'Epistemic badge [REFUTED - TARGET RESISTED] must render');
  console.log('[+] Test 2: HTML renders adversarial sections');
  console.log('[+] Test 3: Epistemic labels explicitly present');

  // --- Test 4: Zero vault secrets in serialization ---
  assert.ok(!html.includes(SECRET_MARKER), 'HTML must not contain vault secret');
  const serializedRefs = JSON.stringify([credRef]);
  assert.ok(!serializedRefs.includes(SECRET_MARKER), 'CredentialReference JSON must not contain secret');
  const serializedImpacts = JSON.stringify(impacts);
  assert.ok(!serializedImpacts.includes(SECRET_MARKER), 'ImpactAssessment JSON must not contain secret');
  const serializedState = JSON.stringify(postState);
  assert.ok(!serializedState.includes(SECRET_MARKER), 'PostExploitationState JSON must not contain secret');
  console.log('[+] Test 4: Report serialization contains zero vault secret strings');

  // --- Integration: OrchestratedAssessmentApplicationService summary + report ---
  const orchRepo = new InMemoryOrchestratedAssessmentRepository();
  await orchRepo.save(record);
  const appService = new OrchestratedAssessmentApplicationService({
    repository: orchRepo,
    attackChainRepository: chainRepo,
    attackChainService: chainService,
    attackPlanRepository: planRepo,
    postExploitationRepository: postRepo,
    credentialVaultService: vault,
    postExploitationService: postService,
    impactAssessmentService: impactService,
  });

  const summary = await appService.getSummary(assessmentId);
  assert.ok(summary.impactAssessments && summary.impactAssessments.length >= 3);
  assert.ok(summary.attackChains && summary.attackChains.length >= 3);
  assert.ok(summary.credentialReferences && summary.credentialReferences.some((r) => r.credentialId === 'cred_a12_001'));
  assert.ok(!JSON.stringify(summary).includes(SECRET_MARKER), 'Summary JSON must not leak vault secret');

  const serviceHtml = await appService.generateHtmlReport(
    assessmentId,
    'operator_a12_lead',
    'Factual defensive assessment performed in authorized scope without synthetic data.',
    nowIso
  );
  assert.ok(serviceHtml.includes('[VERIFIED]'));
  assert.ok(serviceHtml.includes('[INFERRED - NOT VERIFIED]'));
  assert.ok(serviceHtml.includes('[REFUTED - TARGET RESISTED]'));
  assert.ok(!serviceHtml.includes(SECRET_MARKER));
  console.log('[+] Test 5: Application service summary + HTML report wired');

  // --- Composition root + controller surface ---
  const root = V2CompositionRoot.withDependencies({
    orchestratedRepository: orchRepo,
    orchestratedService: appService,
    attackChainRepository: chainRepo,
    attackChainService: chainService,
    attackPlanRepository: planRepo,
    postExploitationRepository: postRepo,
    credentialVaultService: vault,
    postExploitationService: postService,
    impactAssessmentService: impactService,
  });
  assert.ok(root.impactAssessmentService, 'Composition root must expose ImpactAssessmentService');

  const controller = new OrchestratedAssessmentController(appService);
  let summaryStatus = 0;
  let summaryBody: unknown = null;
  await controller.getSummary(
    { params: { assessmentId } } as unknown as Request,
    {
      status(code: number) {
        summaryStatus = code;
        return this;
      },
      json(body: unknown) {
        summaryBody = body;
        return this;
      },
    } as unknown as Response,
    ((err?: unknown) => {
      if (err) fail(`getSummary next error: ${String(err)}`);
    }) as NextFunction
  );
  assert.equal(summaryStatus, 200);
  assert.ok(summaryBody && typeof summaryBody === 'object');
  const bodyObj = summaryBody as { impactAssessments?: unknown[] };
  assert.ok(Array.isArray(bodyObj.impactAssessments) && bodyObj.impactAssessments.length >= 3);
  assert.ok(!JSON.stringify(summaryBody).includes(SECRET_MARKER));
  console.log('[+] Test 6: Summary route exposes impact assessments without secrets');

  console.log('=== Milestone A12 smoke suite PASSED ===');
}

runSmokeTests().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
