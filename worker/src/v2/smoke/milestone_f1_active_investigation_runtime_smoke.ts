/**
 * Etapa 2 · F1 — ActiveInvestigationRuntime consolidated smoke
 *
 * Verifies:
 * 1. Happy path: start → bind attack token → gate → record → complete
 * 2. Deny: lookalike / missing authorization brands fail closed
 * 3. Cancel / kill-switch blocks subsequent gates
 * 4. Request budget exceed fail-closed
 * 5. Investigation timeout fail-closed
 * 6. OrchestratedAssessment wiring + TargetExecutionCoordinator ceilings
 * 7. Investigation start never auto-executes AttackPlans
 * 8. Closed-loop: TestValidity gates VerificationState advance/refute on recordStepOutcome
 */

import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import { ATTACK_PLANNING_CONTRACT_VERSION } from '../attack-planning/AttackPlanContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import {
  ACTIVE_INVESTIGATION_CONTRACT_VERSION,
} from '../active-investigation/ActiveInvestigationContracts.js';
import {
  ActiveInvestigationRuntimeService,
  isRuntimeInvestigationAuthorizationBundle,
} from '../active-investigation/ActiveInvestigationRuntimeService.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION } from '../application/OrchestratedAssessmentContracts.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { Finding } from '../core/Evidence.js';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function assertTrue(condition: boolean, message: string): void {
  if (!condition) fail(message);
}

function createScopeGrant(host: string, scanId: string, grantId: string): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId,
    scanId,
    issuedAt: '2026-09-24T12:00:00.000Z',
    expiresAt: '2026-09-25T12:00:00.000Z',
    subject: {
      targetKind: 'origin',
      normalizedOrigin: `https://${host}`,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for F1 ActiveInvestigation smoke',
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
      allowedDomains: [host],
      allowedHosts: [host],
      allowedOrigins: [`https://${host}`],
      allowedMethods: ['GET', 'HEAD', 'POST'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: false,
      allowCredentialUse: true,
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

function buildPlan(planId: string, assessmentId: string, scanId: string): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId,
    assessmentId,
    scanId,
    capability: 'idor_read_differential',
    title: 'F1 advisory plan',
    reasoning: 'Hermetic plan for investigation runtime smoke — never auto-executed',
    status: 'ready_for_authorization',
    blastRadius: 'single_resource',
    capabilityGained: 'read_escalated',
    sourceFindingIds: ['fnd_f1_001'],
    sourceFindingTypes: ['BROKEN_ACCESS_CONTROL'],
    prerequisites: [],
    steps: [
      {
        stepId: 'step_f1_1',
        ordinal: 1,
        title: 'Advisory step',
        description: 'Not executed by F1 runtime',
        status: 'ready',
        requiredPermissions: ['active_http_get'],
      },
    ],
    targetUrl: 'https://app.example.com/api/resource/1',
    lineage: {
      assessmentId,
      scanId,
      authorizationGrantId: 'grn_f1_001',
      authorizationDecisionId: 'dec_f1_001',
      actorId: 'act_f1_operator',
    },
    createdAt: '2026-09-24T15:00:00.000Z',
    executable: false,
  };
}

async function runSmokeTests(): Promise<void> {
  console.log('=== Etapa 2 · F1: ActiveInvestigationRuntime Smoke Suite ===');

  const host = 'app.example.com';
  const assessmentId = 'asm_f1_001';
  const scanId = 'scn_f1_001';
  const grantId = 'grn_f1_001';
  const decisionId = 'dec_f1_001';
  const actorId = 'act_f1_operator';
  const planId = 'plan_f1_access_diff';
  const nowIso = '2026-09-24T15:00:00.000Z';
  const scopeGrant = createScopeGrant(host, scanId, grantId);

  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId,
      scanId,
      authorizationDecisionId: decisionId,
      authorizedActor: { actorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant,
    },
    nowIso
  );
  if (authRes.status !== 'established' || !authRes.decision) {
    fail(
      `must establish branded decision: ${authRes.status} ${'reasonCode' in authRes ? authRes.reasonCode : ''} ${'safeMessage' in authRes ? authRes.safeMessage : ''}`
    );
  }
  const decision = authRes.decision;

  const planRepo = new InMemoryAttackPlanRepository();
  await planRepo.savePlan(buildPlan(planId, assessmentId, scanId));
  const attackAuth = new AttackAuthorizationService(planRepo);
  const authTok = await attackAuth.authorizePlan(
    planId,
    assessmentId,
    'read_escalated',
    actorId,
    nowIso
  );
  assertTrue(authTok.status === 'established', 'must establish attack token');
  if (authTok.status !== 'established') fail('unreachable');
  const attackToken = authTok.token;

  // -------------------------------------------------------------------------
  // Test 1: Happy path
  // -------------------------------------------------------------------------
  {
    const runtime = new ActiveInvestigationRuntimeService();
    const started = runtime.startInvestigation({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'start_active_investigation_request',
      investigationId: 'inv_f1_happy',
      lineage: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId,
      },
      verifiedAuthorizationDecision: decision,
      budget: {
        maxRequests: 10,
        maxDurationMs: 60_000,
        maxConcurrentSteps: 1,
        requestsPerSecondCeiling: 5,
        maxConcurrencyCeiling: 2,
      },
      openHypothesisRefs: [planId],
      startedAt: nowIso,
    });
    assertTrue(started.status === 'started', 'happy start must succeed');
    if (started.status !== 'started') fail('unreachable');
    assertTrue(
      isRuntimeInvestigationAuthorizationBundle(started.authorizationBundle),
      'authorization bundle must be WeakSet-branded'
    );
    assertTrue(started.snapshot.status === 'running', 'snapshot must be running');
    assertTrue(
      started.snapshot.workingMemory.openHypothesisRefs.includes(planId),
      'open hypothesis refs preserved'
    );

    const bind = runtime.bindAttackAuthorization({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'bind_attack_authorization_request',
      investigationId: 'inv_f1_happy',
      attackAuthorizationToken: attackToken,
    });
    assertTrue(bind.status === 'bound', 'bind attack token must succeed');

    const gate = runtime.gateAuthorizedStep({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'gate_authorized_step_request',
      investigationId: 'inv_f1_happy',
      assessmentId,
      requireAttackAuthorization: true,
      planId,
      expectedRequestCost: 2,
      gatedAt: '2026-09-24T15:00:01.000Z',
    });
    assertTrue(gate.status === 'authorized', 'gate must authorize');
    if (gate.status !== 'authorized') fail('unreachable');

    const recorded = runtime.recordStepOutcome({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'record_investigation_step_request',
      investigationId: 'inv_f1_happy',
      stepId: 'step_f1_obs_1',
      requestCost: 2,
      producedFactIds: ['fact_f1_1'],
      recordedAt: '2026-09-24T15:00:02.000Z',
    });
    assertTrue(recorded.status === 'recorded', 'record must succeed');
    if (recorded.status !== 'recorded') fail('unreachable');
    assertTrue(recorded.snapshot.consumption.requestsConsumed === 2, 'budget consumption tracked');
    assertTrue(
      recorded.snapshot.workingMemory.executedStepIds.includes('step_f1_obs_1'),
      'executed step recorded in working memory'
    );

    const completed = runtime.completeInvestigation('inv_f1_happy', '2026-09-24T15:00:03.000Z');
    assertTrue(completed?.status === 'completed', 'investigation completes');
    console.log('[+] Test 1: happy path OK');
  }

  // -------------------------------------------------------------------------
  // Test 2: Deny lookalike authorization brands
  // -------------------------------------------------------------------------
  {
    const runtime = new ActiveInvestigationRuntimeService();
    const lookalike = {
      ...decision,
    };
    const denied = runtime.startInvestigation({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'start_active_investigation_request',
      investigationId: 'inv_f1_lookalike',
      lineage: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId,
      },
      verifiedAuthorizationDecision: lookalike as typeof decision,
      startedAt: nowIso,
    });
    assertTrue(denied.status === 'denied', 'lookalike decision must deny');
    if (denied.status !== 'denied') fail('unreachable');
    assertTrue(
      denied.reasonCode === 'authorization_brand_invalid',
      'lookalike must fail as authorization_brand_invalid'
    );

    const missing = runtime.startInvestigation({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'start_active_investigation_request',
      investigationId: 'inv_f1_missing',
      lineage: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId,
      },
      verifiedAuthorizationDecision: undefined as never,
      startedAt: nowIso,
    });
    assertTrue(missing.status === 'denied', 'missing decision must deny');
    console.log('[+] Test 2: authorization brand deny OK');
  }

  // -------------------------------------------------------------------------
  // Test 3: Cancel / kill-switch fail-closed
  // -------------------------------------------------------------------------
  {
    const runtime = new ActiveInvestigationRuntimeService();
    const started = runtime.startInvestigation({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'start_active_investigation_request',
      investigationId: 'inv_f1_cancel',
      lineage: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId,
      },
      verifiedAuthorizationDecision: decision,
      startedAt: nowIso,
    });
    assertTrue(started.status === 'started', 'cancel fixture start');

    const cancelled = runtime.cancelInvestigation({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'cancel_active_investigation_request',
      investigationId: 'inv_f1_cancel',
      operatorId: actorId,
      mode: 'kill_switch',
      cancelledAt: '2026-09-24T15:01:00.000Z',
    });
    assertTrue(cancelled.status === 'cancelled', 'kill-switch must cancel');
    if (cancelled.status !== 'cancelled') fail('unreachable');
    assertTrue(cancelled.reasonCode === 'kill_switch_engaged', 'kill_switch reason');
    assertTrue(cancelled.snapshot.killSwitchEngaged === true, 'killSwitchEngaged flag');

    const gate = runtime.gateAuthorizedStep({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'gate_authorized_step_request',
      investigationId: 'inv_f1_cancel',
      assessmentId,
      gatedAt: '2026-09-24T15:01:01.000Z',
    });
    assertTrue(gate.status === 'denied', 'post-kill-switch gate must deny');
    if (gate.status !== 'denied') fail('unreachable');
    assertTrue(gate.reasonCode === 'kill_switch_engaged', 'gate reason kill_switch_engaged');
    console.log('[+] Test 3: cancel/kill-switch fail-closed OK');
  }

  // -------------------------------------------------------------------------
  // Test 4: Budget exceed fail-closed
  // -------------------------------------------------------------------------
  {
    const runtime = new ActiveInvestigationRuntimeService();
    const started = runtime.startInvestigation({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'start_active_investigation_request',
      investigationId: 'inv_f1_budget',
      lineage: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId,
      },
      verifiedAuthorizationDecision: decision,
      budget: {
        maxRequests: 3,
        maxDurationMs: 60_000,
      },
      startedAt: nowIso,
    });
    assertTrue(started.status === 'started', 'budget fixture start');

    const gate1 = runtime.gateAuthorizedStep({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'gate_authorized_step_request',
      investigationId: 'inv_f1_budget',
      assessmentId,
      expectedRequestCost: 2,
      gatedAt: '2026-09-24T15:00:10.000Z',
    });
    assertTrue(gate1.status === 'authorized', 'first gate under budget');
    runtime.recordStepOutcome({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'record_investigation_step_request',
      investigationId: 'inv_f1_budget',
      stepId: 'step_budget_1',
      requestCost: 2,
      recordedAt: '2026-09-24T15:00:11.000Z',
    });

    const gate2 = runtime.gateAuthorizedStep({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'gate_authorized_step_request',
      investigationId: 'inv_f1_budget',
      assessmentId,
      expectedRequestCost: 2,
      gatedAt: '2026-09-24T15:00:12.000Z',
    });
    assertTrue(gate2.status === 'denied', 'over-budget gate must deny');
    if (gate2.status !== 'denied') fail('unreachable');
    assertTrue(gate2.reasonCode === 'budget_exceeded', 'budget_exceeded reason');
    assertTrue(gate2.snapshot?.status === 'budget_exceeded', 'terminal budget_exceeded status');
    console.log('[+] Test 4: budget exceed fail-closed OK');
  }

  // -------------------------------------------------------------------------
  // Test 5: Timeout fail-closed
  // -------------------------------------------------------------------------
  {
    const runtime = new ActiveInvestigationRuntimeService();
    const started = runtime.startInvestigation({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'start_active_investigation_request',
      investigationId: 'inv_f1_timeout',
      lineage: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId,
      },
      verifiedAuthorizationDecision: decision,
      budget: {
        maxRequests: 50,
        maxDurationMs: 1_000,
      },
      startedAt: '2026-09-24T15:00:00.000Z',
    });
    assertTrue(started.status === 'started', 'timeout fixture start');

    const gate = runtime.gateAuthorizedStep({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'gate_authorized_step_request',
      investigationId: 'inv_f1_timeout',
      assessmentId,
      gatedAt: '2026-09-24T15:00:02.000Z',
    });
    assertTrue(gate.status === 'denied', 'timed-out gate must deny');
    if (gate.status !== 'denied') fail('unreachable');
    assertTrue(gate.reasonCode === 'timed_out', 'timed_out reason');
    console.log('[+] Test 5: timeout fail-closed OK');
  }

  // -------------------------------------------------------------------------
  // Test 6: OrchestratedAssessment wiring + coordinator ceilings
  // -------------------------------------------------------------------------
  {
    const repo = new InMemoryOrchestratedAssessmentRepository();
    const liveNow = new Date().toISOString();
    await repo.save({
      contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
      assessmentId,
      scanId,
      targetDomain: host,
      status: 'completed',
      lineage: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId,
      },
      stages: [],
      timing: { startedAt: liveNow, completedAt: liveNow, durationMs: 100 },
      errorCount: 0,
      warningCount: 0,
      findings: [],
      pendingEvidenceDrafts: [],
      recommendations: [],
    });

    const app = new OrchestratedAssessmentApplicationService({ repository: repo });
    app.registerRuntimeVerifiedAuthorizationDecision(assessmentId, decision);

    const started = await app.startActiveInvestigation({
      assessmentId,
      investigationId: 'inv_f1_orch',
      budget: {
        maxRequests: 5,
        maxDurationMs: 60_000,
        requestsPerSecondCeiling: 5,
        maxConcurrencyCeiling: 2,
      },
      openHypothesisRefs: [planId],
      startedAt: liveNow,
    });
    assertTrue(started.status === 'started', 'orchestrated start must succeed');

    const { gate, coordinator } = app.gateAttackExecutionUnderInvestigation({
      assessmentId,
      investigationId: 'inv_f1_orch',
      planId,
      attackAuthorizationToken: attackToken,
      expectedRequestCost: 1,
      targetHost: host,
    });
    assertTrue(gate.status === 'authorized', 'orchestrated gate must authorize');
    assertTrue(coordinator instanceof TargetExecutionCoordinator, 'coordinator returned');
    assertTrue(coordinator !== null, 'coordinator non-null');

    // Ceilings applied — host stats exist after setHostQuota; verify via bind path.
    const bound = app
      .getActiveInvestigationRuntime()
      .bindCoordinatorCeilings({
        investigationId: 'inv_f1_orch',
        coordinator: coordinator!,
        host,
      });
    assertTrue(bound === true, 'coordinator ceilings bound');

    app.recordInvestigationExecutionStep({
      investigationId: 'inv_f1_orch',
      stepId: 'step_orch_1',
      requestCost: 1,
    });

    const snap = app.getActiveInvestigationSnapshot(assessmentId, 'inv_f1_orch');
    assertTrue(snap?.consumption.requestsConsumed === 1, 'orchestrated consumption tracked');
    assertTrue(snap?.status === 'running', 'investigation still running after record');

    // Cancel blocks further execute gates
    const cancelled = app.cancelActiveInvestigation({
      assessmentId,
      investigationId: 'inv_f1_orch',
      operatorId: actorId,
      mode: 'cancel',
    });
    if (cancelled.status !== 'cancelled') {
      fail(
        `orchestrated cancel: ${cancelled.status} ${cancelled.reasonCode} ${cancelled.safeMessage}`
      );
    }

    const blocked = app.gateAttackExecutionUnderInvestigation({
      assessmentId,
      investigationId: 'inv_f1_orch',
      planId,
      attackAuthorizationToken: attackToken,
    });
    assertTrue(blocked.gate.status === 'denied', 'cancelled investigation blocks execute gate');
    console.log('[+] Test 6: orchestrated wiring + ceilings OK');
  }

  // -------------------------------------------------------------------------
  // Test 7: Start investigation never auto-executes plans
  // -------------------------------------------------------------------------
  {
    const runtime = new ActiveInvestigationRuntimeService();
    const started = runtime.startInvestigation({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'start_active_investigation_request',
      investigationId: 'inv_f1_no_auto',
      lineage: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId,
      },
      verifiedAuthorizationDecision: decision,
      openHypothesisRefs: [planId],
      attackAuthorizationToken: attackToken,
      startedAt: nowIso,
    });
    assertTrue(started.status === 'started', 'start with bound token still does not execute');
    if (started.status !== 'started') fail('unreachable');
    assertTrue(
      started.snapshot.workingMemory.executedStepIds.length === 0,
      'no executed steps on start'
    );
    assertTrue(
      started.snapshot.consumption.requestsConsumed === 0,
      'no request consumption on start'
    );
    assertTrue(
      started.authorizationBundle.hasAttackAuthorizationToken === true,
      'token may be bound without executing'
    );
    console.log('[+] Test 7: no auto-execute OK');
  }

  // -------------------------------------------------------------------------
  // Test 8: Closed-loop TestValidity → VerificationState on recordStepOutcome
  // -------------------------------------------------------------------------
  {
    const runtime = new ActiveInvestigationRuntimeService();
    const finding: Finding = Object.freeze({
      id: 'fnd_f1_loop_001',
      type: 'BROKEN_ACCESS_CONTROL',
      severity: 'high',
      title: 'F1 closed-loop finding',
      description: 'Hermetic finding for validity-gated state mutation',
      target: 'https://app.example.com/api/resource/1',
      evidence: 'hermetic',
      confidence: 1,
      verificationState: 'observed_anomaly',
      metadata: {
        kind: 'broken_access_control_metadata' as const,
        category: 'BROKEN_ACCESS_CONTROL' as const,
        candidateId: 'cand_f1_loop',
        evidenceRecordId: 'evr_f1_loop',
        lineage: {},
        endpointUrl: 'https://app.example.com/api/resource/1',
      },
    });

    const started = runtime.startInvestigation({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'start_active_investigation_request',
      investigationId: 'inv_f1_validity',
      lineage: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId,
      },
      verifiedAuthorizationDecision: decision,
      startedAt: nowIso,
    });
    assertTrue(started.status === 'started', 'validity-loop investigation must start');

    const advanced = runtime.recordStepOutcome({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'record_investigation_step_request',
      investigationId: 'inv_f1_validity',
      stepId: 'step_f1_valid_ok',
      requestCost: 1,
      recordedAt: '2026-09-24T15:01:01.000Z',
      stepOutcome: 'succeeded',
      outcomeReasonCode: 'idor_differential_access_observed',
      boundFinding: finding,
      evidenceId: 'ev_f1_adv_001',
      targetHost: 'app.example.com',
    });
    assertTrue(advanced.status === 'recorded', 'valid succeed must record');
    if (advanced.status !== 'recorded') fail('unreachable');
    assertTrue(advanced.reasonCode === 'step_recorded', 'must not time out before closed-loop');
    assertTrue(advanced.testValidityVerdict === 'valid', 'clean reason → valid');
    assertTrue(advanced.verificationMutation === 'advanced', 'valid succeed must advance');
    assertTrue(
      advanced.updatedFinding?.verificationState === 'suspected_vulnerability',
      'must advance one ladder step'
    );
    assertTrue(
      finding.verificationState === 'observed_anomaly',
      'original finding must remain immutable'
    );

    const wafBlocked = runtime.recordStepOutcome({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'record_investigation_step_request',
      investigationId: 'inv_f1_validity',
      stepId: 'step_f1_waf',
      requestCost: 1,
      recordedAt: '2026-09-24T15:01:02.000Z',
      stepOutcome: 'succeeded',
      outcomeReasonCode: 'cloudflare_waf_challenge_blocked',
      boundFinding: advanced.updatedFinding!,
      evidenceId: 'ev_f1_waf_001',
    });
    assertTrue(wafBlocked.status === 'recorded', 'waf outcome must still record step');
    if (wafBlocked.status !== 'recorded') fail('unreachable');
    assertTrue(wafBlocked.testValidityVerdict === 'interfered', 'waf → interfered');
    assertTrue(
      wafBlocked.verificationMutation === 'skipped_interference',
      'interfered must not mutate verification state'
    );
    assertTrue(
      wafBlocked.updatedFinding?.verificationState === 'suspected_vulnerability',
      'WAF block must not advance or refute'
    );

    const refuted = runtime.recordStepOutcome({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'record_investigation_step_request',
      investigationId: 'inv_f1_validity',
      stepId: 'step_f1_refute',
      requestCost: 1,
      recordedAt: '2026-09-24T15:01:03.000Z',
      stepOutcome: 'refuted',
      outcomeReasonCode: 'access_denied_no_differential',
      boundFinding: advanced.updatedFinding!,
      evidenceId: 'ev_f1_ref_001',
    });
    assertTrue(refuted.status === 'recorded', 'valid refute must record');
    if (refuted.status !== 'recorded') fail('unreachable');
    assertTrue(refuted.testValidityVerdict === 'valid', 'clean refute → valid');
    assertTrue(refuted.verificationMutation === 'refuted', 'valid refute mutates via refuteState');
    assertTrue(
      refuted.updatedFinding?.verificationState === 'suspected_vulnerability',
      'same-state refute holds ladder position'
    );
    console.log('[+] Test 8: validity-gated state loop OK');
  }

  console.log('=== F1 ActiveInvestigationRuntime smoke: ALL PASSED ===');
}

runSmokeTests().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
