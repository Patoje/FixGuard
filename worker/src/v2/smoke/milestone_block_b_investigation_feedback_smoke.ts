/**
 * FixGuard V2 — Block B Consolidated Smoke Test Suite
 * Investigation Runtime Activation & Hypothesis Feedback
 *
 * Verifies all 12 Block B requirements:
 * Test A — Hypothesis creation from observations (anon/auth diff, surfaces)
 * Test B — Deterministic hypothesis prioritization & explainable scoring
 * Test C — Investigation plan generation (bounded, explicit contracts)
 * Test D — Execution result updates hypothesis state (candidate → supported)
 * Test E — Invalid test (WAF/challenge interference cannot confirm hypothesis)
 * Test F — Negative evidence refutes/deprioritizes hypothesis
 * Test G — New surface discovery generates next candidate hypothesis
 * Test H — Request budget termination (bounded, zero infinite loops)
 * Test I — Structural route deduplication (e.g. /api/orders/1 vs 2)
 * Test J — Context separation & missing context gating (inconclusive / blocked)
 * Test K — Existing read-detection compatibility
 * Test L — Full canonical runtime composition test
 */

import assert from 'node:assert/strict';
import process from 'node:process';

process.env.FIXGUARD_DISABLE_DEV_CACHE = '1';
process.env.FIXGUARD_V2_HERMETIC_RECON = '1';

import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { ProbeInventory } from '../investigation/ProbeInventoryContracts.js';
import { PROBE_INVENTORY_CONTRACT_VERSION } from '../investigation/ProbeInventoryContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { AttackPlanGeneratorService } from '../attack-planning/AttackPlanGeneratorService.js';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import {
  generateHypothesesFromObservations,
  normalizeStructuralRoute,
  scoreHypothesis,
  scheduleNextInvestigation,
  applyInvestigationFeedback,
} from '../investigation/InvestigationHypothesisScheduler.js';
import type { SecurityHypothesis } from '../hypothesis-scheduler/HypothesisSchedulerContracts.js';
import { evaluateTestValidity } from '../test-validity/TestValidityService.js';
import { runReadInvestigationLoop } from '../investigation/ReadInvestigationLoop.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import {
  ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
  type OrchestratedAssessmentRecord,
} from '../application/OrchestratedAssessmentContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackPlan,
  type AttackCapabilityKind,
} from '../attack-planning/AttackPlanContracts.js';

const HOST = 'api.example.com';
const ACTOR = 'act_block_b_op';
const SCAN = 'scan_block_b_001';
const GRANT = 'grant_block_b_001';
const DECISION = 'dec_block_b_001';
const ASSESSMENT = 'asmt_block_b_001';

function createScopeGrant(): AuthorizedScopeGrant {
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
      authorizationText: 'Authorized Block B investigation smoke test',
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
      allowLoginRequiredAreas: true,
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

function createLineage(): AuthorizedActiveReconRequestLineage {
  return {
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    authorizationGrantId: GRANT,
    authorizationDecisionId: DECISION,
    actorId: ACTOR,
  };
}

function createVerifiedDecision() {
  const grant = createScopeGrant();
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
    throw new Error(`Failed to establish verified decision: ${authRes.reasonCode}`);
  }
  return authRes.decision;
}

function createProbeInventory(entries: Array<{ path: string; method?: string; parameters?: readonly string[] }>): ProbeInventory {
  return {
    contractVersion: PROBE_INVENTORY_CONTRACT_VERSION,
    kind: 'probe_inventory',
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    authorizationGrantId: GRANT,
    authorizationDecisionId: DECISION,
    actorId: ACTOR,
    entries: entries.map((e) => ({
      origin: `https://${HOST}`,
      path: e.path,
      method: e.method ?? 'GET',
      parameters: e.parameters ?? [],
      sources: ['web_inspection'],
    })),
  };
}

function createTestCapabilityRegistry(transport: (request: HttpProbeRequest) => Promise<HttpProbeResponse>): AttackCapabilityRegistry {
  const ports = AttackCapabilityRegistry.createDefault();
  const probeCapabilities: AttackCapabilityKind[] = [
    'security_header_probe',
    'auth_boundary_differential',
    'auth_bypass_probe',
    'graphql_surface_probe',
    'cors_misconfiguration_probe',
    'open_redirect_probe',
    'information_disclosure_probe',
    'idor_read_differential',
  ];
  for (const capability of probeCapabilities) {
    ports.register({
      capability,
      async execute(ctx) {
        const hop = ctx.transport ?? transport;
        const resp = await hop({
          url: ctx.targetUrl,
          method: 'GET',
          headers: { accept: 'application/json' },
        });
        const isRefuted = resp.statusCode === 403;
        return {
          outcome: isRefuted ? 'refuted' : 'observed',
          reasonCode: isRefuted ? 'access_control_enforced' : 'hermetic_probe_observed',
          safeMessage: isRefuted ? 'Access control enforced on endpoint' : 'Hermetic read observed',
        };
      },
    });
  }
  return ports;
}

async function runBlockBSmokeSuite(): Promise<void> {
  console.log('>>> RUNNING FIXGUARD V2 BLOCK B CONSOLIDATED SMOKE SUITE <<<\n');
  const nowIso = new Date().toISOString();
  const decision = createVerifiedDecision();

  // =========================================================================
  // Test A — Hypothesis Creation from Observations
  // =========================================================================
  console.log('[+] Test A: Hypothesis Creation from Real Observations...');
  {
    const inventory = createProbeInventory([
      { path: '/api/v1/orders/123', parameters: ['orderId'] },
      { path: '/graphql' },
    ]);
    const findings: Finding[] = [
      {
        id: 'fnd_diff_01',
        type: 'BROKEN_ACCESS_CONTROL',
        severity: 'high',
        title: 'Auth Boundary Mismatch',
        description: 'Anonymous returned 401, authenticated returned 200',
        target: HOST,
        evidence: 'diff observed',
        confidence: 0.8,
        verificationState: 'observed_anomaly',
        metadata: {
          kind: 'discovery_finding_metadata',
          endpointUrl: `https://${HOST}/api/v1/orders/123`,
        },
      },
    ];

    const hypotheses = generateHypothesesFromObservations({
      assessmentId: ASSESSMENT,
      scanId: SCAN,
      targetDomain: HOST,
      probeInventory: inventory,
      findings,
      sessionContext: {
        hasAuthenticatedContext: true,
        hasSecondaryAuthenticatedContext: false,
        hasJwt: false,
      },
      nowIso,
    });

    assert.ok(hypotheses.length >= 2, 'Should generate at least order differential and graphql hypotheses');
    const orderHyp = hypotheses.find((h) => h.suggestedCapability === 'auth_boundary_differential');
    assert.ok(orderHyp, 'auth_boundary_differential hypothesis must exist');
    assert.equal(orderHyp.state, 'candidate');
    assert.ok(orderHyp.normalizedRoutePattern?.includes('/api/v1/orders/{id}'));
    assert.equal(orderHyp.targetUrl, `https://${HOST}/api/v1/orders/123`);
    assert.ok((orderHyp.supportingEvidence?.length ?? 0) >= 1, 'Must carry originating evidence');
    console.log('  [PASS] Test A: Hypotheses successfully generated from real observations.');
  }

  // =========================================================================
  // Test B — Deterministic Hypothesis Prioritization
  // =========================================================================
  console.log('[+] Test B: Deterministic Hypothesis Prioritization & Scoring...');
  {
    const h1: SecurityHypothesis = {
      contractVersion: 'fixguard-hypothesis-scheduler/v0',
      kind: 'security_hypothesis',
      hypothesisId: 'hyp_low_evidence',
      hypothesisKind: 'parameter_reflection',
      title: 'Info disclosure hypothesis',
      epistemicStatus: 'OBSERVED',
      score: 50,
      blocked: false,
      blockReason: 'none',
      rationale: 'Passive header note',
      suggestedCapability: 'information_disclosure_probe',
      sourceFindingIds: [],
      targetUrl: `https://${HOST}/about`,
      normalizedRoutePattern: '/about',
      state: 'candidate',
      investigationCount: 0,
      supportingEvidence: ['single passive header'],
      contradictingEvidence: [],
      explanation: [],
    };

    const h2: SecurityHypothesis = {
      contractVersion: 'fixguard-hypothesis-scheduler/v0',
      kind: 'security_hypothesis',
      hypothesisId: 'hyp_strong_auth',
      hypothesisKind: 'auth_boundary_differential',
      title: 'Parameterized order auth differential',
      epistemicStatus: 'OBSERVED',
      score: 85,
      blocked: false,
      blockReason: 'none',
      rationale: 'Active 401 unauth vs 200 auth observed',
      suggestedCapability: 'auth_boundary_differential',
      sourceFindingIds: ['fnd_diff_01'],
      targetUrl: `https://${HOST}/api/orders/ord_123`,
      normalizedRoutePattern: '/api/orders/{id}',
      parameterName: 'orderId',
      state: 'candidate',
      investigationCount: 0,
      supportingEvidence: ['Differential observed between auth and unauth'],
      contradictingEvidence: [],
      dependencies: {
        requiresAuth: true,
        requiresSecondaryAuth: false,
        requiresParameter: true,
        satisfied: true,
        blockReason: 'none',
      },
      explanation: [],
    };

    const h3: SecurityHypothesis = {
      contractVersion: 'fixguard-hypothesis-scheduler/v0',
      kind: 'security_hypothesis',
      hypothesisId: 'hyp_already_refuted',
      hypothesisKind: 'auth_bypass',
      title: 'Refuted bypass hypothesis',
      epistemicStatus: 'OBSERVED',
      score: 0,
      blocked: false,
      blockReason: 'none',
      rationale: 'Tested and proven safe',
      suggestedCapability: 'auth_bypass_probe',
      sourceFindingIds: [],
      targetUrl: `https://${HOST}/api/secure`,
      normalizedRoutePattern: '/api/secure',
      state: 'refuted',
      investigationCount: 1,
      supportingEvidence: [],
      contradictingEvidence: ['403 returned across all contexts'],
      explanation: [],
    };

    const scheduled = scheduleNextInvestigation([h1, h2, h3], {
      identityCount: 1,
      hasJwt: false,
      nowIso,
    });

    assert.ok(scheduled !== null, 'Scheduler must pick an actionable hypothesis');
    assert.equal(scheduled.selectedHypothesis.hypothesisId, 'hyp_strong_auth', 'Scheduler must prioritize H2');
    assert.ok(scheduled.selectedHypothesis.score >= 80, 'Score should be high for auth differential');
    const reasons = scheduled.selectedHypothesis.explanation ?? [];
    assert.ok(reasons.length >= 1, 'Must include explainable scoring reasons');
    assert.ok(reasons.some((r) => r.includes('authorization boundary') || r.includes('Parameterized')));

    // Refuted hypothesis score must be 0
    const scoredH3 = scoreHypothesis(h3, { identityCount: 1, hasJwt: false });
    assert.equal(scoredH3.score, 0, 'Refuted hypothesis must receive a score of 0');
    console.log(`  [PASS] Test B: Prioritization deterministically selected H2 (score: ${scheduled.selectedHypothesis.score}).`);
  }

  // =========================================================================
  // Test C — Investigation Plan
  // =========================================================================
  console.log('[+] Test C: Investigation Plan Generation...');
  {
    const hyp: SecurityHypothesis = {
      contractVersion: 'fixguard-hypothesis-scheduler/v0',
      kind: 'security_hypothesis',
      hypothesisId: 'hyp_plan_test',
      hypothesisKind: 'auth_boundary_differential',
      title: 'Auth differential plan test',
      epistemicStatus: 'OBSERVED',
      score: 85,
      blocked: false,
      blockReason: 'none',
      rationale: 'Verify plan contract',
      suggestedCapability: 'auth_boundary_differential',
      sourceFindingIds: ['fnd_01'],
      targetUrl: `https://${HOST}/api/v1/users/me`,
      normalizedRoutePattern: '/api/v1/users/{id}',
      state: 'candidate',
      investigationCount: 0,
      supportingEvidence: ['Observation diff'],
      contradictingEvidence: [],
      dependencies: {
        requiresAuth: true,
        requiresSecondaryAuth: false,
        requiresParameter: false,
        satisfied: true,
        blockReason: 'none',
      },
      explanation: [],
    };

    const scheduled = scheduleNextInvestigation([hyp], {
      identityCount: 1,
      hasJwt: false,
      nowIso,
    });

    assert.ok(scheduled);
    const plan = scheduled.plan;
    assert.equal(plan.capability, 'auth_boundary_differential');
    assert.equal(plan.targetUrl, `https://${HOST}/api/v1/users/me`);
    assert.equal(plan.contextKind, 'authenticated');
    assert.equal(plan.method, 'GET');
    assert.equal(plan.requestCost, 1);
    assert.equal(plan.safetyLevel, 'read_only');
    assert.ok(plan.expectedObservation.length > 0);
    console.log('  [PASS] Test C: Explicit, bounded investigation plan generated.');
  }

  // =========================================================================
  // Test D — Execution Result Updates Hypothesis State (Supported)
  // =========================================================================
  console.log('[+] Test D: Execution Result Feedback (candidate → supported)...');
  {
    const hyp: SecurityHypothesis = {
      contractVersion: 'fixguard-hypothesis-scheduler/v0',
      kind: 'security_hypothesis',
      hypothesisId: 'hyp_feed_d',
      hypothesisKind: 'auth_boundary_differential',
      title: 'Order differential test',
      epistemicStatus: 'OBSERVED',
      score: 70,
      blocked: false,
      blockReason: 'none',
      rationale: 'Test feedback state update',
      suggestedCapability: 'auth_boundary_differential',
      sourceFindingIds: [],
      targetUrl: `https://${HOST}/api/orders/ord_100`,
      normalizedRoutePattern: '/api/orders/{id}',
      state: 'candidate',
      investigationCount: 0,
      supportingEvidence: [],
      contradictingEvidence: [],
      explanation: [],
    };

    const feedbackResult = applyInvestigationFeedback(hyp, {
      contractVersion: 'fixguard-investigation-feedback/v0',
      kind: 'investigation_execution_result',
      planId: 'plan_feed_d',
      hypothesisId: hyp.hypothesisId,
      targetUrl: hyp.targetUrl!,
      executedAt: nowIso,
      status: 'completed',
      statusCode: 200,
      testValidityVerdict: 'valid',
      outcome: 'supported',
      reasonCode: 'differential_observed',
      safeEvidenceMessage: 'Differential confirmed: 200 authenticated vs 401 unauthenticated',
    });

    assert.equal(feedbackResult.updatedHypothesis.state, 'supported');
    assert.equal(feedbackResult.updatedHypothesis.investigationCount, 1);
    assert.ok((feedbackResult.updatedHypothesis.supportingEvidence?.length ?? 0) >= 1);
    assert.equal(feedbackResult.stepRecord.outcome, 'supported');
    console.log('  [PASS] Test D: Valid observation transitioned hypothesis to "supported".');
  }

  // =========================================================================
  // Test E — Invalid Result via WAF / Transport Interference
  // =========================================================================
  console.log('[+] Test E: Invalid Result Gating (WAF interference must NOT confirm)...');
  {
    const hyp: SecurityHypothesis = {
      contractVersion: 'fixguard-hypothesis-scheduler/v0',
      kind: 'security_hypothesis',
      hypothesisId: 'hyp_feed_e',
      hypothesisKind: 'auth_boundary_differential',
      title: 'Protected API test',
      epistemicStatus: 'OBSERVED',
      score: 75,
      blocked: false,
      blockReason: 'none',
      rationale: 'Verify WAF interference handling',
      suggestedCapability: 'auth_boundary_differential',
      sourceFindingIds: [],
      targetUrl: `https://${HOST}/api/orders/ord_waf`,
      normalizedRoutePattern: '/api/orders/{id}',
      state: 'candidate',
      investigationCount: 0,
      supportingEvidence: [],
      contradictingEvidence: [],
      explanation: [],
    };

    // WAF 403 test validity evaluation
    const validity = evaluateTestValidity({
      probe: {
        statusCode: 403,
        headerValues: { 'cf-ray': '12345', server: 'cloudflare' },
        targetHost: HOST,
      },
      observedAt: nowIso,
    });
    assert.equal(validity.verdict, 'interfered', 'WAF challenge must evaluate to interfered');

    const feedbackResult = applyInvestigationFeedback(hyp, {
      contractVersion: 'fixguard-investigation-feedback/v0',
      kind: 'investigation_execution_result',
      planId: 'plan_feed_e',
      hypothesisId: hyp.hypothesisId,
      targetUrl: hyp.targetUrl!,
      executedAt: nowIso,
      status: 'completed',
      statusCode: 403,
      testValidityVerdict: validity.verdict,
      outcome: 'inconclusive',
      reasonCode: 'waf_or_challenge_interfered',
      safeEvidenceMessage: 'WAF/edge challenge interfered with probe; cannot claim application denial',
    });

    assert.equal(feedbackResult.updatedHypothesis.state, 'inconclusive');
    assert.notEqual(feedbackResult.updatedHypothesis.state, 'supported');
    assert.notEqual(feedbackResult.updatedHypothesis.state, 'validated');
    console.log('  [PASS] Test E: WAF challenge cleanly routed to "inconclusive" without false confirmation.');
  }

  // =========================================================================
  // Test F — Negative Evidence Refutes / Deprioritizes Hypothesis
  // =========================================================================
  console.log('[+] Test F: Negative Evidence Refutation & Deprioritization...');
  {
    const hyp: SecurityHypothesis = {
      contractVersion: 'fixguard-hypothesis-scheduler/v0',
      kind: 'security_hypothesis',
      hypothesisId: 'hyp_feed_f',
      hypothesisKind: 'auth_bypass',
      title: 'Suspected bypass',
      epistemicStatus: 'OBSERVED',
      score: 60,
      blocked: false,
      blockReason: 'none',
      rationale: 'Testing refutation logic',
      suggestedCapability: 'auth_bypass_probe',
      sourceFindingIds: [],
      targetUrl: `https://${HOST}/admin`,
      normalizedRoutePattern: '/admin',
      state: 'candidate',
      investigationCount: 0,
      supportingEvidence: [],
      contradictingEvidence: [],
      explanation: [],
    };

    const feedbackResult = applyInvestigationFeedback(hyp, {
      contractVersion: 'fixguard-investigation-feedback/v0',
      kind: 'investigation_execution_result',
      planId: 'plan_feed_f',
      hypothesisId: hyp.hypothesisId,
      targetUrl: hyp.targetUrl!,
      executedAt: nowIso,
      status: 'completed',
      statusCode: 403,
      testValidityVerdict: 'valid',
      outcome: 'refuted',
      reasonCode: 'access_control_enforced',
      safeEvidenceMessage: 'Target returned strictly enforced 403 across all attempted mutations',
    });

    assert.equal(feedbackResult.updatedHypothesis.state, 'refuted');
    assert.ok((feedbackResult.updatedHypothesis.contradictingEvidence?.length ?? 0) >= 1);

    // Ensure scheduler gives refuted hypothesis 0 priority
    const scored = scoreHypothesis(feedbackResult.updatedHypothesis, {
      identityCount: 1,
      hasJwt: false,
    });
    assert.equal(scored.score, 0);
    assert.ok(scored.explanation.some((r) => r.toLowerCase().includes('refuted')));
    console.log('  [PASS] Test F: Negative evidence properly refuted and zeroed out hypothesis score.');
  }

  // =========================================================================
  // Test G — New Surface Discovery Generates Next Candidate
  // =========================================================================
  console.log('[+] Test G: Dynamic Surface Discovery & Candidate Enqueueing...');
  {
    const initialInventory = createProbeInventory([{ path: '/health' }]);
    const initialHypotheses = generateHypothesesFromObservations({
      assessmentId: ASSESSMENT,
      scanId: SCAN,
      targetDomain: HOST,
      probeInventory: initialInventory,
      findings: [],
      sessionContext: { hasAuthenticatedContext: true, hasSecondaryAuthenticatedContext: false, hasJwt: false },
      nowIso,
    });

    assert.equal(initialHypotheses.length, 0, 'No security hypotheses on plain health check');

    // Dynamically discovered finding during investigation
    const discoveredFinding: Finding = {
      id: 'fnd_discovered_01',
      type: 'DISCOVERY',
      severity: 'info',
      title: 'Discovered parameterized endpoint',
      description: 'Found /api/documents/doc_442 in response body',
      target: HOST,
      evidence: 'response_body',
      confidence: 1,
      verificationState: 'observed_anomaly',
      metadata: {
        kind: 'discovery_finding_metadata',
        endpointUrl: `https://${HOST}/api/documents/doc_442`,
      },
    };

    const updatedHypotheses = generateHypothesesFromObservations({
      assessmentId: ASSESSMENT,
      scanId: SCAN,
      targetDomain: HOST,
      probeInventory: createProbeInventory([{ path: '/health' }, { path: '/api/documents/doc_442' }]),
      findings: [discoveredFinding],
      sessionContext: { hasAuthenticatedContext: true, hasSecondaryAuthenticatedContext: false, hasJwt: false },
      nowIso,
    });

    assert.ok(updatedHypotheses.length >= 1);
    const newHyp = updatedHypotheses[0];
    assert.ok(newHyp.normalizedRoutePattern?.includes('/api/documents/{id}'));
    assert.equal(newHyp.state, 'candidate');
    console.log('  [PASS] Test G: Newly discovered surface successfully materialized candidate hypothesis.');
  }

  // =========================================================================
  // Test H — Bounded Request Budget Termination
  // =========================================================================
  console.log('[+] Test H: Deterministic Budget Termination (Bounded Steps)...');
  {
    const plansRepo = new InMemoryAttackPlanRepository();
    const probeRequests: string[] = [];
    const mockTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      probeRequests.push(req.url);
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: '{"status":"ok"}',
        responseTimeMs: 2,
      };
    };

    // Invariant: Zero plans pre-seeded in repository. Dynamic generation required!
    const result = await runReadInvestigationLoop({
      assessmentId: ASSESSMENT,
      lineage: createLineage(),
      verifiedAuthorizationDecision: decision,
      scopeGrant: createScopeGrant(),
      coordinator: new TargetExecutionCoordinator({ requestsPerSecond: 10, maxConcurrency: 2 }),
      dnsResolver: async () => ['93.184.216.34'],
      transport: mockTransport,
      circuitHost: HOST,
      findings: [],
      probeInventory: createProbeInventory([
        { path: '/api/v1/orders/101' },
        { path: '/api/v1/users/usr_201' },
        { path: '/graphql' },
      ]),
      planRepository: plansRepo,
      planGenerator: new AttackPlanGeneratorService(),
      authorizationService: new AttackAuthorizationService(plansRepo),
      executionService: new AttackExecutionService({
        planRepository: plansRepo,
        capabilityRegistry: createTestCapabilityRegistry(mockTransport),
      }),
      primaryIdentity: { identityId: 'session_primary' },
      identities: [{ identityId: 'session_primary', hasJwt: false }],
      recordOutcome: async () => {},
      stepBudget: 2, // Explicitly limit to 2 steps
    });

    assert.equal(result.record.stopReason, 'step_budget_exhausted');
    assert.equal(result.record.stepsExecuted, 2);
    assert.equal(probeRequests.length, 2, 'Must not execute more requests than the step budget allows');
    assert.equal(result.feedbackSteps.length, 2, 'Must record exactly 2 feedback steps');
    console.log('  [PASS] Test H: Real hypothesis-driven loop terminated strictly at stepBudget = 2.');
  }

  // =========================================================================
  // Test I — Structural Route Deduplication
  // =========================================================================
  console.log('[+] Test I: Structural Route Deduplication...');
  {
    const normalized1 = normalizeStructuralRoute('/api/orders/ord_123');
    const normalized2 = normalizeStructuralRoute('/api/orders/ord_999');
    const normalized3 = normalizeStructuralRoute('/api/users/usr_abc/items/item_9');

    assert.equal(normalized1.normalizedPattern, '/api/orders/{id}');
    assert.equal(normalized2.normalizedPattern, '/api/orders/{id}');
    assert.equal(normalized3.normalizedPattern, '/api/users/{id}/items/{id}');

    const inventory = createProbeInventory([
      { path: '/api/orders/ord_1' },
      { path: '/api/orders/ord_2' },
      { path: '/api/orders/ord_3' },
    ]);

    const hypotheses = generateHypothesesFromObservations({
      assessmentId: ASSESSMENT,
      scanId: SCAN,
      targetDomain: HOST,
      probeInventory: inventory,
      findings: [],
      sessionContext: { hasAuthenticatedContext: true, hasSecondaryAuthenticatedContext: false, hasJwt: false },
      nowIso,
    });

    const orderHypotheses = hypotheses.filter((h) => h.normalizedRoutePattern?.includes('/api/orders/{id}'));
    assert.equal(orderHypotheses.length, 1, 'Should produce only 1 deduplicated hypothesis for /api/orders/{id}');
    const orderHyp = orderHypotheses[0];
    assert.ok(orderHyp.observedObjectIds && orderHyp.observedObjectIds.length >= 3, 'Must preserve all raw object IDs');
    assert.ok(orderHyp.observedObjectIds.includes('ord_1'));
    assert.ok(orderHyp.observedObjectIds.includes('ord_2'));
    assert.ok(orderHyp.observedObjectIds.includes('ord_3'));
    assert.ok(orderHyp.candidateTargetUrls && orderHyp.candidateTargetUrls.length >= 3, 'Must preserve individual candidate URLs');
    console.log('  [PASS] Test I: Multiple raw entity URLs deduplicated with raw object IDs preserved.');
  }

  // =========================================================================
  // Test J — Context Separation & Gating
  // =========================================================================
  console.log('[+] Test J: Context Separation & Missing Context Gating...');
  {
    const hyp: SecurityHypothesis = {
      contractVersion: 'fixguard-hypothesis-scheduler/v0',
      kind: 'security_hypothesis',
      hypothesisId: 'hyp_needs_secondary',
      hypothesisKind: 'idor_differential',
      title: 'Multi-role IDOR hypothesis',
      epistemicStatus: 'OBSERVED',
      score: 90,
      blocked: false,
      blockReason: 'none',
      rationale: 'Requires secondary authenticated identity',
      suggestedCapability: 'idor_read_differential',
      sourceFindingIds: [],
      targetUrl: `https://${HOST}/api/tenant/data`,
      normalizedRoutePattern: '/api/tenant/data',
      state: 'candidate',
      investigationCount: 0,
      supportingEvidence: ['Sensitive multi-tenant resource'],
      contradictingEvidence: [],
      dependencies: {
        requiresAuth: true,
        requiresSecondaryAuth: true,
        requiresParameter: false,
        satisfied: true,
        blockReason: 'none',
      },
      explanation: [],
    };

    // When only primary identity is available (0 secondary), hypothesis cannot be scheduled
    const scheduledMissing = scheduleNextInvestigation([hyp], {
      identityCount: 1, // Only primary
      hasJwt: false,
      nowIso,
    });

    assert.equal(scheduledMissing, null, 'Hypothesis requiring secondary identity must be blocked when secondary is absent');

    // When secondary identity is provided, it becomes runnable
    const scheduledWithSecondary = scheduleNextInvestigation([hyp], {
      identityCount: 2, // Primary + secondary
      hasJwt: false,
      nowIso,
    });

    assert.ok(scheduledWithSecondary !== null, 'Hypothesis must be scheduled once secondary identity is provided');
    assert.equal(scheduledWithSecondary.plan.contextKind, 'authenticated_secondary');
    console.log('  [PASS] Test J: Context gating strictly blocked unexecutable hypothesis when identity was absent.');
  }

  // =========================================================================
  // Test K — Existing Read Detection Compatibility
  // =========================================================================
  console.log('[+] Test K: Existing Read Detection Compatibility...');
  {
    const inventory = createProbeInventory([
      { path: '/graphql' },
      { path: '/api/cors-endpoint' },
    ]);
    const corsFinding: Finding = {
      id: 'fnd_cors_01',
      type: 'CORS_MISCONFIGURATION',
      severity: 'medium',
      title: 'Permissive CORS Header',
      description: 'Access-Control-Allow-Origin: * on API',
      target: HOST,
      evidence: 'headers',
      confidence: 0.9,
      verificationState: 'observed_anomaly',
      metadata: {
        kind: 'discovery_finding_metadata',
        endpointUrl: `https://${HOST}/api/cors-endpoint`,
      },
    };

    const hypotheses = generateHypothesesFromObservations({
      assessmentId: ASSESSMENT,
      scanId: SCAN,
      targetDomain: HOST,
      probeInventory: inventory,
      findings: [corsFinding],
      sessionContext: { hasAuthenticatedContext: true, hasSecondaryAuthenticatedContext: false, hasJwt: false },
      nowIso,
    });

    assert.ok(hypotheses.some((h) => h.suggestedCapability === 'graphql_surface_probe'), 'Must generate graphql probe');
    assert.ok(hypotheses.some((h) => h.suggestedCapability === 'cors_misconfiguration_probe'), 'Must generate CORS probe');
    console.log('  [PASS] Test K: Existing read-detection findings & GraphQL surfaces mapped cleanly.');
  }

  // =========================================================================
  // Test L — Full Canonical Runtime Composition
  // =========================================================================
  console.log('[+] Test L: Multi-Step Adaptive Investigation Feedback Composition (End-to-End)...');
  {
    const plansRepo = new InMemoryAttackPlanRepository();
    const asmtRepo = new InMemoryOrchestratedAssessmentRepository();
    const calls: string[] = [];

    // INVARIANT: Plan repository starts completely EMPTY (0 pre-seeded plans)
    const initialRepoPlans = await plansRepo.listByAssessmentId(ASSESSMENT);
    assert.equal(initialRepoPlans.length, 0, 'Must have ZERO pre-seeded plans; dynamic generation required');

    const mockTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      calls.push(req.url);
      if (req.url.includes('/api/orders/ord_hop')) {
        // Step 1 target: Clean application 403 Forbidden (application denial, valid test evidence)
        return {
          statusCode: 403,
          headers: { 'content-type': 'application/json' },
          bodyText: '{"error":"Forbidden","code":"ACCESS_DENIED"}',
          responseTimeMs: 3,
        };
      }
      if (req.url.includes('/graphql')) {
        // Step 2 target: HTTP 200 OK
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: '{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
          responseTimeMs: 2,
        };
      }
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        bodyText: '<html><body>Generic app</body></html>',
        responseTimeMs: 1,
      };
    };

    // Initial finding: high priority auth boundary issue on /api/orders/ord_hop (Hypothesis H1)
    const initialFinding: Finding = {
      id: 'fnd_comp_01',
      type: 'BROKEN_ACCESS_CONTROL',
      severity: 'high',
      title: 'Observed auth difference on orders',
      description: '401 anon vs 200 auth',
      target: HOST,
      evidence: 'prior_recon',
      confidence: 0.85,
      verificationState: 'observed_anomaly',
      metadata: {
        kind: 'discovery_finding_metadata',
        endpointUrl: `https://${HOST}/api/orders/ord_hop`,
      },
    };

    // Inventory contains /api/orders/ord_hop AND /graphql (Hypothesis H2)
    const inventory = createProbeInventory([
      { path: '/api/orders/ord_hop' },
      { path: '/graphql' },
    ]);

    const service = new OrchestratedAssessmentApplicationService({
      repository: asmtRepo,
      attackPlanRepository: plansRepo,
      dnsResolver: async () => ['93.184.216.34'],
      httpTransport: mockTransport,
    });

    const initialRecord: OrchestratedAssessmentRecord = {
      contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
      assessmentId: ASSESSMENT,
      scanId: SCAN,
      targetDomain: HOST,
      status: 'running',
      lineage: createLineage(),
      stages: [],
      timing: { startedAt: nowIso },
      errorCount: 0,
      warningCount: 0,
      findings: [initialFinding],
      recommendations: [],
    };
    await asmtRepo.save(initialRecord);

    // Execute canonical closed-loop investigation with stepBudget: 2
    const result = await runReadInvestigationLoop({
      assessmentId: ASSESSMENT,
      lineage: createLineage(),
      verifiedAuthorizationDecision: decision,
      scopeGrant: createScopeGrant(),
      coordinator: new TargetExecutionCoordinator({ requestsPerSecond: 10, maxConcurrency: 2 }),
      dnsResolver: async () => ['93.184.216.34'],
      transport: mockTransport,
      circuitHost: HOST,
      findings: [initialFinding],
      probeInventory: inventory,
      planRepository: plansRepo,
      planGenerator: new AttackPlanGeneratorService(),
      authorizationService: new AttackAuthorizationService(plansRepo),
      executionService: new AttackExecutionService({
        planRepository: plansRepo,
        capabilityRegistry: createTestCapabilityRegistry(mockTransport),
      }),
      recordOutcome: async (args) => {
        await service.recordAttackExecutionOutcome(args);
      },
      primaryIdentity: { identityId: 'session_primary' },
      identities: [{ identityId: 'session_primary', hasJwt: false }],
      stepBudget: 2,
    });

    // 1. Verify budget & execution count
    assert.equal(result.record.stepsExecuted, 2, 'Must execute exactly 2 steps under stepBudget = 2');
    assert.equal(result.record.stopReason, 'step_budget_exhausted');
    assert.equal(result.feedbackSteps.length, 2, 'Must record exactly 2 feedback steps');
    assert.equal(calls.length, 2, 'Must make exactly 2 network probe requests');

    // 2. Verify Step 1: H1 selected first, executed, and refuted by clean application 403
    const step1 = result.feedbackSteps[0];
    assert.ok(step1.targetUrl.includes('/api/orders/ord_hop'), 'Step 1 must target H1 (/api/orders/ord_hop)');
    assert.equal(step1.testValidityVerdict, 'valid', 'Clean application 403 must NOT be marked as WAF interfered');
    assert.equal(step1.outcome, 'refuted', 'Step 1 result must refute H1');
    assert.equal(step1.stateTransition.from, 'candidate');
    assert.equal(step1.stateTransition.to, 'refuted');

    // 3. Verify Step 2: H2 selected AFTER H1 was refuted, executed, and supported by 200 OK
    const step2 = result.feedbackSteps[1];
    assert.ok(step2.targetUrl.includes('/graphql'), 'Step 2 must target H2 (/graphql) because H1 was refuted');
    assert.notEqual(step1.hypothesisId, step2.hypothesisId, 'Step 2 must target a different hypothesis than Step 1');
    assert.notEqual(step1.planId, step2.planId, 'Step 2 plan must be dynamically synthesized distinct from Step 1');
    assert.equal(step2.testValidityVerdict, 'valid');
    assert.equal(step2.outcome, 'supported', 'Step 2 result must support H2');
    assert.equal(step2.stateTransition.from, 'candidate');
    assert.equal(step2.stateTransition.to, 'supported');

    // 4. Verify causality: Plan 2 was generated dynamically after Plan 1 result
    const dynamicallyGeneratedPlans = await plansRepo.listByAssessmentId(ASSESSMENT);
    assert.equal(dynamicallyGeneratedPlans.length, 2, 'Exactly 2 plans dynamically created and saved');
    assert.equal(calls[0], `https://${HOST}/api/orders/ord_hop`, 'Call order: H1 executed first');
    assert.equal(calls[1], `https://${HOST}/graphql`, 'Call order: H2 executed second');

    // 5. Verify operator view projection
    service.recordInvestigationHypotheses(ASSESSMENT, result.hypotheses);
    const projectedHypotheses = service.getInvestigationHypotheses(ASSESSMENT);
    assert.ok(projectedHypotheses && projectedHypotheses.length >= 2, 'Runtime hypotheses must be recorded in service');
    const projectedH1 = projectedHypotheses.find((h) => h.targetUrl?.includes('/api/orders/ord_hop'));
    assert.equal(projectedH1?.state, 'refuted', 'Projected H1 must be in refuted state');
    const projectedH2 = projectedHypotheses.find((h) => h.targetUrl?.includes('/graphql'));
    assert.equal(projectedH2?.state, 'supported', 'Projected H2 must be in supported state');

    const refresh = await service.getAttackModeRefresh(ASSESSMENT);
    assert.ok(refresh, 'Refresh DTO must be successfully returned');

    console.log('  [PASS] Test L: Real multi-step feedback loop proved: R1 refuted H1, scheduler selected H2, P2 dynamically generated and executed.');
  }

  console.log('\n>>> ALL FIXGUARD V2 BLOCK B TESTS (A THROUGH L) PASSED SUCCESSFULLY! <<<');
}

runBlockBSmokeSuite().catch((err) => {
  console.error('\n[FATAL] Block B smoke test failed:', err);
  process.exit(1);
});
