/**
 * Milestone P5-8 Smoke Test Suite — State Transition Anomaly Engine
 *
 * Verifies:
 * 1. Detects business logic bypass when terminal transaction succeeds without prerequisite steps.
 * 2. Cleanly abstains (secure_target_abstained) when target enforces state machine sequencing.
 * 3. Preflight and egress gates block internal/SSRF targets.
 * 4. Full HITL triage lifecycle promotes drafts to formal Findings.
 * 5. State bypass evaluation and candidate endpoint matcher accuracy.
 */

import {
  runStateTransitionAnomalyDetection,
  evaluateStateBypass,
  isStateTransitionCandidateEndpoint,
} from '../detection/StateTransitionAnomalyDetectionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { IdorHttpProbeTransport, HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

async function runSmokeTests() {
  console.log('=== Milestone P5-8: State Transition Anomaly Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const assessmentId = 'asm_smoke_p5_8_001';
  const scanId = 'scn_smoke_p5_8_001';
  const grantId = 'grn_smoke_p5_8_001';
  const decisionId = 'dec_smoke_p5_8_001';
  const actorId = 'act_smoke_p5_8_operator';

  const scopeGrant: AuthorizedScopeGrant = {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId,
    scanId,
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'origin',
      normalizedOrigin: 'https://app.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone P5-8 State Transition smoke test',
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
      allowedDomains: ['app.example.com'],
      allowedHosts: ['app.example.com'],
      allowedOrigins: ['https://app.example.com'],
      allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'OPTIONS'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: true,
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
    throw new Error(`Failed to establish verified authorization: ${authRes.reasonCode}`);
  }

  const verifiedDecision = authRes.decision;

  // -------------------------------------------------------------------------
  // TEST 1: Detects business logic bypass when terminal transaction succeeds
  // -------------------------------------------------------------------------
  console.log('[TEST 1] Testing state transition bypass detection (direct checkout completion)...');
  {
    const mockVulnerableTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.url.includes('/api/checkout/finalize') && req.method === 'POST') {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({
            status: 'completed',
            orderId: 'ord_99887766',
            confirmationNumber: 'CNF-44321',
            totalAmount: 0.0,
            message: 'Order processed successfully without payment verification',
          }),
          responseTimeMs: 35,
        };
      }
      return { statusCode: 404, headers: {}, bodyText: 'Not Found', responseTimeMs: 10 };
    };

    const result = await runStateTransitionAnomalyDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'state_transition_anomaly_detection_request',
      detectionId: 'det_statetr_test_001',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      endpointUrl: 'https://app.example.com/api/checkout/finalize',
      httpMethod: 'POST',
      transport: mockVulnerableTransport,
    });

    if (result.status !== 'pending_human_review') {
      throw new Error(`[TEST 1] Expected pending_human_review, got ${result.status} (${result.reasonCode})`);
    }
    if (!result.evidenceDraft) {
      throw new Error('[TEST 1] Expected evidenceDraft in unattended run');
    }
    if (result.bypassedSuccessfully !== true) {
      throw new Error('[TEST 1] Expected bypassedSuccessfully: true');
    }
    if (!result.responseExcerpt || !result.responseExcerpt.includes('ord_99887766')) {
      throw new Error(`[TEST 1] Expected responseExcerpt with orderId, got ${result.responseExcerpt}`);
    }
    console.log(`[TEST 1] PASS: Flagged state bypass draft: ${result.evidenceDraft.draftId}, excerpt: "${result.responseExcerpt}"`);
  }

  // -------------------------------------------------------------------------
  // TEST 2: Cleanly abstains when target enforces state machine sequencing (HTTP 422)
  // -------------------------------------------------------------------------
  console.log('[TEST 2] Verifying abstention on prerequisite state enforcement (HTTP 422)...');
  {
    const mockSecureTransport: IdorHttpProbeTransport = async (_req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      return {
        statusCode: 422,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ error: 'Prerequisite payment step required before order finalization' }),
        responseTimeMs: 15,
      };
    };

    const result = await runStateTransitionAnomalyDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'state_transition_anomaly_detection_request',
      detectionId: 'det_statetr_test_002',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      endpointUrl: 'https://app.example.com/api/checkout/finalize',
      httpMethod: 'POST',
      transport: mockSecureTransport,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`[TEST 2] Expected secure_target_abstained, got ${result.status}`);
    }
    if (result.bypassedSuccessfully !== false) {
      throw new Error('[TEST 2] Expected bypassedSuccessfully: false');
    }
    console.log('[TEST 2] PASS: Cleanly abstained on secure state machine.');
  }

  // -------------------------------------------------------------------------
  // TEST 3: Preflight & Egress Gates Block Internal / SSRF Targets
  // -------------------------------------------------------------------------
  console.log('[TEST 3] Verifying preflight SSRF protection against loopback/metadata...');
  {
    const ssrfScopeGrant: AuthorizedScopeGrant = {
      ...scopeGrant,
      subject: {
        targetKind: 'origin',
        normalizedOrigin: 'http://169.254.169.254',
      },
      boundaries: {
        allowedDomains: ['169.254.169.254'],
        allowedHosts: ['169.254.169.254'],
        allowedOrigins: ['http://169.254.169.254'],
        allowedMethods: ['POST'],
      },
    };

    const ssrfAuth = establishVerifiedAuthorizationDecision(
      {
        contractVersion: 'fixguard-verified-authorization-decision/v0',
        kind: 'establish_verified_authorization_decision_request',
        assessmentId,
        scanId,
        authorizationDecisionId: 'dec_ssrf_007',
        authorizedActor: { actorId, actorType: 'human' },
        decision: 'authorized',
        decidedAt: nowIso,
        scopeGrant: ssrfScopeGrant,
      },
      nowIso
    );

    if (ssrfAuth.status !== 'established' || !ssrfAuth.decision) {
      throw new Error('Failed to establish SSRF auth decision fixture');
    }

    const result = await runStateTransitionAnomalyDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'state_transition_anomaly_detection_request',
      detectionId: 'det_statetr_ssrf_001',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: 'dec_ssrf_007',
      actorId,
      verifiedAuthorizationDecision: ssrfAuth.decision,
      scopeGrant: ssrfScopeGrant,
      endpointUrl: 'http://169.254.169.254/checkout/complete',
      httpMethod: 'POST',
    });

    if (result.status !== 'preflight_denied') {
      throw new Error(`[TEST 3] Expected preflight_denied for loopback, got ${result.status}`);
    }
    console.log('[TEST 3] PASS: Preflight successfully blocked loopback SSRF probe.');
  }

  // -------------------------------------------------------------------------
  // TEST 4: Full HITL Review Lifecycle & Promotion to Formal Finding
  // -------------------------------------------------------------------------
  console.log('[TEST 4] Testing HITL review lifecycle promoting draft to formal Finding...');
  {
    const repo = new InMemoryOrchestratedAssessmentRepository();
    const appService = new OrchestratedAssessmentApplicationService({ repository: repo });

    const initialRecord = {
      contractVersion: 'fixguard-orchestrated-assessment/v0' as const,
      assessmentId,
      scanId,
      targetDomain: 'app.example.com',
      status: 'completed' as const,
      lineage: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId,
      },
      stages: [],
      timing: { startedAt: nowIso, completedAt: nowIso, durationMs: 150 },
      errorCount: 0,
      warningCount: 0,
      findings: [],
      pendingEvidenceDrafts: [
        {
          draftKind: 'non_persisted_comparison_evidence_draft' as const,
          draftId: 'dft_statetr_rev_001',
          suggestedEvidenceType: 'http_difference' as const,
          suggestedStrength: 'strong' as const,
          sourceComparisonId: 'cmp_statetr_001',
          sourceSnapshotIds: {
            baselineSnapshotId: 'snp_base_001',
            validationSnapshotId: 'snp_val_001',
          },
          requiresHumanReview: true as const,
          notPersisted: true as const,
          notARealFinding: true as const,
          notConfirmedEvidence: true as const,
          notForExternalDelivery: true as const,
          notM45EvidenceRecord: true as const,
          safeRationale: 'Terminal endpoint https://app.example.com/api/checkout/finalize executed without prerequisites.',
          differentialContext: {
            endpointUrl: 'https://app.example.com/api/checkout/finalize',
            detectionKind: 'state_transition_anomaly' as const,
            httpMethod: 'POST',
            expectedPrerequisiteSteps: ['cart_validation', 'payment_authorization'],
            bypassedSuccessfully: true,
            responseExcerpt: '{"status":"completed","orderId":"ord_99887766"}',
            validationStatusCode: 200,
          },
        },
      ],
      recommendations: [],
    };

    await repo.save(initialRecord);

    const reviewRes = await appService.reviewEvidenceDraft({
      assessmentId,
      draftId: 'dft_statetr_rev_001',
      decision: 'approve_evidence',
      reviewerId: 'act_operator_human_01',
      reviewedAt: nowIso,
      notes: 'Confirmed state machine workflow bypass allowing direct order execution.',
    });

    if (reviewRes.decision !== 'approve_evidence' || !reviewRes.findingCreated) {
      throw new Error(`[TEST 4] Expected review decision 'approve_evidence' with findingCreated, got ${reviewRes.decision}`);
    }

    const updated = await repo.findById(assessmentId);
    if (!updated || updated.findings.length === 0) {
      throw new Error('[TEST 4] Expected formal finding created in repository');
    }

    const createdFinding = updated.findings[0];
    if (
      createdFinding.metadata.kind !== 'state_transition_anomaly_metadata' ||
      createdFinding.metadata.category !== 'BUSINESS_LOGIC_BYPASS' ||
      createdFinding.metadata.bypassedSuccessfully !== true
    ) {
      throw new Error('[TEST 4] Metadata mismatch in promoted finding');
    }
    console.log(`[TEST 4] PASS: Promoted finding verified: ${createdFinding.id} (${createdFinding.title})`);
  }

  // -------------------------------------------------------------------------
  // TEST 5: State Bypass Evaluator & Candidate Endpoint Helper Accuracy
  // -------------------------------------------------------------------------
  console.log('[TEST 5] Testing evaluateStateBypass and isStateTransitionCandidateEndpoint...');
  {
    // Test candidate endpoint detection
    if (
      !isStateTransitionCandidateEndpoint('https://app.example.com/api/checkout/finalize') ||
      !isStateTransitionCandidateEndpoint('https://app.example.com/workflow/approve')
    ) {
      throw new Error('[TEST 5] Failed candidate endpoint detection');
    }
    if (isStateTransitionCandidateEndpoint('https://app.example.com/api/products/search')) {
      throw new Error('[TEST 5] False positive on non-transaction endpoint');
    }

    // Test bypass evaluation
    const passBypass = evaluateStateBypass(200, JSON.stringify({ status: 'completed', orderId: '123' }));
    if (!passBypass.bypassed || !passBypass.excerpt) {
      throw new Error('[TEST 5] Expected bypass confirmation');
    }

    const failBypass = evaluateStateBypass(422, JSON.stringify({ error: 'Step missing' }));
    if (failBypass.bypassed) {
      throw new Error('[TEST 5] Should not bypass on 422');
    }
    console.log('[TEST 5] PASS: Helpers verified.');
  }

  console.log('\n[ALL TESTS PASSED] Milestone P5-8 State Transition Anomaly Engine certified!');
}

runSmokeTests().catch((err) => {
  console.error('[SMOKE FAILED]', err);
  process.exit(1);
});
