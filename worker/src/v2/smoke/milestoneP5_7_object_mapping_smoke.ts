/**
 * Milestone P5-7 Smoke Test Suite — Object Mapping Anomaly Probe
 *
 * Verifies:
 * 1. Detects mass assignment / object binding anomaly when injected privilege properties are accepted and echoed.
 * 2. Cleanly abstains (secure_target_abstained) when target strips unbound properties or validates strictly.
 * 3. Preflight and egress gates block internal/SSRF targets.
 * 4. Full HITL triage lifecycle promotes drafts to formal Findings.
 * 5. Binding echo evaluation helper accuracy.
 */

import {
  runObjectMappingAnomalyDetection,
  evaluateBindingEcho,
} from '../detection/ObjectMappingAnomalyDetectionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { IdorHttpProbeTransport, HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

async function runSmokeTests() {
  console.log('=== Milestone P5-7: Object Mapping Anomaly Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const assessmentId = 'asm_smoke_p5_7_001';
  const scanId = 'scn_smoke_p5_7_001';
  const grantId = 'grn_smoke_p5_7_001';
  const decisionId = 'dec_smoke_p5_7_001';
  const actorId = 'act_smoke_p5_7_operator';

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
      authorizationText: 'Authorized for Milestone P5-7 Object Mapping smoke test',
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
  // TEST 1: Detects mass assignment / object binding anomaly when privilege properties are accepted
  // -------------------------------------------------------------------------
  console.log('[TEST 1] Testing object mapping privilege escalation detection...');
  {
    const mockVulnerableTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.url.includes('/api/user/profile') && req.method === 'PUT') {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({
            id: 42,
            username: 'alice',
            email: 'alice@example.com',
            isAdmin: true,
            role: 'admin',
            updatedAt: nowIso,
          }),
          responseTimeMs: 30,
        };
      }
      return { statusCode: 404, headers: {}, bodyText: 'Not Found', responseTimeMs: 10 };
    };

    const result = await runObjectMappingAnomalyDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'object_mapping_anomaly_detection_request',
      detectionId: 'det_objmap_test_001',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      endpointUrl: 'https://app.example.com/api/user/profile',
      httpMethod: 'PUT',
      transport: mockVulnerableTransport,
    });

    if (result.status !== 'pending_human_review') {
      throw new Error(`[TEST 1] Expected pending_human_review, got ${result.status} (${result.reasonCode})`);
    }
    if (!result.evidenceDraft) {
      throw new Error('[TEST 1] Expected evidenceDraft in unattended run');
    }
    if (result.bindingAccepted !== true) {
      throw new Error('[TEST 1] Expected bindingAccepted: true');
    }
    if (!result.injectedProperties.includes('isAdmin') || !result.injectedProperties.includes('role')) {
      throw new Error(`[TEST 1] Expected isAdmin and role in injectedProperties, got ${result.injectedProperties.join(', ')}`);
    }
    console.log(`[TEST 1] PASS: Flagged mass assignment draft: ${result.evidenceDraft.draftId}, props: ${result.injectedProperties.join(', ')}`);
  }

  // -------------------------------------------------------------------------
  // TEST 2: Cleanly abstains when target rejects with 422 or strips unbound properties
  // -------------------------------------------------------------------------
  console.log('[TEST 2] Verifying abstention on strict schema validation (HTTP 422)...');
  {
    const mockSecureTransport: IdorHttpProbeTransport = async (_req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      return {
        statusCode: 422,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ error: 'Unrecognized field: isAdmin' }),
        responseTimeMs: 15,
      };
    };

    const result = await runObjectMappingAnomalyDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'object_mapping_anomaly_detection_request',
      detectionId: 'det_objmap_test_002',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      endpointUrl: 'https://app.example.com/api/user/profile',
      httpMethod: 'PUT',
      transport: mockSecureTransport,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`[TEST 2] Expected secure_target_abstained, got ${result.status}`);
    }
    if (result.bindingAccepted !== false) {
      throw new Error('[TEST 2] Expected bindingAccepted: false');
    }
    console.log('[TEST 2] PASS: Cleanly abstained on secure target.');
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
        authorizationDecisionId: 'dec_ssrf_006',
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

    const result = await runObjectMappingAnomalyDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'object_mapping_anomaly_detection_request',
      detectionId: 'det_objmap_ssrf_001',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: 'dec_ssrf_006',
      actorId,
      verifiedAuthorizationDecision: ssrfAuth.decision,
      scopeGrant: ssrfScopeGrant,
      endpointUrl: 'http://169.254.169.254/user/update',
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
          draftId: 'dft_objmap_rev_001',
          suggestedEvidenceType: 'http_difference' as const,
          suggestedStrength: 'strong' as const,
          sourceComparisonId: 'cmp_objmap_001',
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
          safeRationale: 'Endpoint https://app.example.com/api/user/profile accepted unconstrained properties (isAdmin, role).',
          differentialContext: {
            endpointUrl: 'https://app.example.com/api/user/profile',
            detectionKind: 'object_mapping_anomaly' as const,
            httpMethod: 'PUT',
            injectedProperties: ['isAdmin', 'role'],
            bindingAccepted: true,
            sanitizedEchoResponse: '{"id":42,"isAdmin":true,"role":"admin"}',
            validationStatusCode: 200,
          },
        },
      ],
      recommendations: [],
    };

    await repo.save(initialRecord);

    const reviewRes = await appService.reviewEvidenceDraft({
      assessmentId,
      draftId: 'dft_objmap_rev_001',
      decision: 'approve_evidence',
      reviewerId: 'act_operator_human_01',
      reviewedAt: nowIso,
      notes: 'Confirmed mass assignment privilege escalation vulnerability.',
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
      createdFinding.metadata.kind !== 'object_mapping_anomaly_metadata' ||
      createdFinding.metadata.category !== 'BROKEN_ACCESS_CONTROL' ||
      createdFinding.metadata.httpMethod !== 'PUT' ||
      createdFinding.metadata.bindingAccepted !== true
    ) {
      throw new Error('[TEST 4] Metadata mismatch in promoted finding');
    }
    console.log(`[TEST 4] PASS: Promoted finding verified: ${createdFinding.id} (${createdFinding.title})`);
  }

  // -------------------------------------------------------------------------
  // TEST 5: Binding Echo Evaluation Helper Accuracy
  // -------------------------------------------------------------------------
  console.log('[TEST 5] Testing evaluateBindingEcho helper...');
  {
    const testProps = { isAdmin: true, role: 'admin' };

    // Accepted case
    const match = evaluateBindingEcho(JSON.stringify({ name: 'test', isAdmin: true, role: 'admin' }), testProps);
    if (!match.accepted || match.matchedKeys.length !== 2) {
      throw new Error('[TEST 5] Failed to match accepted keys');
    }

    // Stripped case
    const stripped = evaluateBindingEcho(JSON.stringify({ name: 'test' }), testProps);
    if (stripped.accepted || stripped.matchedKeys.length !== 0) {
      throw new Error('[TEST 5] Stripped properties should not be accepted');
    }

    // Invalid JSON
    const invalidJson = evaluateBindingEcho('<html><body>Not JSON</body></html>', testProps);
    if (invalidJson.accepted) {
      throw new Error('[TEST 5] Non-JSON should not match');
    }
    console.log('[TEST 5] PASS: evaluateBindingEcho verified.');
  }

  console.log('\n[ALL TESTS PASSED] Milestone P5-7 Object Mapping Anomaly Probe certified!');
}

runSmokeTests().catch((err) => {
  console.error('[SMOKE FAILED]', err);
  process.exit(1);
});
