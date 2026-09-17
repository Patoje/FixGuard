/**
 * Milestone P5-3 Smoke Test Suite — HTTP Method Manipulation Detection Engine
 *
 * Verifies:
 * 1. Detects authorization bypass via X-HTTP-Method-Override header.
 * 2. Detects enabled TRACE method reflecting custom canary header (XST risk).
 * 3. Cleanly abstains (secure_target_abstained) when target blocks overrides or returns 405.
 * 4. Preflight and egress gates block internal/SSRF targets.
 * 5. Full HITL triage lifecycle promotes drafts to formal Findings.
 */

import { runHttpMethodManipulationDetection } from '../detection/HttpMethodManipulationDetectionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { IdorHttpProbeTransport, HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

async function runSmokeTests() {
  console.log('=== Milestone P5-3: HTTP Method Manipulation Detection Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const assessmentId = 'asm_smoke_p5_3_001';
  const scanId = 'scn_smoke_p5_3_001';
  const grantId = 'grn_smoke_p5_3_001';
  const decisionId = 'dec_smoke_p5_3_001';
  const actorId = 'act_smoke_p5_3_operator';

  const scopeGrant: AuthorizedScopeGrant = {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId,
    scanId,
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'origin',
      normalizedOrigin: 'https://api.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone P5-3 HTTP method manipulation smoke test',
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
      allowedDomains: ['api.example.com'],
      allowedHosts: ['api.example.com'],
      allowedOrigins: ['https://api.example.com'],
      allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
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
  // TEST 1: Detects authorization bypass via X-HTTP-Method-Override header
  // -------------------------------------------------------------------------
  console.log('[TEST 1] Testing HTTP Method Override authorization bypass...');
  {
    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      const getHeader = (name: string) => {
        const lower = name.toLowerCase();
        for (const [k, v] of Object.entries(req.headers)) {
          if (k.toLowerCase() === lower) return v;
        }
        return undefined;
      };

      // Baseline DELETE check -> returns 403 Forbidden
      if (req.method === 'DELETE' && !getHeader('x-http-method-override')) {
        return {
          statusCode: 403,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({ error: 'Forbidden: DELETE method requires admin role' }),
          responseTimeMs: 25,
        };
      }
      // Overridden POST check with X-HTTP-Method-Override: DELETE -> returns 200 OK
      if (req.method === 'POST' && getHeader('x-http-method-override') === 'DELETE') {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({ success: true, message: 'Resource deleted via override' }),
          responseTimeMs: 30,
        };
      }
      return {
        statusCode: 405,
        headers: {},
        bodyText: 'Method Not Allowed',
        responseTimeMs: 10,
      };
    };

    const result = await runHttpMethodManipulationDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'http_method_manipulation_detection_request',
      detectionId: 'det_hmeth_test_001',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      endpointUrl: 'https://api.example.com/api/admin/users/42',
      targetOperation: 'delete_user_account',
      baselineMethod: 'DELETE',
      transport: mockTransport,
    });

    if (result.status !== 'pending_human_review') {
      throw new Error(`[TEST 1] Expected pending_human_review, got ${result.status} (${result.reasonCode})`);
    }
    if (!result.evidenceDraft) {
      throw new Error('[TEST 1] Expected evidenceDraft in unattended run');
    }
    if (result.bypassType !== 'method_override_header') {
      throw new Error(`[TEST 1] Expected bypassType 'method_override_header', got ${result.bypassType}`);
    }
    if (result.manipulatedStatusCode !== 200) {
      throw new Error(`[TEST 1] Expected manipulatedStatusCode 200, got ${result.manipulatedStatusCode}`);
    }
    console.log(`[TEST 1] PASS: Flagged method override draft: ${result.evidenceDraft.draftId}`);
  }

  // -------------------------------------------------------------------------
  // TEST 2: Detects enabled TRACE method reflecting custom canary header
  // -------------------------------------------------------------------------
  console.log('[TEST 2] Testing TRACE method reflection detection...');
  {
    const mockTraceTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      // Baseline DELETE is 403
      if (req.method === 'DELETE') {
        return {
          statusCode: 403,
          headers: {},
          bodyText: 'Forbidden',
          responseTimeMs: 15,
        };
      }
      // TRACE method reflects the request headers including canary
      if (req.method === 'TRACE') {
        const canary = req.headers['x-fixguard-canary'] || req.headers['X-Fixguard-Canary'] || '';
        return {
          statusCode: 200,
          headers: { 'content-type': 'message/http' },
          bodyText: `TRACE /api/admin HTTP/1.1\r\nHost: api.example.com\r\nX-Fixguard-Canary: ${canary}\r\n`,
          responseTimeMs: 20,
        };
      }
      return {
        statusCode: 405,
        headers: {},
        bodyText: 'Method Not Allowed',
        responseTimeMs: 10,
      };
    };

    const result = await runHttpMethodManipulationDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'http_method_manipulation_detection_request',
      detectionId: 'det_hmeth_test_002',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      endpointUrl: 'https://api.example.com/api/admin',
      targetOperation: 'trace_check',
      baselineMethod: 'DELETE',
      transport: mockTraceTransport,
    });

    if (result.status !== 'pending_human_review') {
      throw new Error(`[TEST 2] Expected pending_human_review, got ${result.status} (${result.reasonCode})`);
    }
    if (result.bypassType !== 'trace_enabled') {
      throw new Error(`[TEST 2] Expected bypassType 'trace_enabled', got ${result.bypassType}`);
    }
    console.log(`[TEST 2] PASS: Detected TRACE reflection draft: ${result.evidenceDraft?.draftId}`);
  }

  // -------------------------------------------------------------------------
  // TEST 3: Cleanly abstains when target blocks overrides or returns 405
  // -------------------------------------------------------------------------
  console.log('[TEST 3] Verifying abstention on secure target blocking overrides...');
  {
    const mockSecureTransport: IdorHttpProbeTransport = async (_req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      return {
        statusCode: 405,
        headers: {},
        bodyText: 'Method Not Allowed',
        responseTimeMs: 10,
      };
    };

    const result = await runHttpMethodManipulationDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'http_method_manipulation_detection_request',
      detectionId: 'det_hmeth_test_003',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      endpointUrl: 'https://api.example.com/api/secure',
      targetOperation: 'secure_op',
      baselineMethod: 'DELETE',
      transport: mockSecureTransport,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`[TEST 3] Expected secure_target_abstained, got ${result.status}`);
    }
    console.log('[TEST 3] PASS: Cleanly abstained on secure target.');
  }

  // -------------------------------------------------------------------------
  // TEST 4: Preflight & Egress Gates Block Internal / SSRF Targets
  // -------------------------------------------------------------------------
  console.log('[TEST 4] Verifying preflight SSRF protection against loopback/metadata...');
  {
    const ssrfScopeGrant: AuthorizedScopeGrant = {
      ...scopeGrant,
      subject: {
        targetKind: 'origin',
        normalizedOrigin: 'http://127.0.0.1:8080',
      },
      boundaries: {
        allowedDomains: ['127.0.0.1'],
        allowedHosts: ['127.0.0.1'],
        allowedOrigins: ['http://127.0.0.1:8080'],
        allowedMethods: ['GET', 'POST', 'DELETE'],
      },
    };

    const ssrfAuth = establishVerifiedAuthorizationDecision(
      {
        contractVersion: 'fixguard-verified-authorization-decision/v0',
        kind: 'establish_verified_authorization_decision_request',
        assessmentId,
        scanId,
        authorizationDecisionId: 'dec_ssrf_002',
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

    const result = await runHttpMethodManipulationDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'http_method_manipulation_detection_request',
      detectionId: 'det_hmeth_ssrf_001',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: 'dec_ssrf_002',
      actorId,
      verifiedAuthorizationDecision: ssrfAuth.decision,
      scopeGrant: ssrfScopeGrant,
      endpointUrl: 'http://127.0.0.1:8080/api/admin',
    });

    if (result.status !== 'preflight_denied') {
      throw new Error(`[TEST 4] Expected preflight_denied for loopback, got ${result.status}`);
    }
    console.log('[TEST 4] PASS: Preflight successfully blocked loopback SSRF probe.');
  }

  // -------------------------------------------------------------------------
  // TEST 5: Full HITL Review Lifecycle & Promotion to Formal Finding
  // -------------------------------------------------------------------------
  console.log('[TEST 5] Testing HITL review lifecycle promoting draft to formal Finding...');
  {
    const repo = new InMemoryOrchestratedAssessmentRepository();
    const appService = new OrchestratedAssessmentApplicationService({ repository: repo });

    const initialRecord = {
      contractVersion: 'fixguard-orchestrated-assessment/v0' as const,
      assessmentId,
      scanId,
      targetDomain: 'api.example.com',
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
          draftId: 'dft_hmeth_rev_001',
          suggestedEvidenceType: 'http_difference' as const,
          suggestedStrength: 'strong' as const,
          sourceComparisonId: 'cmp_hmeth_001',
          sourceSnapshotIds: {
            baselineSnapshotId: 'snp_base_001',
            validationSnapshotId: 'snp_ovr_001',
          },
          requiresHumanReview: true as const,
          notPersisted: true as const,
          notARealFinding: true as const,
          notConfirmedEvidence: true as const,
          notForExternalDelivery: true as const,
          notM45EvidenceRecord: true as const,
          safeRationale: 'Endpoint blocked under DELETE returns 200 OK via X-HTTP-Method-Override header.',
          differentialContext: {
            endpointUrl: 'https://api.example.com/api/admin/users/42',
            detectionKind: 'http_method_manipulation' as const,
            targetOperation: 'delete_user_account',
            baselineMethod: 'DELETE',
            bypassMethodOrHeader: 'X-HTTP-Method-Override: DELETE',
            baselineStatusCode: 403,
            manipulatedStatusCode: 200,
            bypassType: 'method_override_header' as const,
            validationStatusCode: 200,
          },
        },
      ],
      recommendations: [],
    };

    await repo.save(initialRecord);

    const reviewRes = await appService.reviewEvidenceDraft({
      assessmentId,
      draftId: 'dft_hmeth_rev_001',
      decision: 'approve_evidence',
      reviewerId: 'act_operator_human_01',
      reviewedAt: nowIso,
      notes: 'Confirmed HTTP method override authorization bypass.',
    });

    if (reviewRes.decision !== 'approve_evidence' || !reviewRes.findingCreated) {
      throw new Error(`[TEST 5] Expected review decision 'approve_evidence' with findingCreated, got ${reviewRes.decision}`);
    }

    const updated = await repo.findById(assessmentId);
    if (!updated || updated.findings.length === 0) {
      throw new Error('[TEST 5] Expected formal finding created in repository');
    }

    const createdFinding = updated.findings[0];
    if (
      createdFinding.metadata.kind !== 'http_method_manipulation_metadata' ||
      createdFinding.metadata.category !== 'BROKEN_ACCESS_CONTROL' ||
      createdFinding.metadata.bypassType !== 'method_override_header' ||
      createdFinding.metadata.manipulatedStatusCode !== 200
    ) {
      throw new Error('[TEST 5] Metadata mismatch in promoted finding');
    }
    console.log(`[TEST 5] PASS: Promoted finding verified: ${createdFinding.id} (${createdFinding.title})`);
  }

  console.log('\n[ALL TESTS PASSED] Milestone P5-3 HTTP Method Manipulation Detection Engine certified!');
}

runSmokeTests().catch((err) => {
  console.error('[SMOKE FAILED]', err);
  process.exit(1);
});
