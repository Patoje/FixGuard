/**
 * Milestone P5-3 Smoke Test Suite — HTTP Method Manipulation Detection Engine
 *
 * Verifies:
 * 1. Detects verb override tamper (`X-HTTP-Method-Override` / `_method`) bypassing baseline 403.
 * 2. Detects TRACE method reflection exposing diagnostic headers.
 * 3. Cleanly abstains (secure_target_abstained) when target enforces auth/405 across alternative methods.
 * 4. Preflight and egress gates block internal/SSRF targets.
 * 5. Full HITL triage lifecycle promotes drafts to formal Findings with HttpMethodManipulationMetadata.
 */

import { runHttpMethodManipulationDetection } from '../detection/HttpMethodManipulationDetectionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { IdorHttpProbeTransport, HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import type { OrchestratedAssessmentRecord } from '../application/OrchestratedAssessmentContracts.js';
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
      allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
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
    throw new Error(`Failed to establish verified authorization: ${authRes.reasonCode} - ${JSON.stringify(authRes)}`);
  }

  const verifiedDecision = authRes.decision;

  // -------------------------------------------------------------------------
  // TEST 1: Detects verb override header tampering (X-HTTP-Method-Override)
  // -------------------------------------------------------------------------
  console.log('[TEST 1] Testing HTTP Method Override header bypass on protected endpoint...');
  {
    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      // Baseline POST returns 403 Forbidden
      if (req.method === 'POST' && !req.headers['X-HTTP-Method-Override']) {
        return {
          statusCode: 403,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({ error: 'Forbidden' }),
          responseTimeMs: 20,
        };
      }
      // Override header X-HTTP-Method-Override: GET returns 200 OK
      if (req.headers['X-HTTP-Method-Override'] === 'GET') {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({ status: 'success', data: ['secret1', 'secret2'] }),
          responseTimeMs: 22,
        };
      }
      return {
        statusCode: 405,
        headers: {},
        bodyText: 'Method Not Allowed',
        responseTimeMs: 15,
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
      endpointUrl: 'https://api.example.com/api/v1/admin/users',
      targetOperation: 'delete_user',
      baselineMethod: 'POST',
      transport: mockTransport,
    });

    if (result.status !== 'pending_human_review') {
      throw new Error(`[TEST 1] Expected pending_human_review, got ${result.status} (${result.reasonCode})`);
    }
    if (!result.evidenceDraft) {
      throw new Error('[TEST 1] Expected evidenceDraft in result');
    }
    if (result.bypassType !== 'method_override_header') {
      throw new Error(`[TEST 1] Expected bypassType 'method_override_header', got ${result.bypassType}`);
    }
    console.log(`[TEST 1] PASS: Flagged HTTP method override draft: ${result.evidenceDraft.draftId}`);
  }

  // -------------------------------------------------------------------------
  // TEST 2: Detects TRACE method header reflection
  // -------------------------------------------------------------------------
  console.log('[TEST 2] Testing TRACE method reflection with canary header...');
  {
    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.method === 'POST') {
        return {
          statusCode: 403,
          headers: {},
          bodyText: 'Forbidden',
          responseTimeMs: 15,
        };
      }
      if (req.method === 'TRACE') {
        // Echo back request lines including canary header
        const canary = req.headers['X-Fixguard-Canary'] ?? 'canary-reflected';
        return {
          statusCode: 200,
          headers: { 'content-type': 'message/http' },
          bodyText: `TRACE /api/v1/debug HTTP/1.1\r\nHost: api.example.com\r\nX-Fixguard-Canary: ${canary}\r\n`,
          responseTimeMs: 25,
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
      endpointUrl: 'https://api.example.com/api/v1/debug',
      targetOperation: 'read_debug_info',
      baselineMethod: 'POST',
      transport: mockTransport,
    });

    if (result.status !== 'pending_human_review') {
      throw new Error(`[TEST 2] Expected pending_human_review, got ${result.status} (${result.reasonCode})`);
    }
    if (result.bypassType !== 'trace_enabled') {
      throw new Error(`[TEST 2] Expected bypassType 'trace_enabled', got ${result.bypassType}`);
    }
    console.log(`[TEST 2] PASS: Flagged TRACE method reflection draft: ${result.evidenceDraft?.draftId}`);
  }

  // -------------------------------------------------------------------------
  // TEST 3: Clean abstention on 405 or non-bypass endpoints
  // -------------------------------------------------------------------------
  console.log('[TEST 3] Testing clean abstention on secure endpoint...');
  {
    const mockTransportSecure: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => {
      return {
        statusCode: 405,
        headers: {},
        bodyText: 'Method Not Allowed',
        responseTimeMs: 12,
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
      endpointUrl: 'https://api.example.com/api/v1/secure',
      targetOperation: 'secure_op',
      baselineMethod: 'POST',
      transport: mockTransportSecure,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`[TEST 3] Expected secure_target_abstained, got ${result.status}`);
    }
    if (result.evidenceDraft !== undefined) {
      throw new Error('[TEST 3] Expected no draft on abstention');
    }
    console.log(`[TEST 3] PASS: Cleanly abstained with reason ${result.reasonCode}`);
  }

  // -------------------------------------------------------------------------
  // TEST 4: SSRF Preflight / Egress Gate Rejection
  // -------------------------------------------------------------------------
  console.log('[TEST 4] Verifying preflight SSRF protection against internal endpoints...');
  {
    const mockTransport: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => {
      throw new Error('Transport should not be called for SSRF target');
    };

    const ssrfResult = await runHttpMethodManipulationDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'http_method_manipulation_detection_request',
      detectionId: 'det_hmeth_test_004',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      endpointUrl: 'http://169.254.169.254/latest/meta-data',
      targetOperation: 'metadata_access',
      baselineMethod: 'POST',
      transport: mockTransport,
    });

    if (ssrfResult.status !== 'preflight_denied') {
      throw new Error(`[TEST 4] Expected preflight_denied for SSRF target, got ${ssrfResult.status}`);
    }
    console.log(`[TEST 4] PASS: Safely rejected SSRF target with code ${ssrfResult.reasonCode}`);
  }

  // -------------------------------------------------------------------------
  // TEST 5: Orchestrated Assessment Application Service HITL lifecycle promotion
  // -------------------------------------------------------------------------
  console.log('[TEST 5] Verifying HITL draft review & promotion to formal Finding in Application Service...');
  {
    const repo = new InMemoryOrchestratedAssessmentRepository();
    const service = new OrchestratedAssessmentApplicationService({ repository: repo });

    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.headers['X-HTTP-Method-Override'] === 'GET') {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({ success: true, bypassed: true }),
          responseTimeMs: 18,
        };
      }
      return {
        statusCode: 403,
        headers: {},
        bodyText: 'Forbidden',
        responseTimeMs: 15,
      };
    };

    const detResult = await runHttpMethodManipulationDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'http_method_manipulation_detection_request',
      detectionId: 'det_hmeth_test_005',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      endpointUrl: 'https://api.example.com/api/v1/users/delete',
      targetOperation: 'delete_user_op',
      baselineMethod: 'POST',
      transport: mockTransport,
    });

    if (detResult.status !== 'pending_human_review' || !detResult.evidenceDraft) {
      throw new Error('[TEST 5] Failed to generate evidence draft for review promotion');
    }

    const draft = detResult.evidenceDraft;

    // Execute HITL review reviewEvidenceDraft via OrchestratedAssessmentApplicationService
    const initialRecord: OrchestratedAssessmentRecord = {
      contractVersion: 'fixguard-orchestrated-assessment/v0',
      assessmentId,
      scanId,
      targetDomain: 'api.example.com',
      status: 'running',
      lineage: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId,
      },
      stages: [],
      timing: {
        startedAt: nowIso,
      },
      errorCount: 0,
      warningCount: 0,
      findings: [],
      pendingEvidenceDrafts: [draft],
      recommendations: [],
    };

    await repo.save(initialRecord);

    const reviewRes = await service.reviewEvidenceDraft({
      assessmentId,
      draftId: draft.draftId,
      decision: 'approve_evidence',
      reviewerId: 'act_operator_human_01',
      reviewedAt: nowIso,
      notes: 'Confirmed HTTP method override bypass on sensitive endpoint.',
    });

    if (reviewRes.decision !== 'approve_evidence' || !reviewRes.findingCreated) {
      throw new Error(`[TEST 5] Expected review decision 'approve_evidence' with findingCreated, got ${reviewRes.decision}`);
    }

    const updated = await repo.findById(assessmentId);
    if (!updated || updated.findings.length === 0) {
      throw new Error('[TEST 5] Expected formal finding created in repository');
    }

    const finding = updated.findings[0];
    if (finding.metadata.kind !== 'http_method_manipulation_metadata') {
      throw new Error(`[TEST 5] Expected finding metadata kind 'http_method_manipulation_metadata', got ${finding.metadata.kind}`);
    }
    console.log(`[TEST 5] PASS: HITL review promoted evidence draft to formal Finding: ${finding.id}`);
  }

  console.log('\n=== ALL 5 MILESTONE P5-3 SMOKE TESTS PASSED SUCCESSFULLY ===');
}

runSmokeTests().catch((err) => {
  console.error('FAILED Smoke Test:', err);
  process.exit(1);
});
