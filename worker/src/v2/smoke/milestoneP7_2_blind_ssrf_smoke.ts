/**
 * Milestone P7-2 — Blind SSRF Detection Probe Smoke Suite
 *
 * Assertions:
 * 1. Detects blind SSRF when parameter injection triggers an inbound OOB callback validated by OobCanaryManager.
 * 2. Cleanly abstains (secure_target_abstained) when no callback interaction is recorded.
 * 3. Preflight SSRF protection (blocks loopback/metadata targets).
 * 4. Full HITL review lifecycle promotes Blind SSRF draft to formal Finding.
 * 5. Helper tests verify isSsrfCandidateParameter detection accuracy.
 */

import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type {
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from '../detection/DetectionContracts.js';
import {
  runBlindSsrfDetection,
  isSsrfCandidateParameter,
} from '../detection/BlindSsrfDetectionService.js';
import { OobCanaryManager } from '../oob/OobCanaryManager.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { OrchestratedAssessmentRecord } from '../application/OrchestratedAssessmentContracts.js';

async function runSmokeSuite(): Promise<void> {
  console.log('=== Milestone P7-2: Blind SSRF Detection Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const assessmentId = 'asm_smoke_p7_2_001';
  const scanId = 'scn_smoke_p7_2_001';
  const grantId = 'grn_smoke_p7_2_001';
  const decisionId = 'dec_smoke_p7_2_001';
  const actorId = 'usr_sec_auditor_p72';

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
      authorizationText: 'Authorized for Milestone P7-2 Blind SSRF smoke test',
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
      bodyText: '<html><body>Webhook received and scheduled for fetch</body></html>',
      responseTimeMs: 25,
    };
  };

  const dummyDnsResolver = async (_host: string) => ['93.184.216.34'];

  // -------------------------------------------------------------------------
  // Test 1: Blind SSRF Detection with Confirmed OOB Interaction
  // -------------------------------------------------------------------------
  console.log('[TEST 1] Testing Blind SSRF detection with confirmed OOB callback...');
  const isolatedOobManager = new OobCanaryManager({ defaultCallbackDomain: 'oob.test.local' });

  // Custom transport that automatically simulates remote target fetching the canary URL
  const interactiveTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    // Simulate remote server processing URL and contacting the canary
    const url = new URL(req.url);
    const injectedUrl = url.searchParams.get('webhook_url') ?? '';
    if (injectedUrl) {
      const injectedParsed = new URL(injectedUrl);
      const canaryToken = injectedParsed.hostname.split('.')[0] ?? '';
      // Simulate remote host connecting to canary
      isolatedOobManager.recordInteraction({
        canaryToken,
        interactionType: 'http_callback',
        remoteAddress: '198.51.100.77',
        receivedAt: new Date().toISOString(),
        httpMethod: 'POST',
      });
    }
    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      bodyText: JSON.stringify({ status: 'queued' }),
      responseTimeMs: 40,
    };
  };

  const result1 = await runBlindSsrfDetection(
    {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'blind_ssrf_detection_request',
      detectionId: 'det_bssrf_test_01',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decision.authorizationDecisionId,
      actorId,
      endpointUrl: 'https://app.example.com/api/v1/integrations/register',
      parameterName: 'webhook_url',
      method: 'GET',
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
  console.log(`[TEST 1] PASS: Flagged Blind SSRF draft: ${result1.evidenceDraft.draftId}, canary: ${result1.canaryToken}, remote: ${result1.remoteAddress}`);

  // -------------------------------------------------------------------------
  // Test 2: Abstention on Uncontacted Canary
  // -------------------------------------------------------------------------
  console.log('[TEST 2] Verifying abstention on untouched canary token...');
  const result2 = await runBlindSsrfDetection(
    {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'blind_ssrf_detection_request',
      detectionId: 'det_bssrf_test_02',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decision.authorizationDecisionId,
      actorId,
      endpointUrl: 'https://app.example.com/api/v1/user/avatar-url',
      parameterName: 'avatar_url',
      method: 'GET',
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
    grantId: 'grn_smoke_p7_2_loopback',
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
      authorizationDecisionId: 'dec_smoke_p7_2_loopback',
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

  const result3 = await runBlindSsrfDetection(
    {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'blind_ssrf_detection_request',
      detectionId: 'det_bssrf_test_03',
      assessmentId,
      scanId,
      authorizationGrantId: loopbackScopeGrant.grantId,
      authorizationDecisionId: loopbackDecision.authorizationDecisionId,
      actorId,
      endpointUrl: 'http://127.0.0.1:8080/admin/proxy',
      parameterName: 'url',
      method: 'GET',
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
  console.log('[TEST 4] Testing HITL review lifecycle promoting Blind SSRF draft to formal Finding...');
  const repo = new InMemoryOrchestratedAssessmentRepository();
  const appService = new OrchestratedAssessmentApplicationService({
    repository: repo,
  });

  const testAssessmentId = 'asm_bssrf_rev_001';
  const testScanId = 'scn_bssrf_rev_001';
  const draftId = 'dft_bssrf_rev_001';

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
      actorId: 'usr_sec_auditor_p72',
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
        sourceComparisonId: 'cmp_bssrf_rev_001',
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
        safeRationale: 'Confirmed blind SSRF on parameter webhook_url at https://app.example.com/api/v1/integrations/register.',
        differentialContext: {
          endpointUrl: 'https://app.example.com/api/v1/integrations/register',
          detectionKind: 'blind_ssrf' as const,
          parameterName: 'webhook_url',
          injectedCanaryUrl: 'https://oob.test.local/c/fgc_test_canary_01',
          canaryToken: 'fgc_test_canary_01',
          interactionConfirmed: true,
          remoteAddress: '198.51.100.77',
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
    reviewerId: 'usr_sec_auditor_p72',
    reviewedAt: nowIso,
    notes: 'Confirmed external request initiated by application backend upon registering webhook.',
  });

  if (!reviewRes.findingCreated || reviewRes.findingCreated.type !== 'SERVER_SIDE_REQUEST_FORGERY') {
    throw new Error(`Test 4 Failed: Expected promoted finding of type SERVER_SIDE_REQUEST_FORGERY, got ${JSON.stringify(reviewRes.findingCreated)}`);
  }

  if (reviewRes.findingCreated.severity !== 'critical') {
    throw new Error(`Test 4 Failed: Expected critical severity, got ${reviewRes.findingCreated.severity}`);
  }

  const updated = await repo.findById(testAssessmentId);
  if (!updated) {
    throw new Error('Test 4 Failed: Assessment not found in repository');
  }

  const promotedFinding = updated.findings.find((f) => f.id.startsWith('fnd_bssrf_'));
  if (!promotedFinding) {
    throw new Error('Test 4 Failed: Expected promoted Blind SSRF finding in repository');
  }

  console.log(`[TEST 4] PASS: Promoted Blind SSRF finding verified: ${promotedFinding.id} (${promotedFinding.title})`);

  // -------------------------------------------------------------------------
  // Test 5: Parameter Classifier Helper
  // -------------------------------------------------------------------------
  console.log('[TEST 5] Testing isSsrfCandidateParameter helper...');
  if (!isSsrfCandidateParameter('url') || !isSsrfCandidateParameter('webhook') || !isSsrfCandidateParameter('feed_url')) {
    throw new Error('Test 5 Failed: isSsrfCandidateParameter failed for candidate params');
  }
  if (isSsrfCandidateParameter('id') || isSsrfCandidateParameter('page_number') || isSsrfCandidateParameter('username')) {
    throw new Error('Test 5 Failed: isSsrfCandidateParameter falsely flagged benign params');
  }
  console.log('[TEST 5] PASS: isSsrfCandidateParameter verified.');

  console.log('\n[ALL TESTS PASSED] Milestone P7-2 Blind SSRF Detection Probe certified!\n');
}

runSmokeSuite().catch((err) => {
  console.error('[SMOKE TEST FAILED]', err);
  process.exit(1);
});
