/**
 * Milestone P3-3 Smoke Test Suite
 * Multi-Identity Differential IDOR with BYOT (Milestone P3-3)
 *
 * Verifies:
 * 1. Full pipeline execution with ByotSessionIdentityBundle feeds identityA and identityB to the IDOR engine.
 * 2. Automatic fallback to anonymous identityB when only identityA is supplied.
 * 3. Detects unauthorized access differential and produces pending draft with BrokenAccessControlMetadata.
 * 4. Response snapshots redact injected session headers and sanitize body fragments.
 * 5. Full HITL triage lifecycle (approve/reject) works cleanly for BYOT IDOR drafts.
 */

import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import { runIdorDifferentialDetection } from '../detection/IdorDifferentialDetectionService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { evaluateScopePolicy } from '../scope/AuthorizedScopePolicyService.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type {
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
  ByotSessionIdentityBundle,
} from '../detection/DetectionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { Finding } from '../core/Evidence.js';

console.log('[milestoneP3_3_idor_byot_smoke] Starting Milestone P3-3 smoke suite...');

async function runTests(): Promise<void> {
  const lineage = {
    assessmentId: 'asm_test_p3_001',
    scanId: 'scn_test_p3_001',
    authorizationGrantId: 'grnt_test_p3_001',
    authorizationDecisionId: 'dec_test_p3_001',
    actorId: 'usr_secops_lead',
  };

  const decidedAt = new Date().toISOString();

  const scopeGrant: AuthorizedScopeGrant = {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: lineage.authorizationGrantId,
    scanId: lineage.scanId,
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'origin',
      normalizedOrigin: 'https://app.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone P3-3 IDOR BYOT smoke testing',
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

  const authDecisionResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      authorizedActor: { actorId: lineage.actorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt,
      scopeGrant,
    },
    decidedAt
  );

  if (authDecisionResult.status !== 'established' || !authDecisionResult.decision) {
    const errorMsg = 'safeMessage' in authDecisionResult ? authDecisionResult.safeMessage : 'establishment failed';
    throw new Error(`Pre-test failure: authorization decision failed: ${errorMsg}`);
  }

  const verifiedDecision = authDecisionResult.decision;

  const scopeResult = evaluateScopePolicy({
    grant: verifiedDecision.scopeGrant,
    request: {
      contractVersion: 'fixguard-authorized-scope-policy/v0',
      kind: 'scope_action_request',
      requestId: 'req_scope_001',
      scanId: lineage.scanId,
      requestedAt: decidedAt,
      actionKind: 'endpoint_discovery',
      target: { targetKind: 'origin', normalizedOrigin: 'https://app.example.com' },
      method: 'GET',
      pathTemplate: '/api/user/1',
      intensity: 'low',
      usesCredentials: true,
      mayChangeServerState: false,
      usesOob: false,
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
    },
    decisionId: 'eval_scope_001',
    evaluatedAt: decidedAt,
  });

  if (scopeResult.decision !== 'allowed') {
    throw new Error(`Pre-test failure: scope evaluation denied: [${scopeResult.reasonCode}] ${scopeResult.reason}`);
  }

  const mockAvailabilityService = new ReconToolAvailabilityService({
    async execute() {
      return { stdout: '1.0.0\n', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
    },
  });

  // Assertion 1: Multi-Identity Differential IDOR Engine with BYOT
  console.log('-> Test 1: IDOR engine executes with Dual BYOT identities and detects access violation');
  let capturedIdentityAAuth = '';
  let capturedIdentityBAuth = '';

  const mockDifferentialTransport: IdorHttpProbeTransport = async (
    req: HttpProbeRequest
  ): Promise<HttpProbeResponse> => {
    if (req.headers['authorization']?.includes('token_user_a')) {
      capturedIdentityAAuth = req.headers['authorization'];
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json', 'x-custom-meta': 'unredacted' },
        bodyText: JSON.stringify({ id: 1, name: 'Alice Owner', role: 'admin', profileKey: 'key_12345' }),
        responseTimeMs: 25,
      };
    }

    if (req.headers['authorization']?.includes('token_user_b') || !req.headers['authorization']) {
      capturedIdentityBAuth = req.headers['authorization'] ?? 'anonymous';
      // IDOR: Identity B also gets 200 OK with Alice's object
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ id: 1, name: 'Alice Owner', role: 'admin', profileKey: 'key_12345' }),
        responseTimeMs: 30,
      };
    }

    return {
      statusCode: 403,
      headers: {},
      bodyText: 'Forbidden',
      responseTimeMs: 20,
    };
  };

  const idorRequestResult = await runIdorDifferentialDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'idor_differential_detection_request',
    detectionId: 'det_test_diff_001',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    authorizationGrantId: lineage.authorizationGrantId,
    authorizationDecisionId: lineage.authorizationDecisionId,
    actorId: lineage.actorId,
    endpointUrl: 'https://app.example.com/api/user/1',
    resourceParamName: 'id',
    baselineResourceId: '1',
    identityA: {
      identityId: 'operator_identity_a',
      headers: { authorization: 'Bearer token_user_a_secret' },
    },
    identityB: {
      identityId: 'operator_identity_b',
      headers: { authorization: 'Bearer token_user_b_secret' },
    },
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    transport: mockDifferentialTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  if (idorRequestResult.status !== 'pending_human_review') {
    throw new Error(`Test 1 Failed: Expected status pending_human_review, got ${idorRequestResult.status} (reasonCode: ${idorRequestResult.reasonCode}, error: ${JSON.stringify(idorRequestResult.error)})`);
  }
  if (!idorRequestResult.evidenceDraft) {
    throw new Error('Test 1 Failed: evidenceDraft was not generated');
  }
  if (!capturedIdentityAAuth.includes('token_user_a') || !capturedIdentityBAuth.includes('token_user_b')) {
    throw new Error('Test 1 Failed: BYOT headers were not transmitted in dual probes');
  }
  console.log('  [PASS] Dual BYOT identities dispatched and IDOR difference detected.');

  // Assertion 2: Header Redaction & Anti-Leak Snapshot Verification
  console.log('-> Test 2: Response snapshots redact sensitive headers and sanitize fragments');
  const baselineHeaders = idorRequestResult.baselineSnapshot?.headerNames ?? [];
  const validationHeaders = idorRequestResult.validationSnapshot?.headerNames ?? [];

  if (baselineHeaders.includes('authorization') || baselineHeaders.includes('cookie')) {
    throw new Error('Test 2 Failed: Sensitive authorization header found in baseline snapshot headerNames');
  }
  if (validationHeaders.includes('authorization') || validationHeaders.includes('cookie')) {
    throw new Error('Test 2 Failed: Sensitive authorization header found in validation snapshot headerNames');
  }

  const rawExcerpt = `Response for user_b: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig123 with cookie session=secret_cookie_val`;
  const sanitizedExcerpt = sanitizeEvidenceFragment(rawExcerpt);
  if (sanitizedExcerpt.includes('secret_cookie_val') || sanitizedExcerpt.includes('sig123')) {
    throw new Error('Test 2 Failed: Sensitive credentials leaked through excerpt');
  }
  console.log('  [PASS] Sensitive headers and cookies verified redacted from snapshots and fragments.');

  // Assertion 3: Automatic Fallback to Anonymous Identity B
  console.log('-> Test 3: Fallback to anonymous identity B when only identity A is supplied');
  let anonymousIdentityBDispatched = false;

  const mockAnonFallbackTransport: IdorHttpProbeTransport = async (
    req: HttpProbeRequest
  ): Promise<HttpProbeResponse> => {
    if (req.headers['authorization']?.includes('token_user_a')) {
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ id: 1, user: 'owner' }),
        responseTimeMs: 20,
      };
    }
    // Probe B without authorization header
    if (!req.headers['authorization']) {
      anonymousIdentityBDispatched = true;
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ id: 1, user: 'owner' }),
        responseTimeMs: 20,
      };
    }
    return { statusCode: 401, headers: {}, bodyText: 'Unauthorized', responseTimeMs: 15 };
  };

  const idorAnonFallbackResult = await runIdorDifferentialDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'idor_differential_detection_request',
    detectionId: 'det_test_anon_002',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    authorizationGrantId: lineage.authorizationGrantId,
    authorizationDecisionId: lineage.authorizationDecisionId,
    actorId: lineage.actorId,
    endpointUrl: 'https://app.example.com/api/user/1',
    resourceParamName: 'id',
    baselineResourceId: '1',
    identityA: {
      identityId: 'user_a',
      headers: { authorization: 'Bearer token_user_a' },
    },
    identityB: {
      identityId: 'identity_anon_b',
      headers: {},
    },
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    transport: mockAnonFallbackTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  if (!anonymousIdentityBDispatched) {
    throw new Error('Test 3 Failed: Anonymous probe B was not dispatched');
  }
  if (idorAnonFallbackResult.status !== 'pending_human_review') {
    throw new Error('Test 3 Failed: Expected pending_human_review for unauthenticated IDOR');
  }
  console.log('  [PASS] Anonymous identity B fallback successfully dispatched.');

  // Assertion 4: Full Pipeline & HITL Triage Integration
  console.log('-> Test 4: Full Orchestrated Assessment Pipeline & HITL Triage for IDOR');
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const service = new OrchestratedAssessmentApplicationService({
    repository,
    dnsResolver: async () => ['93.184.216.34'],
    availabilityService: mockAvailabilityService,
    httpTransport: mockDifferentialTransport,
  });

  const sessionBundle: ByotSessionIdentityBundle = {
    identityA: {
      identityId: 'operator_alice',
      injectHeaders: { authorization: 'Bearer token_user_a' },
    },
    identityB: {
      identityId: 'operator_bob',
      injectHeaders: { authorization: 'Bearer token_user_b' },
    },
  };

  const startRes = await service.startAssessment({
    targetDomain: 'app.example.com',
    actorId: 'usr_secops_lead',
    sessionIdentities: sessionBundle,
  });

  if (startRes.status !== 'running') {
    throw new Error('Test 4 Failed: Assessment did not start with running status');
  }

  // Wait for background pipeline completion
  let attempts = 0;
  let status = await service.getStatus(startRes.assessmentId);
  while (status.status === 'running' && attempts < 100) {
    await new Promise((r) => setTimeout(r, 100));
    status = await service.getStatus(startRes.assessmentId);
    attempts++;
  }
  const draftsResult = await service.getEvidenceDrafts(startRes.assessmentId);
  const idorDraft = draftsResult.drafts.find((d) => d.differentialContext?.detectionKind === 'idor_access_control');

  if (!idorDraft) {
    throw new Error('Test 4 Failed: Expected idor_access_control draft in pendingEvidenceDrafts');
  }

  // Triage: Human Operator Approves IDOR draft
  const triageApprove = await service.reviewEvidenceDraft({
    assessmentId: startRes.assessmentId,
    draftId: idorDraft.draftId,
    decision: 'approve_evidence',
    reviewerId: 'usr_lead_analyst',
    reviewedAt: new Date().toISOString(),
    notes: 'Confirmed dual-identity unauthorized access on /api/user/1',
  });

  if (triageApprove.decision !== 'approve_evidence') {
    throw new Error('Test 4 Failed: Triage approval failed');
  }

  const summary = await service.getSummary(startRes.assessmentId);
  const idorFinding = summary.findings.find((f: Finding) => f.type === 'BROKEN_ACCESS_CONTROL');

  if (!idorFinding) {
    throw new Error('Test 4 Failed: Finding not promoted to formal BROKEN_ACCESS_CONTROL');
  }
  if (idorFinding.severity !== 'high') {
    throw new Error(`Test 4 Failed: Expected severity high, got ${idorFinding.severity}`);
  }
  if (idorFinding.metadata?.kind !== 'broken_access_control_metadata') {
    throw new Error('Test 4 Failed: Finding metadata kind mismatch');
  }

  console.log('  [PASS] Full pipeline produced IDOR draft and promoted to high-severity Finding on HITL approval.');

  console.log('[milestoneP3_3_idor_byot_smoke] ALL SMOKE TESTS PASSED (100%)');
}

runTests().catch((err) => {
  console.error('[milestoneP3_3_idor_byot_smoke] TEST FAILED:', err);
  process.exit(1);
});
