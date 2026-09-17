/**
 * Milestone P4-1 Smoke Test Suite
 * Authentication Bypass Detection Engine (Milestone P4-1)
 *
 * Verifies:
 * 1. Detects authentication bypass when protected endpoint returns 200 OK anonymously with matching body.
 * 2. Cleanly abstains (secure_target_abstained) when unauthenticated request receives 401/403 or login redirect.
 * 3. Validates that sensitive session tokens remain redacted in captured snapshots and body fragments.
 * 4. Full HITL triage flow promotes draft to formal Finding with AuthBypassMetadata.
 */

import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import { runAuthBypassDetection } from '../detection/AuthBypassDetectionService.js';
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

console.log('[milestoneP4_1_auth_bypass_smoke] Starting Milestone P4-1 smoke suite...');

async function runTests(): Promise<void> {
  const lineage = {
    assessmentId: 'asm_test_p41_001',
    scanId: 'scn_test_p41_001',
    authorizationGrantId: 'grnt_test_p41_001',
    authorizationDecisionId: 'dec_test_p41_001',
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
      authorizationText: 'Authorized for Milestone P4-1 Auth Bypass smoke testing',
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
      pathTemplate: '/api/user/profile',
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

  // Assertion 1: Authentication Bypass Detection when protected endpoint returns 200 OK anonymously
  console.log('-> Test 1: Detects authentication bypass when protected endpoint returns 200 OK anonymously');
  let authHeaderPassed = false;
  let anonHeaderStripped = false;

  const mockVulnerableTransport: IdorHttpProbeTransport = async (
    req: HttpProbeRequest
  ): Promise<HttpProbeResponse> => {
    if (req.headers['authorization']?.includes('operator_token_a')) {
      authHeaderPassed = true;
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json', 'x-custom-meta': 'authenticated' },
        bodyText: JSON.stringify({ userId: 'u_1001', email: 'alice@example.com', role: 'admin', tier: 'enterprise' }),
        responseTimeMs: 25,
      };
    }

    // Anonymous request (stripped)
    if (!req.headers['authorization']) {
      anonHeaderStripped = true;
      // Flaw: server returns identical profile data anonymously
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json', 'x-custom-meta': 'anonymous' },
        bodyText: JSON.stringify({ userId: 'u_1001', email: 'alice@example.com', role: 'admin', tier: 'enterprise' }),
        responseTimeMs: 22,
      };
    }

    return { statusCode: 403, headers: {}, bodyText: 'Forbidden', responseTimeMs: 20 };
  };

  const bypassDetectResult = await runAuthBypassDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'auth_bypass_detection_request',
    detectionId: 'det_test_ab_001',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    authorizationGrantId: lineage.authorizationGrantId,
    authorizationDecisionId: lineage.authorizationDecisionId,
    actorId: lineage.actorId,
    endpointUrl: 'https://app.example.com/api/user/profile',
    method: 'GET',
    identityA: {
      identityId: 'user_alice',
      headers: { authorization: 'Bearer operator_token_a' },
    },
    bypassMechanism: 'header_stripping',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    transport: mockVulnerableTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  if (!authHeaderPassed || !anonHeaderStripped) {
    throw new Error('Test 1 Failed: Probes were not properly dispatched with and without credentials');
  }
  if (bypassDetectResult.status !== 'pending_human_review') {
    throw new Error(`Test 1 Failed: Expected status pending_human_review, got ${bypassDetectResult.status} (reasonCode: ${bypassDetectResult.reasonCode})`);
  }
  if (!bypassDetectResult.evidenceDraft) {
    throw new Error('Test 1 Failed: evidenceDraft was not generated');
  }
  if (bypassDetectResult.similarityRatio !== 1.0) {
    throw new Error(`Test 1 Failed: Expected similarityRatio 1.0, got ${bypassDetectResult.similarityRatio}`);
  }
  console.log('  [PASS] Authentication bypass detected and pending draft produced.');

  // Assertion 2: Clean Abstention on Enforced Access Control (401, 403, Login Redirect)
  console.log('-> Test 2: Cleanly abstains (secure_target_abstained) when unauthenticated probe is denied/redirected');
  
  // Case A: 401 Unauthorized
  const mock401Transport: IdorHttpProbeTransport = async (req): Promise<HttpProbeResponse> => {
    if (req.headers['authorization']) {
      return { statusCode: 200, headers: { 'content-type': 'application/json' }, bodyText: '{"data":"protected"}', responseTimeMs: 20 };
    }
    return { statusCode: 401, headers: {}, bodyText: 'Unauthorized', responseTimeMs: 15 };
  };

  const abstain401Result = await runAuthBypassDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'auth_bypass_detection_request',
    detectionId: 'det_test_ab_002',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    authorizationGrantId: lineage.authorizationGrantId,
    authorizationDecisionId: lineage.authorizationDecisionId,
    actorId: lineage.actorId,
    endpointUrl: 'https://app.example.com/api/user/profile',
    identityA: { identityId: 'user_alice', headers: { authorization: 'Bearer token_a' } },
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    transport: mock401Transport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  if (abstain401Result.status !== 'secure_target_abstained' || abstain401Result.reasonCode !== 'authentication_enforced') {
    throw new Error(`Test 2A Failed: Expected secure_target_abstained on 401, got ${abstain401Result.status} (${abstain401Result.reasonCode})`);
  }

  // Case B: 302 Redirect to /login
  const mock302Transport: IdorHttpProbeTransport = async (req): Promise<HttpProbeResponse> => {
    if (req.headers['authorization']) {
      return { statusCode: 200, headers: { 'content-type': 'application/json' }, bodyText: '{"data":"protected"}', responseTimeMs: 20 };
    }
    return { statusCode: 302, headers: { location: '/login' }, bodyText: '', responseTimeMs: 15 };
  };

  const abstain302Result = await runAuthBypassDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'auth_bypass_detection_request',
    detectionId: 'det_test_ab_003',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    authorizationGrantId: lineage.authorizationGrantId,
    authorizationDecisionId: lineage.authorizationDecisionId,
    actorId: lineage.actorId,
    endpointUrl: 'https://app.example.com/api/user/profile',
    identityA: { identityId: 'user_alice', headers: { authorization: 'Bearer token_a' } },
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    transport: mock302Transport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  if (abstain302Result.status !== 'secure_target_abstained' || abstain302Result.reasonCode !== 'authentication_enforced') {
    throw new Error(`Test 2B Failed: Expected secure_target_abstained on login redirect, got ${abstain302Result.status} (${abstain302Result.reasonCode})`);
  }
  console.log('  [PASS] Target abstention cleanly verified for 401 Unauthorized and 302 Login Redirect.');

  // Assertion 3: Anti-Leak Redaction of Session Tokens in Snapshots and Fragments
  console.log('-> Test 3: Validates sensitive session tokens remain redacted in snapshots and fragments');
  const baselineHeaders = bypassDetectResult.baselineSnapshot?.headerNames ?? [];
  const validationHeaders = bypassDetectResult.validationSnapshot?.headerNames ?? [];

  if (baselineHeaders.includes('authorization') || baselineHeaders.includes('cookie')) {
    throw new Error('Test 3 Failed: Sensitive authorization header found in baseline snapshot headerNames');
  }
  if (validationHeaders.includes('authorization') || validationHeaders.includes('cookie')) {
    throw new Error('Test 3 Failed: Sensitive authorization header found in validation snapshot headerNames');
  }

  const rawExcerpt = `Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.sig456 with cookie session=session_cookie_123`;
  const sanitized = sanitizeEvidenceFragment(rawExcerpt);
  if (sanitized.includes('sig456') || sanitized.includes('session_cookie_123')) {
    throw new Error('Test 3 Failed: Sensitive tokens leaked through evidence fragment');
  }
  console.log('  [PASS] Anti-leak redaction confirmed across snapshot headers and fragments.');

  // Assertion 4: Full Orchestrated Assessment Pipeline & HITL Triage Integration
  console.log('-> Test 4: Full Orchestrated Assessment Pipeline & HITL Triage for Auth Bypass');
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const service = new OrchestratedAssessmentApplicationService({
    repository,
    dnsResolver: async () => ['93.184.216.34'],
    availabilityService: mockAvailabilityService,
    httpTransport: mockVulnerableTransport,
  });

  const sessionBundle: ByotSessionIdentityBundle = {
    identityA: {
      identityId: 'operator_alice',
      injectHeaders: { authorization: 'Bearer operator_token_a' },
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
  const authBypassDraft = draftsResult.drafts.find((d) => d.differentialContext?.detectionKind === 'auth_bypass');

  if (!authBypassDraft) {
    throw new Error('Test 4 Failed: Expected auth_bypass draft in pendingEvidenceDrafts');
  }

  // Operator Reviews & Approves Auth Bypass Draft
  const triageApprove = await service.reviewEvidenceDraft({
    assessmentId: startRes.assessmentId,
    draftId: authBypassDraft.draftId,
    decision: 'approve_evidence',
    reviewerId: 'usr_lead_analyst',
    reviewedAt: new Date().toISOString(),
    notes: 'Confirmed authentication bypass on unprotected profile resource',
  });

  if (triageApprove.decision !== 'approve_evidence') {
    throw new Error('Test 4 Failed: Triage approval failed');
  }

  const summary = await service.getSummary(startRes.assessmentId);
  const bypassFinding = summary.findings.find((f: Finding) => f.type === 'BROKEN_AUTHENTICATION');

  if (!bypassFinding) {
    throw new Error('Test 4 Failed: Finding not promoted to formal BROKEN_AUTHENTICATION');
  }
  if (bypassFinding.severity !== 'high') {
    throw new Error(`Test 4 Failed: Expected severity high, got ${bypassFinding.severity}`);
  }
  if (bypassFinding.metadata?.kind !== 'auth_bypass_metadata') {
    throw new Error(`Test 4 Failed: Expected auth_bypass_metadata, got ${bypassFinding.metadata?.kind}`);
  }

  console.log('  [PASS] Full pipeline produced Auth Bypass draft and promoted to BROKEN_AUTHENTICATION finding on HITL approval.');

  console.log('[milestoneP4_1_auth_bypass_smoke] ALL SMOKE TESTS PASSED (100%)');
}

runTests().catch((err) => {
  console.error('[milestoneP4_1_auth_bypass_smoke] TEST FAILED:', err);
  process.exit(1);
});
