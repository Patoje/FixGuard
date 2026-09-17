/**
 * Milestone P4-8 Smoke Test Suite
 * Session Fixation Detection Engine (Milestone P4-8)
 *
 * Verifies:
 * 1. Detects session fixation when server accepts caller-supplied cookie without issuing Set-Cookie regeneration.
 * 2. Cleanly abstains (secure_target_abstained) when server properly issues fresh Set-Cookie replacing the synthetic token.
 * 3. Cleanly abstains when server rejects caller-supplied session token with 401/403.
 * 4. Preflight and egress gates block internal/SSRF targets.
 * 5. Full HITL triage lifecycle promotes drafts to formal Findings.
 */

import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import { runSessionFixationDetection } from '../detection/SessionFixationDetectionService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type {
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from '../detection/DetectionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { Finding, SessionFixationMetadata } from '../core/Evidence.js';

console.log('[milestoneP4_8_session_fixation_smoke] Starting Milestone P4-8 smoke suite...');

async function runTests(): Promise<void> {
  const lineage = {
    assessmentId: 'asm_test_p48_001',
    scanId: 'scn_test_p48_001',
    authorizationGrantId: 'grnt_test_p48_001',
    authorizationDecisionId: 'dec_test_p48_001',
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
      authorizationText: 'Authorized for Milestone P4-8 Session Fixation smoke testing',
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
      allowLoginRequiredAreas: false,
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
    throw new Error('Failed to establish verified authorization decision for smoke test');
  }

  const authDecision = authDecisionResult.decision;

  // -------------------------------------------------------------------------
  // Test 1: Detects session fixation when server accepts caller-supplied cookie
  // -------------------------------------------------------------------------
  console.log('--- Test 1: Detects session fixation when server accepts caller-supplied cookie ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      // Server returns 200 OK and DOES NOT issue a Set-Cookie header overriding the injected PHPSESSID
      return {
        statusCode: 200,
        headers: {
          'content-type': 'text/html; charset=utf-8',
          server: 'Apache/2.4.41',
        },
        bodyText: `<html><body>Welcome to Dashboard. Session active: ${req.headers['Cookie']}</body></html>`,
        responseTimeMs: 25,
      };
    };

    const result = await runSessionFixationDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'session_fixation_detection_request',
      detectionId: 'det_test_p48_fixation',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'https://app.example.com/dashboard',
      httpMethod: 'GET',
      sessionCookieName: 'PHPSESSID',
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      transport: mockTransport,
      humanReviewDecision: {
        reviewerId: 'usr_secops_lead',
        reviewedAt: new Date().toISOString(),
        decision: 'approve_evidence',
      },
    });

    if (result.status !== 'vulnerability_detected') {
      throw new Error(`Test 1 Failed: Expected status 'vulnerability_detected', got '${result.status}'`);
    }
    if (result.serverRegeneratedSession !== false) {
      throw new Error('Test 1 Failed: Expected serverRegeneratedSession to be false');
    }
    if (!result.finding) {
      throw new Error('Test 1 Failed: Expected finding to be constructed');
    }
    const meta = result.finding.metadata as SessionFixationMetadata;
    if (meta.kind !== 'session_fixation_metadata' || meta.category !== 'BROKEN_AUTHENTICATION') {
      throw new Error(`Test 1 Failed: Invalid metadata: ${JSON.stringify(meta)}`);
    }
    if (meta.sessionCookieName !== 'PHPSESSID' || !meta.fixedSessionId.startsWith('fixguard_fix_')) {
      throw new Error(`Test 1 Failed: Invalid cookie name or fixedSessionId in metadata: ${JSON.stringify(meta)}`);
    }

    console.log('✓ Test 1 Passed: Session fixation correctly identified');
  }

  // -------------------------------------------------------------------------
  // Test 2: Cleanly abstains when server properly issues fresh Set-Cookie
  // -------------------------------------------------------------------------
  console.log('--- Test 2: Cleanly abstains when server issues fresh Set-Cookie (regeneration) ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => {
      // Server properly regenerates the session by issuing a new Set-Cookie header
      return {
        statusCode: 200,
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'set-cookie': 'PHPSESSID=fresh_server_generated_session_token_xyz; Path=/; HttpOnly; Secure',
        },
        bodyText: '<html><body>Welcome to Dashboard</body></html>',
        responseTimeMs: 25,
      };
    };

    const result = await runSessionFixationDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'session_fixation_detection_request',
      detectionId: 'det_test_p48_regen',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'https://app.example.com/dashboard',
      httpMethod: 'GET',
      sessionCookieName: 'PHPSESSID',
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      transport: mockTransport,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`Test 2 Failed: Expected status 'secure_target_abstained', got '${result.status}'`);
    }
    if (result.reasonCode !== 'session_regenerated_by_server') {
      throw new Error(`Test 2 Failed: Expected reasonCode 'session_regenerated_by_server', got '${result.reasonCode}'`);
    }
    if (result.serverRegeneratedSession !== true) {
      throw new Error('Test 2 Failed: Expected serverRegeneratedSession to be true');
    }

    console.log('✓ Test 2 Passed: Hardened session regeneration cleanly abstained');
  }

  // -------------------------------------------------------------------------
  // Test 3: Cleanly abstains when server rejects probe with 401/403
  // -------------------------------------------------------------------------
  console.log('--- Test 3: Cleanly abstains when server rejects probe with 401/403 ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => {
      return {
        statusCode: 401,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ error: 'Unauthorized: Invalid or unrecognized session' }),
        responseTimeMs: 20,
      };
    };

    const result = await runSessionFixationDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'session_fixation_detection_request',
      detectionId: 'det_test_p48_denied',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'https://app.example.com/dashboard',
      httpMethod: 'GET',
      sessionCookieName: 'PHPSESSID',
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      transport: mockTransport,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`Test 3 Failed: Expected status 'secure_target_abstained', got '${result.status}'`);
    }
    if (result.reasonCode !== 'session_probe_denied') {
      throw new Error(`Test 3 Failed: Expected reasonCode 'session_probe_denied', got '${result.reasonCode}'`);
    }

    console.log('✓ Test 3 Passed: 401/403 rejection cleanly abstained');
  }

  // -------------------------------------------------------------------------
  // Test 4: Preflight and egress gates block internal/SSRF targets
  // -------------------------------------------------------------------------
  console.log('--- Test 4: Preflight and egress gates block internal/SSRF targets ---');
  {
    const internalScopeGrant: AuthorizedScopeGrant = {
      ...scopeGrant,
      subject: {
        targetKind: 'origin',
        normalizedOrigin: 'http://169.254.169.254',
      },
      boundaries: {
        allowedDomains: ['169.254.169.254'],
        allowedHosts: ['169.254.169.254'],
        allowedOrigins: ['http://169.254.169.254'],
        allowedMethods: ['GET'],
      },
    };

    const internalAuthDecisionResult = establishVerifiedAuthorizationDecision(
      {
        contractVersion: 'fixguard-verified-authorization-decision/v0',
        kind: 'establish_verified_authorization_decision_request',
        assessmentId: lineage.assessmentId,
        scanId: lineage.scanId,
        authorizationDecisionId: lineage.authorizationDecisionId,
        authorizedActor: { actorId: lineage.actorId, actorType: 'human' },
        decision: 'authorized',
        decidedAt,
        scopeGrant: internalScopeGrant,
      },
      decidedAt
    );

    if (internalAuthDecisionResult.status !== 'established' || !internalAuthDecisionResult.decision) {
      throw new Error('Failed to establish internal auth decision');
    }

    const result = await runSessionFixationDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'session_fixation_detection_request',
      detectionId: 'det_test_p48_ssrf',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'http://169.254.169.254/latest/meta-data/',
      verifiedAuthorizationDecision: internalAuthDecisionResult.decision,
      scopeGrant: internalScopeGrant,
    });

    if (result.status !== 'preflight_denied') {
      throw new Error(`Test 4 Failed: Expected status 'preflight_denied', got '${result.status}'`);
    }

    console.log('✓ Test 4 Passed: SSRF target safely blocked at preflight boundary');
  }

  // -------------------------------------------------------------------------
  // Test 5: Full HITL triage lifecycle promotes drafts to formal Findings
  // -------------------------------------------------------------------------
  console.log('--- Test 5: Full HITL triage lifecycle promotes drafts to formal Findings ---');
  {
    const repository = new InMemoryOrchestratedAssessmentRepository();
    const availabilityService = new ReconToolAvailabilityService({
      async execute() {
        return { stdout: '1.0.0\n', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
      },
    });

    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        bodyText: `<html><body>App active on ${req.url}</body></html>`,
        responseTimeMs: 20,
      };
    };

    const mockDnsResolver = async (_host: string): Promise<string[]> => ['93.184.216.34'];

    const appService = new OrchestratedAssessmentApplicationService({
      repository,
      availabilityService,
      httpTransport: mockTransport,
      dnsResolver: mockDnsResolver,
    });

    const startRes = await appService.startAssessment({
      targetDomain: 'app.example.com',
      actorId: 'usr_secops_lead',
    });

    if (startRes.status !== 'running') {
      throw new Error(`Test 5 Failed: Assessment did not start with running status: ${startRes.status}`);
    }

    let attempts = 0;
    let status = await appService.getStatus(startRes.assessmentId);
    while (status.status === 'running' && attempts < 100) {
      await new Promise((r) => setTimeout(r, 100));
      status = await appService.getStatus(startRes.assessmentId);
      attempts++;
    }

    const draftsResponse = await appService.getEvidenceDrafts(startRes.assessmentId);
    const fixDraft = draftsResponse.drafts.find(
      (d) => d.differentialContext?.detectionKind === 'session_fixation'
    );

    if (!fixDraft) {
      throw new Error(`Test 5 Failed: Expected pending Session Fixation draft, found: ${JSON.stringify(draftsResponse.drafts.map((d) => d.differentialContext?.detectionKind))}`);
    }

    if (fixDraft.differentialContext?.sessionCookieName !== 'PHPSESSID') {
      throw new Error(`Test 5 Failed: Expected sessionCookieName 'PHPSESSID', got '${fixDraft.differentialContext?.sessionCookieName}'`);
    }

    // Perform HITL review promotion
    const reviewResult = await appService.reviewEvidenceDraft({
      assessmentId: startRes.assessmentId,
      draftId: fixDraft.draftId,
      decision: 'approve_evidence',
      reviewerId: 'usr_secops_lead',
      reviewedAt: new Date().toISOString(),
      notes: 'Confirmed session fixation in staging environment without Set-Cookie regeneration.',
    });

    if (reviewResult.decision !== 'approve_evidence' || !reviewResult.findingCreated) {
      throw new Error(`Test 5 Failed: Review promotion failed: ${JSON.stringify(reviewResult)}`);
    }

    const promotedFinding = reviewResult.findingCreated;
    if (promotedFinding.type !== 'BROKEN_AUTHENTICATION') {
      throw new Error(`Test 5 Failed: Expected finding type 'BROKEN_AUTHENTICATION', got '${promotedFinding.type}'`);
    }

    const findingMeta = promotedFinding.metadata as SessionFixationMetadata;
    if (findingMeta.kind !== 'session_fixation_metadata' || findingMeta.sessionCookieName !== 'PHPSESSID') {
      throw new Error(`Test 5 Failed: Invalid promoted finding metadata: ${JSON.stringify(findingMeta)}`);
    }

    const summary = await appService.getSummary(startRes.assessmentId);
    const summaryFinding = summary.findings.find((f: Finding) => f.metadata?.kind === 'session_fixation_metadata');
    if (!summaryFinding) {
      throw new Error('Test 5 Failed: Promoted Session Fixation finding not found in assessment summary');
    }

    console.log('✓ Test 5 Passed: HITL review approved and promoted Session Fixation draft to formal Finding');
  }

  console.log('\n[milestoneP4_8_session_fixation_smoke] ALL 5 TESTS PASSED SUCCESSFULLY! (100% compliant)');
}

runTests().catch((err) => {
  console.error('[milestoneP4_8_session_fixation_smoke] FATAL ERROR:', err);
  process.exit(1);
});
