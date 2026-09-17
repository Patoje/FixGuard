/**
 * Milestone P4-7 Smoke Test Suite
 * JWT Algorithm Confusion Probe (Milestone P4-7)
 *
 * Verifies:
 * 1. Detects signature bypass when endpoint accepts 'alg: none' JWT with 200 OK.
 * 2. Cleanly abstains (secure_target_abstained) when endpoint rejects 'alg: none' with 401/403.
 * 3. Cleanly abstains when identityA does not contain a JWT Bearer token (no_jwt_bearer_detected).
 * 4. Response snapshots and evidence fragments redact JWT tokens in headers and bodies.
 * 5. Full HITL triage lifecycle promotes drafts to formal Findings.
 */

import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import { runJwtAlgorithmConfusionDetection } from '../detection/JwtAlgorithmConfusionDetectionService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { evaluateScopePolicy } from '../scope/AuthorizedScopePolicyService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type {
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
  ProbeAuthContext,
} from '../detection/DetectionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { Finding, JwtAlgorithmConfusionMetadata } from '../core/Evidence.js';

console.log('[milestoneP4_7_jwt_confusion_smoke] Starting Milestone P4-7 smoke suite...');

async function runTests(): Promise<void> {
  const lineage = {
    assessmentId: 'asm_test_p47_001',
    scanId: 'scn_test_p47_001',
    authorizationGrantId: 'grnt_test_p47_001',
    authorizationDecisionId: 'dec_test_p47_001',
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
      normalizedOrigin: 'https://api.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone P4-7 JWT Confusion smoke testing',
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

  // Sample genuine JWT with HS256 algorithm
  const sampleHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const samplePayload = Buffer.from(JSON.stringify({ sub: 'usr_123', role: 'admin', exp: 1999999999 })).toString('base64url');
  const sampleSignature = 'sampleSignatureMockValue12345';
  const legitimateJwt = `${sampleHeader}.${samplePayload}.${sampleSignature}`;

  const validJwtIdentityContext: ProbeAuthContext = {
    identityId: 'id_user_a',
    headers: {
      authorization: `Bearer ${legitimateJwt}`,
    },
    cookies: {},
  };

  // -------------------------------------------------------------------------
  // Test 1: Detects signature bypass when endpoint accepts 'alg: none' JWT
  // -------------------------------------------------------------------------
  console.log('--- Test 1: Detects signature bypass when endpoint accepts alg: none JWT ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      const auth = req.headers['authorization'] ?? req.headers['Authorization'] ?? '';
      if (auth.includes('Bearer')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({ message: 'Welcome user', user: 'usr_123' }),
          responseTimeMs: 20,
        };
      }
      return {
        statusCode: 401,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ error: 'Unauthorized' }),
        responseTimeMs: 20,
      };
    };

    const result = await runJwtAlgorithmConfusionDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'jwt_algorithm_confusion_detection_request',
      detectionId: 'det_test_p47_bypass',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'https://api.example.com/api/user/profile',
      httpMethod: 'GET',
      identityAContext: validJwtIdentityContext,
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
    if (result.originalAlgorithm !== 'HS256' || result.manipulatedAlgorithm !== 'none') {
      throw new Error(`Test 1 Failed: Expected HS256 -> none, got ${result.originalAlgorithm} -> ${result.manipulatedAlgorithm}`);
    }
    if (!result.finding) {
      throw new Error('Test 1 Failed: Expected finding to be constructed');
    }
    const meta = result.finding.metadata as JwtAlgorithmConfusionMetadata;
    if (meta.kind !== 'jwt_algorithm_confusion_metadata' || meta.category !== 'BROKEN_AUTHENTICATION') {
      throw new Error(`Test 1 Failed: Invalid metadata: ${JSON.stringify(meta)}`);
    }

    console.log('✓ Test 1 Passed: Signature bypass with alg: none correctly identified');
  }

  // -------------------------------------------------------------------------
  // Test 2: Cleanly abstains when endpoint rejects 'alg: none' JWT with 401/403
  // -------------------------------------------------------------------------
  console.log('--- Test 2: Cleanly abstains when endpoint rejects alg: none with 401/403 ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      const auth = req.headers['authorization'] ?? req.headers['Authorization'] ?? '';
      // If signature is empty (alg: none), reject with 401
      if (auth.endsWith('.')) {
        return {
          statusCode: 401,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({ error: 'Invalid JWT signature or unsigned token not allowed' }),
          responseTimeMs: 20,
        };
      }
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ message: 'Authenticated' }),
        responseTimeMs: 20,
      };
    };

    const result = await runJwtAlgorithmConfusionDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'jwt_algorithm_confusion_detection_request',
      detectionId: 'det_test_p47_reject',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'https://api.example.com/api/user/profile',
      httpMethod: 'GET',
      identityAContext: validJwtIdentityContext,
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      transport: mockTransport,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`Test 2 Failed: Expected status 'secure_target_abstained', got '${result.status}'`);
    }
    if (result.reasonCode !== 'signature_verification_enforced') {
      throw new Error(`Test 2 Failed: Expected reasonCode 'signature_verification_enforced', got '${result.reasonCode}'`);
    }

    console.log('✓ Test 2 Passed: Hardened JWT endpoint cleanly abstained');
  }

  // -------------------------------------------------------------------------
  // Test 3: Cleanly abstains when identityA does not contain a JWT Bearer token
  // -------------------------------------------------------------------------
  console.log('--- Test 3: Cleanly abstains when identityA does not contain a JWT Bearer ---');
  {
    const nonJwtContext: ProbeAuthContext = {
      identityId: 'id_user_a',
      headers: {
        authorization: 'Basic dXNlcjpwYXNz',
      },
      cookies: {},
    };

    const result = await runJwtAlgorithmConfusionDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'jwt_algorithm_confusion_detection_request',
      detectionId: 'det_test_p47_no_jwt',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'https://api.example.com/api/user/profile',
      identityAContext: nonJwtContext,
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`Test 3 Failed: Expected status 'secure_target_abstained', got '${result.status}'`);
    }
    if (result.reasonCode !== 'no_jwt_bearer_detected') {
      throw new Error(`Test 3 Failed: Expected reasonCode 'no_jwt_bearer_detected', got '${result.reasonCode}'`);
    }

    console.log('✓ Test 3 Passed: Non-JWT identity cleanly abstained');
  }

  // -------------------------------------------------------------------------
  // Test 4: Response snapshots and evidence fragments redact JWT tokens
  // -------------------------------------------------------------------------
  console.log('--- Test 4: Anti-leak verification in evidence fragment ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => {
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ status: 'ok', tokenRefreshed: legitimateJwt }),
        responseTimeMs: 20,
      };
    };

    const result = await runJwtAlgorithmConfusionDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'jwt_algorithm_confusion_detection_request',
      detectionId: 'det_test_p47_leak_check',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'https://api.example.com/api/user/profile',
      identityAContext: validJwtIdentityContext,
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      transport: mockTransport,
      humanReviewDecision: {
        reviewerId: 'usr_secops_lead',
        reviewedAt: new Date().toISOString(),
        decision: 'approve_evidence',
      },
    });

    if (result.status !== 'vulnerability_detected' || !result.finding) {
      throw new Error('Test 4 Failed: Expected finding');
    }

    const evidenceStr = result.finding.evidence;
    if (evidenceStr.includes(sampleSignature) || evidenceStr.includes(legitimateJwt)) {
      throw new Error('Test 4 Failed: Evidence fragment leaks raw JWT token or signature');
    }

    console.log('✓ Test 4 Passed: Anti-leak redaction confirmed across evidence output');
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
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ message: 'Authenticated with token', path: req.url }),
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
      targetDomain: 'api.example.com',
      actorId: 'usr_secops_lead',
      sessionIdentities: {
        identityA: {
          identityId: 'usr_jwt_owner',
          injectHeaders: {
            authorization: `Bearer ${legitimateJwt}`,
          },
        },
      },
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
    const jwtDraft = draftsResponse.drafts.find(
      (d) => d.differentialContext?.detectionKind === 'jwt_algorithm_confusion'
    );

    if (!jwtDraft) {
      throw new Error(`Test 5 Failed: Expected pending JWT confusion draft, found: ${JSON.stringify(draftsResponse.drafts.map((d) => d.differentialContext?.detectionKind))}`);
    }

    if (jwtDraft.differentialContext?.originalAlgorithm !== 'HS256' || jwtDraft.differentialContext?.manipulatedAlgorithm !== 'none') {
      throw new Error(`Test 5 Failed: Expected HS256 -> none, got ${jwtDraft.differentialContext?.originalAlgorithm} -> ${jwtDraft.differentialContext?.manipulatedAlgorithm}`);
    }

    // Perform HITL review promotion
    const reviewResult = await appService.reviewEvidenceDraft({
      assessmentId: startRes.assessmentId,
      draftId: jwtDraft.draftId,
      decision: 'approve_evidence',
      reviewerId: 'usr_secops_lead',
      reviewedAt: new Date().toISOString(),
      notes: 'Confirmed JWT signature bypass via alg: none in staging.',
    });

    if (reviewResult.decision !== 'approve_evidence' || !reviewResult.findingCreated) {
      throw new Error(`Test 5 Failed: Review promotion failed: ${JSON.stringify(reviewResult)}`);
    }

    const promotedFinding = reviewResult.findingCreated;
    if (promotedFinding.type !== 'BROKEN_AUTHENTICATION') {
      throw new Error(`Test 5 Failed: Expected finding type 'BROKEN_AUTHENTICATION', got '${promotedFinding.type}'`);
    }

    const findingMeta = promotedFinding.metadata as JwtAlgorithmConfusionMetadata;
    if (findingMeta.kind !== 'jwt_algorithm_confusion_metadata' || findingMeta.manipulatedAlgorithm !== 'none') {
      throw new Error(`Test 5 Failed: Invalid promoted finding metadata: ${JSON.stringify(findingMeta)}`);
    }

    const summary = await appService.getSummary(startRes.assessmentId);
    const summaryFinding = summary.findings.find((f: Finding) => f.metadata?.kind === 'jwt_algorithm_confusion_metadata');
    if (!summaryFinding) {
      throw new Error('Test 5 Failed: Promoted JWT confusion finding not found in assessment summary');
    }

    console.log('✓ Test 5 Passed: HITL review approved and promoted JWT confusion draft to formal Finding');
  }

  console.log('\n[milestoneP4_7_jwt_confusion_smoke] ALL 5 TESTS PASSED SUCCESSFULLY! (100% compliant)');
}

runTests().catch((err) => {
  console.error('[milestoneP4_7_jwt_confusion_smoke] FATAL ERROR:', err);
  process.exit(1);
});
