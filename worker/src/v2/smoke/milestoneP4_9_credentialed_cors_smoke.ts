/**
 * Milestone P4-9 Smoke Test Suite
 * Credentialed CORS Detection Upgrade (Milestone P4-9)
 *
 * Verifies:
 * 1. Detects credentialed CORS when server reflects untrusted origin and sets Allow-Credentials: true.
 * 2. Cleanly abstains (secure_target_abstained) when server rejects untrusted origin or enforces strict origin policy.
 * 3. Cleanly abstains when server reflects origin but Allow-Credentials header is absent or false.
 * 4. Preflight and egress gates block internal/SSRF targets.
 * 5. Full HITL triage lifecycle promotes drafts to formal Findings.
 */

import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import { runCredentialedCorsDetection } from '../detection/CredentialedCorsDetectionService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type {
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from '../detection/DetectionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { Finding, CredentialedCorsMetadata } from '../core/Evidence.js';

console.log('[milestoneP4_9_credentialed_cors_smoke] Starting Milestone P4-9 smoke suite...');

async function runTests(): Promise<void> {
  const lineage = {
    assessmentId: 'asm_test_p49_001',
    scanId: 'scn_test_p49_001',
    authorizationGrantId: 'grnt_test_p49_001',
    authorizationDecisionId: 'dec_test_p49_001',
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
      authorizationText: 'Authorized for Milestone P4-9 Credentialed CORS smoke testing',
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
  // Test 1: Detects credentialed CORS when server reflects untrusted origin and ACAC: true
  // -------------------------------------------------------------------------
  console.log('--- Test 1: Detects credentialed CORS when server reflects untrusted origin and ACAC: true ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      // Server reflects untrusted origin in ACAO and returns ACAC: true
      return {
        statusCode: 200,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'access-control-allow-origin': req.headers['Origin'] ?? '',
          'access-control-allow-credentials': 'true',
          'vary': 'Origin',
        },
        bodyText: JSON.stringify({ sensitiveUserData: 'secret_profile_info' }),
        responseTimeMs: 25,
      };
    };

    const result = await runCredentialedCorsDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'credentialed_cors_detection_request',
      detectionId: 'det_test_p49_cors',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'https://app.example.com/api/user/profile',
      httpMethod: 'GET',
      suppliedOrigin: 'https://canary.fixguard.internal',
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
    if (result.allowCredentialsHeader !== true) {
      throw new Error('Test 1 Failed: Expected allowCredentialsHeader to be true');
    }
    if (result.reflectedOrigin !== 'https://canary.fixguard.internal') {
      throw new Error(`Test 1 Failed: Expected reflectedOrigin 'https://canary.fixguard.internal', got '${result.reflectedOrigin}'`);
    }
    if (!result.finding) {
      throw new Error('Test 1 Failed: Expected finding to be constructed');
    }
    const meta = result.finding.metadata as CredentialedCorsMetadata;
    if (meta.kind !== 'credentialed_cors_metadata' || meta.category !== 'SECURITY_MISCONFIGURATION') {
      throw new Error(`Test 1 Failed: Invalid metadata: ${JSON.stringify(meta)}`);
    }
    if (meta.allowCredentialsHeader !== true || meta.suppliedOrigin !== 'https://canary.fixguard.internal') {
      throw new Error(`Test 1 Failed: Invalid header flags in metadata: ${JSON.stringify(meta)}`);
    }

    console.log('✓ Test 1 Passed: Credentialed CORS vulnerability correctly identified');
  }

  // -------------------------------------------------------------------------
  // Test 2: Cleanly abstains when server rejects untrusted origin
  // -------------------------------------------------------------------------
  console.log('--- Test 2: Cleanly abstains when server rejects untrusted origin ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => {
      // Server strictly allows only https://app.example.com or omits ACAO
      return {
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'access-control-allow-origin': 'https://app.example.com',
          'access-control-allow-credentials': 'true',
        },
        bodyText: JSON.stringify({ status: 'ok' }),
        responseTimeMs: 20,
      };
    };

    const result = await runCredentialedCorsDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'credentialed_cors_detection_request',
      detectionId: 'det_test_p49_strict',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'https://app.example.com/api/user/profile',
      httpMethod: 'GET',
      suppliedOrigin: 'https://canary.fixguard.internal',
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      transport: mockTransport,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`Test 2 Failed: Expected status 'secure_target_abstained', got '${result.status}'`);
    }
    if (result.reasonCode !== 'cors_policy_enforced') {
      throw new Error(`Test 2 Failed: Expected reasonCode 'cors_policy_enforced', got '${result.reasonCode}'`);
    }

    console.log('✓ Test 2 Passed: Strict CORS origin cleanly abstained');
  }

  // -------------------------------------------------------------------------
  // Test 3: Cleanly abstains when Allow-Credentials is false or missing
  // -------------------------------------------------------------------------
  console.log('--- Test 3: Cleanly abstains when Allow-Credentials is false or missing ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      // Server reflects origin for public endpoints but does NOT set Allow-Credentials: true
      return {
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'access-control-allow-origin': req.headers['Origin'] ?? '',
          'access-control-allow-credentials': 'false',
        },
        bodyText: JSON.stringify({ publicStatus: 'ok' }),
        responseTimeMs: 20,
      };
    };

    const result = await runCredentialedCorsDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'credentialed_cors_detection_request',
      detectionId: 'det_test_p49_no_cred',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'https://app.example.com/api/public/status',
      httpMethod: 'GET',
      suppliedOrigin: 'https://canary.fixguard.internal',
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      transport: mockTransport,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`Test 3 Failed: Expected status 'secure_target_abstained', got '${result.status}'`);
    }
    if (result.allowCredentialsHeader !== false) {
      throw new Error('Test 3 Failed: Expected allowCredentialsHeader to be false');
    }

    console.log('✓ Test 3 Passed: Non-credentialed origin reflection cleanly abstained');
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

    const result = await runCredentialedCorsDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'credentialed_cors_detection_request',
      detectionId: 'det_test_p49_ssrf',
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
      const origin = req.headers['Origin'] ?? req.headers['origin'] ?? 'https://canary.fixguard.internal';
      return {
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'access-control-allow-origin': origin,
          'access-control-allow-credentials': 'true',
        },
        bodyText: JSON.stringify({ sensitive: 'user_profile' }),
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
    const corsDraft = draftsResponse.drafts.find(
      (d) => d.differentialContext?.detectionKind === 'credentialed_cors'
    );

    if (!corsDraft) {
      throw new Error(`Test 5 Failed: Expected pending Credentialed CORS draft, found: ${JSON.stringify(draftsResponse.drafts.map((d) => d.differentialContext?.detectionKind))}`);
    }

    if (corsDraft.differentialContext?.allowCredentialsHeader !== true) {
      throw new Error(`Test 5 Failed: Expected allowCredentialsHeader true, got '${corsDraft.differentialContext?.allowCredentialsHeader}'`);
    }

    // Perform HITL review promotion
    const reviewResult = await appService.reviewEvidenceDraft({
      assessmentId: startRes.assessmentId,
      draftId: corsDraft.draftId,
      decision: 'approve_evidence',
      reviewerId: 'usr_secops_lead',
      reviewedAt: new Date().toISOString(),
      notes: 'Confirmed credentialed CORS origin reflection against canary origin.',
    });

    if (reviewResult.decision !== 'approve_evidence' || !reviewResult.findingCreated) {
      throw new Error(`Test 5 Failed: Review promotion failed: ${JSON.stringify(reviewResult)}`);
    }

    const promotedFinding = reviewResult.findingCreated;
    if (promotedFinding.type !== 'SECURITY_MISCONFIGURATION') {
      throw new Error(`Test 5 Failed: Expected finding type 'SECURITY_MISCONFIGURATION', got '${promotedFinding.type}'`);
    }

    const findingMeta = promotedFinding.metadata as CredentialedCorsMetadata;
    if (findingMeta.kind !== 'credentialed_cors_metadata' || findingMeta.allowCredentialsHeader !== true) {
      throw new Error(`Test 5 Failed: Invalid promoted finding metadata: ${JSON.stringify(findingMeta)}`);
    }

    const summary = await appService.getSummary(startRes.assessmentId);
    const summaryFinding = summary.findings.find((f: Finding) => f.metadata?.kind === 'credentialed_cors_metadata');
    if (!summaryFinding) {
      throw new Error('Test 5 Failed: Promoted Credentialed CORS finding not found in assessment summary');
    }

    console.log('✓ Test 5 Passed: HITL review approved and promoted Credentialed CORS draft to formal Finding');
  }

  console.log('\n[milestoneP4_9_credentialed_cors_smoke] ALL 5 TESTS PASSED SUCCESSFULLY! (100% compliant)');
}

runTests().catch((err) => {
  console.error('[milestoneP4_9_credentialed_cors_smoke] FATAL ERROR:', err);
  process.exit(1);
});
