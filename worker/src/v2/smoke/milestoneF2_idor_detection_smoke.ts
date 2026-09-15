/**
 * Milestone F2 — IDOR / BOLA Differential Detection Smoke Test Suite
 *
 * Validates the first real end-to-end vulnerability detection vertical in FixGuard V2:
 * 1. Detection flow against mock vulnerable target -> Verified Finding Candidate & Finding generated.
 * 2. Safe abstention on secure target -> 0 findings generated, clean execution_completed.
 * 3. Pipeline lineage integrity preserved from detection probe to promoted candidate.
 * 4. Unauthenticated API or preflight denials fail closed with 0 network requests spawned.
 */

import assert from 'node:assert';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { HttpProbeRequest, HttpProbeResponse, IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import { runIdorDifferentialDetection } from '../detection/IdorDifferentialDetectionService.js';

function createScopeGrant(overrides?: Partial<AuthorizedScopeGrant>): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_f2_001',
    scanId: 'scan_f2_001',
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'domain',
      domain: 'api.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone F2 IDOR differential detection testing',
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
      allowedDomains: ['example.com', 'api.example.com'],
      allowedHosts: ['example.com', 'api.example.com', '93.184.216.34'],
      allowedOrigins: ['https://example.com', 'https://api.example.com'],
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
    ...overrides,
  };
}

function setupAuthorizedContext(scopeGrant = createScopeGrant()) {
  const nowIso = new Date().toISOString();
  const establishResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'assess_f2_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_f2_001',
      authorizedActor: { actorId: 'sec_lead_1', actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant,
    },
    nowIso
  );


  if (establishResult.status !== 'established') {
    throw new Error(`Failed to establish verified decision: ${establishResult.safeMessage}`);
  }

  return {
    verifiedAuthorizationDecision: establishResult.decision,
    scopeGrant,
    lineage: {
      assessmentId: 'assess_f2_001',
      scanId: scopeGrant.scanId,
      authorizationGrantId: scopeGrant.grantId,
      authorizationDecisionId: 'decision_f2_001',
      actorId: 'sec_lead_1',
    },
  };
}

async function runMilestoneF2SmokeTests() {
  console.log('=== [M-F2 SMOKE] First Real Vulnerability Detection Vertical (IDOR Differential Engine) ===\n');

  // -------------------------------------------------------------------------
  // Assertion 1: Vulnerable Target Detection & Formal Finding Generation
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 1: Detection flow against mock vulnerable target');
  {
    const auth = setupAuthorizedContext();
    const probeCalls: HttpProbeRequest[] = [];

    const mockVulnerableTransport: IdorHttpProbeTransport = async (req) => {
      probeCalls.push(req);
      const isIdentityA = req.headers['x-user-id'] === 'user_a';
      // Vulnerable backend: both Identity A and Identity B receive private document payload
      return {
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'server': 'mock-vulnerable-api'
        },
        bodyText: JSON.stringify({
          documentId: 'doc_f2_101',
          owner: 'user_a',
          title: 'Confidential Financial Plan',
          amount: 5000000,
          notes: 'Restricted to owner user_a'
        }),
        responseTimeMs: 35
      };
    };

    // 1a. Unreviewed execution returns pending_human_review with EvidenceDraft and ZERO findings
    const unreviewedResult = await runIdorDifferentialDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'idor_differential_detection_request',
      detectionId: 'det_f2_001_unreviewed',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/api/v1/documents/:id',
      resourceParamName: 'id',
      baselineResourceId: 'doc_f2_101',
      identityA: {
        identityId: 'user_a',
        headers: { 'x-user-id': 'user_a' }
      },
      identityB: {
        identityId: 'user_b',
        headers: { 'x-user-id': 'user_b' }
      },
      transport: mockVulnerableTransport,
      dnsResolver: async () => ['93.184.216.34']
    });

    assert.strictEqual(unreviewedResult.status, 'pending_human_review', 'Unreviewed status must be pending_human_review');
    assert.strictEqual(unreviewedResult.reasonCode, 'pending_human_review', 'Reason code must be pending_human_review');
    assert.ok(unreviewedResult.evidenceDraft, 'Evidence draft must be returned for human review');
    assert.strictEqual(unreviewedResult.finding, undefined, 'Zero findings must be generated without human authorization');
    assert.strictEqual(unreviewedResult.findingCandidate, undefined, 'Zero candidates generated without human authorization');

    // 1b. Human Reviewed & Authorized execution produces confirmed formal candidate & finding
    const result = await runIdorDifferentialDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'idor_differential_detection_request',
      detectionId: 'det_f2_001',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/api/v1/documents/:id',
      resourceParamName: 'id',
      baselineResourceId: 'doc_f2_101',
      identityA: {
        identityId: 'user_a',
        headers: { 'x-user-id': 'user_a' }
      },
      identityB: {
        identityId: 'user_b',
        headers: { 'x-user-id': 'user_b' }
      },
      humanReviewDecision: {
        decision: 'approve_evidence',
        reviewerId: 'reviewer_lead_sec',
        reviewedAt: new Date().toISOString()
      },
      transport: mockVulnerableTransport,
      dnsResolver: async () => ['93.184.216.34']
    });

    assert.strictEqual(result.status, 'vulnerability_detected', 'Status must be vulnerability_detected');
    assert.strictEqual(result.reasonCode, 'broken_access_control_proven', 'Reason code must be broken_access_control_proven');

    // Verify finding candidate
    assert.ok(result.findingCandidate, 'Formal finding candidate must be generated');
    assert.strictEqual(result.findingCandidate.candidateState.lifecycleState, 'formal_candidate_created');
    assert.strictEqual(result.findingCandidate.candidateState.confirmationState, 'not_confirmed');

    // Verify canonical Finding
    assert.ok(result.finding, 'Canonical Finding must be created');
    assert.strictEqual(result.finding.type, 'BROKEN_ACCESS_CONTROL', 'Finding type must be BROKEN_ACCESS_CONTROL');
    assert.strictEqual(result.finding.severity, 'high', 'Finding severity must be high');
    assert.strictEqual(result.finding.target, 'https://api.example.com/api/v1/documents/:id');
    assert.strictEqual(result.finding.confidence, 0.95);
    assert.strictEqual(result.finding.metadata.kind, 'broken_access_control_metadata');
    assert.ok(result.finding.evidence.includes('doc_f2_101'), 'Evidence diff must reference target resource');

    console.log('    [PASS] Human review gate verified: unreviewed halts at pending_human_review, authorized promotes to Finding');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: Safe Abstention on Secure Target
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 2: Safe abstention on secure target (403 Forbidden on Identity B)');
  {
    const auth = setupAuthorizedContext();
    const probeCalls: HttpProbeRequest[] = [];

    const mockSecureTransport: IdorHttpProbeTransport = async (req) => {
      probeCalls.push(req);
      const isIdentityA = req.headers['x-user-id'] === 'user_a';
      if (isIdentityA) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({ documentId: 'doc_f2_101', owner: 'user_a' }),
          responseTimeMs: 25
        };
      }
      // Secure backend properly rejects unauthorized Identity B with 403 Forbidden
      return {
        statusCode: 403,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ error: 'AccessDenied', message: 'Forbidden resource' }),
        responseTimeMs: 20
      };
    };

    const result = await runIdorDifferentialDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'idor_differential_detection_request',
      detectionId: 'det_f2_002',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/api/v1/documents/:id',
      resourceParamName: 'id',
      baselineResourceId: 'doc_f2_101',
      identityA: {
        identityId: 'user_a',
        headers: { 'x-user-id': 'user_a' }
      },
      identityB: {
        identityId: 'user_b',
        headers: { 'x-user-id': 'user_b' }
      },
      transport: mockSecureTransport,
      dnsResolver: async () => ['93.184.216.34']
    });

    assert.strictEqual(result.status, 'secure_target_abstained', 'Status must be secure_target_abstained');
    assert.strictEqual(result.reasonCode, 'access_control_enforced', 'Reason code must be access_control_enforced');
    assert.strictEqual(result.finding, undefined, 'Zero findings must be generated for secure targets');
    assert.strictEqual(result.findingCandidate, undefined, 'Zero candidates must be generated for secure targets');
    assert.strictEqual(probeCalls.length, 2, 'Both baseline and validation probes executed before abstaining');

    console.log('    [PASS] Clean abstention with 0 findings created on properly enforced access control');
  }

  // -------------------------------------------------------------------------
  // Assertion 3: Pipeline Lineage Integrity Preserved End-to-End
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 3: Lineage tuple integrity preserved from probe to promoted candidate');
  {
    const auth = setupAuthorizedContext();

    const mockVulnerableTransport: IdorHttpProbeTransport = async () => ({
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      bodyText: JSON.stringify({ docId: 'doc_f2_103', owner: 'user_a', data: 'payroll' }),
      responseTimeMs: 30
    });

    const result = await runIdorDifferentialDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'idor_differential_detection_request',
      detectionId: 'det_f2_003',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/api/v1/documents/:id',
      resourceParamName: 'id',
      baselineResourceId: 'doc_f2_103',
      identityA: { identityId: 'user_a', headers: { 'x-user': 'a' } },
      identityB: { identityId: 'anonymous' },
      humanReviewDecision: {
        decision: 'approve_evidence',
        reviewerId: 'reviewer_lead_sec',
        reviewedAt: new Date().toISOString()
      },
      transport: mockVulnerableTransport,
      dnsResolver: async () => ['93.184.216.34']
    });

    assert.strictEqual(result.status, 'vulnerability_detected');
    assert.ok(result.lineage, 'Result lineage must exist');
    assert.strictEqual(result.lineage.assessmentId, auth.lineage.assessmentId);
    assert.strictEqual(result.lineage.scanId, auth.lineage.scanId);
    assert.strictEqual(result.lineage.authorizationGrantId, auth.lineage.authorizationGrantId);
    assert.strictEqual(result.lineage.authorizationDecisionId, auth.lineage.authorizationDecisionId);
    assert.strictEqual(result.lineage.actorId, auth.lineage.actorId);

    // Verify lineage carried into M50 EvidenceRecord
    assert.ok(result.evidenceRecord?.lineage, 'EvidenceRecord must carry lineage');
    assert.strictEqual(result.evidenceRecord.lineage.assessmentId, auth.lineage.assessmentId);
    assert.strictEqual(result.evidenceRecord.lineage.scanId, auth.lineage.scanId);
    assert.strictEqual(result.evidenceRecord.lineage.authorizationGrantId, auth.lineage.authorizationGrantId);
    assert.strictEqual(result.evidenceRecord.lineage.authorizationDecisionId, auth.lineage.authorizationDecisionId);
    assert.strictEqual(result.evidenceRecord.lineage.actorId, auth.lineage.actorId);

    // Verify lineage carried into core Finding metadata
    const findingMetadata = result.finding?.metadata as { lineage?: typeof auth.lineage };
    assert.ok(findingMetadata?.lineage, 'Finding metadata must carry lineage');
    assert.strictEqual(findingMetadata.lineage.assessmentId, auth.lineage.assessmentId);
    assert.strictEqual(findingMetadata.lineage.scanId, auth.lineage.scanId);
    assert.strictEqual(findingMetadata.lineage.authorizationGrantId, auth.lineage.authorizationGrantId);
    assert.strictEqual(findingMetadata.lineage.authorizationDecisionId, auth.lineage.authorizationDecisionId);
    assert.strictEqual(findingMetadata.lineage.actorId, auth.lineage.actorId);

    console.log('    [PASS] Lineage tuple verified identical across request, evidence record, candidate, and finding');
  }

  // -------------------------------------------------------------------------
  // Assertion 4: Preflight Denials Fail Closed with 0 Network Probes Spawned
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 4: Unauthenticated or SSRF preflight denials fail closed with 0 network calls');
  {
    const auth = setupAuthorizedContext();
    let networkCalls = 0;
    const trackingTransport: IdorHttpProbeTransport = async () => {
      networkCalls++;
      return { statusCode: 200, headers: {}, bodyText: '', responseTimeMs: 0 };
    };

    // Case 4a: Unbranded authorization decision
    const unbrandedDecision = {
      ...auth.verifiedAuthorizationDecision,
      decision: 'authorized' as const,
    };

    const unbrandedResult = await runIdorDifferentialDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'idor_differential_detection_request',
      detectionId: 'det_f2_004a',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: unbrandedDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/api/v1/documents/:id',
      resourceParamName: 'id',
      baselineResourceId: 'doc_f2_104',
      identityA: { identityId: 'user_a' },
      identityB: { identityId: 'user_b' },
      transport: trackingTransport,
      dnsResolver: async () => ['93.184.216.34']
    });

    assert.strictEqual(unbrandedResult.status, 'preflight_denied');
    assert.strictEqual(unbrandedResult.reasonCode, 'authorization_unconfirmed');
    assert.strictEqual(networkCalls, 0, 'Zero network calls must be executed on unbranded authorization');

    // Case 4b: SSRF target (DNS resolving to loopback 127.0.0.1)
    const ssrfResult = await runIdorDifferentialDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'idor_differential_detection_request',
      detectionId: 'det_f2_004b',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/api/v1/documents/:id',
      resourceParamName: 'id',
      baselineResourceId: 'doc_f2_104',
      identityA: { identityId: 'user_a' },
      identityB: { identityId: 'user_b' },
      transport: trackingTransport,
      dnsResolver: async () => ['127.0.0.1'] // DNS resolves to loopback!
    });

    assert.strictEqual(ssrfResult.status, 'preflight_denied');
    assert.strictEqual(ssrfResult.reasonCode, 'ssrf_target_blocked');
    assert.strictEqual(networkCalls, 0, 'Zero network calls must be executed on SSRF target');

    // Case 4c: Target out of scope
    const outOfScopeResult = await runIdorDifferentialDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'idor_differential_detection_request',
      detectionId: 'det_f2_004c',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://unauthorized-evil-target.com/api/documents',
      resourceParamName: 'id',
      baselineResourceId: 'doc_f2_104',
      identityA: { identityId: 'user_a' },
      identityB: { identityId: 'user_b' },
      transport: trackingTransport,
      dnsResolver: async () => ['93.184.216.34']
    });

    assert.strictEqual(outOfScopeResult.status, 'preflight_denied');
    assert.strictEqual(outOfScopeResult.reasonCode, 'target_out_of_scope');
    assert.strictEqual(networkCalls, 0, 'Zero network calls must be executed on out-of-scope target');

    console.log('    [PASS] Preflight fail-closed semantics verified with strictly 0 network probes');
  }

  console.log('\n>>> ALL 4 MILESTONE F2 ASSERTIONS PASSED SUCCESSFULLY! <<<\n');
}

runMilestoneF2SmokeTests().catch((err) => {
  console.error('\n[!] Smoke test execution failed:', err);
  process.exit(1);
});
