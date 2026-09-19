/**
 * milestoneA1_verification_state_smoke.ts
 * FixGuard V2 - Milestone A1 Verification State Machine Smoke Suite
 *
 * Verifies:
 * 1. Detection engine finding generation assigns initial verification state
 *    ('validated_vulnerability' for deterministic findings, 'observed_anomaly' for heuristic findings).
 * 2. VerificationStateService.advanceState successfully advances state upon HITL approval
 *    ('observed_anomaly' -> 'suspected_vulnerability').
 * 3. Direct modification attempts / invalid state transitions fail typecheck or runtime invariant rules.
 */

import assert from 'node:assert';
import { VerificationStateService } from '../core/VerificationStateService.js';
import type { Finding } from '../core/Evidence.js';
import { runAuthBypassDetection } from '../detection/AuthBypassDetectionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import { runInformationDisclosureDetection } from '../detection/InformationDisclosureDetectionService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';

async function runSmokeSuite() {
  console.log('=== Milestone A1: Verification State Machine Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const lineage = {
    assessmentId: 'asm_a1_smoke_001',
    scanId: 'scan_a1_smoke_001',
    authorizationGrantId: 'grant_a1_smoke_001',
    authorizationDecisionId: 'dec_a1_smoke_001',
    actorId: 'operator_secops_lead',
  };

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
      authorizationText: 'Authorized for Milestone A1 Smoke testing',
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
      decidedAt: nowIso,
      scopeGrant,
    },
    nowIso
  );

  if (authDecisionResult.status !== 'established' || !authDecisionResult.decision) {
    throw new Error('Preflight decision establishment failed');
  }

  const verifiedAuthorizationDecision = authDecisionResult.decision;

  // -------------------------------------------------------------------------
  // Test 1: Deterministic Engine assigns 'validated_vulnerability'
  // -------------------------------------------------------------------------
  console.log('--- Test 1: High-confidence deterministic engine assigns validated_vulnerability ---');
  {
    const mockTransport = async () => ({
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      bodyText: '{"admin":true}',
      responseTimeMs: 10,
    });

    const result = await runAuthBypassDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_request',
      ...lineage,
      detectionId: 'det_a1_auth_001',
      endpointUrl: 'https://app.example.com/api/admin/config',
      method: 'GET',
      identityA: { identityId: 'user_alice', headers: { authorization: 'Bearer token_a' } },
      bypassMechanism: 'header_stripping',
      verifiedAuthorizationDecision,
      scopeGrant,
      transport: mockTransport,
      dnsResolver: async () => ['93.184.216.34'],
      humanReviewDecision: {
        reviewerId: lineage.actorId,
        reviewedAt: nowIso,
        decision: 'approve_evidence',
      },
    });

    assert.strictEqual(result.status, 'vulnerability_detected');
    assert.strictEqual(result.finding?.verificationState, 'validated_vulnerability');
    console.log('✓ Test 1 Passed: Deterministic finding generated with verificationState = "validated_vulnerability"');
  }

  // -------------------------------------------------------------------------
  // Test 2: Heuristic Engine assigns 'observed_anomaly'
  // -------------------------------------------------------------------------
  console.log('--- Test 2: Heuristic engine assigns observed_anomaly ---');
  {
    const mockTransport = async () => ({
      statusCode: 200,
      headers: { 'content-type': 'text/plain' },
      bodyText: 'Exception in thread "main" java.lang.NullPointerException at com.example.App.main(App.java:42)',
      responseTimeMs: 10,
    });

    const result = await runInformationDisclosureDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'information_disclosure_detection_request',
      ...lineage,
      detectionId: 'det_a1_info_001',
      endpointUrl: 'https://app.example.com/debug/vars',
      verifiedAuthorizationDecision,
      scopeGrant,
      transport: mockTransport,
      dnsResolver: async () => ['93.184.216.34'],
      humanReviewDecision: {
        reviewerId: lineage.actorId,
        reviewedAt: nowIso,
        decision: 'approve_evidence',
      },
    });

    assert.strictEqual(result.status, 'potential_weakness');
    assert.strictEqual(result.finding?.verificationState, 'observed_anomaly');
    console.log('✓ Test 2 Passed: Heuristic finding generated with verificationState = "observed_anomaly"');
  }

  // -------------------------------------------------------------------------
  // Test 3: VerificationStateService.advanceState transitions state upon HITL approval
  // -------------------------------------------------------------------------
  console.log('--- Test 3: HITL approval advances observed_anomaly -> suspected_vulnerability ---');
  {
    const heuristicFinding: Finding = {
      id: 'fnd_heuristic_001',
      type: 'SECURITY_MISCONFIGURATION',
      severity: 'medium',
      title: 'Disclosed Server Version Banner',
      description: 'Server header exposes nginx/1.18.0',
      target: 'https://app.example.com/',
      evidence: 'Server: nginx/1.18.0',
      confidence: 0.8,
      verificationState: 'observed_anomaly',
      metadata: {
        kind: 'information_disclosure_metadata',
        category: 'SECURITY_MISCONFIGURATION',
        disclosureKind: 'server_banner',
        disclosedFragment: 'nginx/1.18.0',
        trigger: 'server_header',
        observedAt: nowIso,
      },
    };

    const { updatedFinding, transitionRecord } = VerificationStateService.advanceState(
      heuristicFinding,
      'suspected_vulnerability',
      {
        reviewerId: lineage.actorId,
        reasonCode: 'hitl_operator_approval',
      }
    );

    assert.strictEqual(updatedFinding.verificationState, 'suspected_vulnerability');
    assert.strictEqual(transitionRecord.fromState, 'observed_anomaly');
    assert.strictEqual(transitionRecord.toState, 'suspected_vulnerability');
    assert.strictEqual(transitionRecord.reviewerId, lineage.actorId);
    assert.strictEqual(transitionRecord.reasonCode, 'hitl_operator_approval');
    console.log('✓ Test 3 Passed: State advanced cleanly to suspected_vulnerability with complete transition audit trail');
  }

  // -------------------------------------------------------------------------
  // Test 4: Transition Invariant Safeguard (Missing evidenceId & reviewerId throws)
  // -------------------------------------------------------------------------
  console.log('--- Test 4: Enforces transition invariant (rejects transition without evidenceId or reviewerId) ---');
  {
    const finding: Finding = {
      id: 'fnd_test_004',
      type: 'SECURITY_MISCONFIGURATION',
      severity: 'low',
      title: 'Test Finding',
      description: 'Test Description',
      target: 'https://app.example.com/',
      evidence: 'test',
      confidence: 1.0,
      verificationState: 'observed_anomaly',
      metadata: {
        kind: 'missing_security_headers_metadata',
        category: 'SECURITY_MISCONFIGURATION',
        missingHeaders: ['X-Frame-Options'],
        presentHeaders: [],
        observedAt: nowIso,
      },
    };

    assert.throws(
      () => {
        VerificationStateService.advanceState(finding, 'suspected_vulnerability', {
          reasonCode: 'unauthorized_attempt',
        } as any);
      },
      /Verification state transition invariant violated/
    );

    console.log('✓ Test 4 Passed: Unattributed state transition attempt blocked fail-closed');
  }

  // -------------------------------------------------------------------------
  // Test 5: Immutability Guarantee (Readonly frozen object)
  // -------------------------------------------------------------------------
  console.log('--- Test 5: Verified Immutability Guarantee ---');
  {
    const initialFinding: Finding = {
      id: 'fnd_test_005',
      type: 'SECURITY_MISCONFIGURATION',
      severity: 'high',
      title: 'Immutable Target Finding',
      description: 'Immutability test',
      target: 'https://app.example.com/',
      evidence: 'test',
      confidence: 1.0,
      verificationState: 'observed_anomaly',
      metadata: {
        kind: 'missing_security_headers_metadata',
        category: 'SECURITY_MISCONFIGURATION',
        missingHeaders: ['X-Frame-Options'],
        presentHeaders: [],
        observedAt: nowIso,
      },
    };

    const { updatedFinding } = VerificationStateService.advanceState(
      initialFinding,
      'validated_vulnerability',
      {
        evidenceId: 'evd_proof_005',
        reasonCode: 'proof_of_concept_verification',
      }
    );

    assert.strictEqual(initialFinding.verificationState, 'observed_anomaly');
    assert.strictEqual(updatedFinding.verificationState, 'validated_vulnerability');
    assert.throws(() => {
      (updatedFinding as any).verificationState = 'observed_anomaly';
    });

    console.log('✓ Test 5 Passed: Object immutability enforced, preventing direct in-place mutation');
  }

  console.log('\n=== All Milestone A1 Verification State Machine Smoke Tests PASSED (5/5) ===');
}

runSmokeSuite().catch((err) => {
  console.error('[!] Milestone A1 Smoke Suite Failed:', err);
  process.exit(1);
});
