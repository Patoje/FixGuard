/**
 * Milestone 8 — Controlled Active Verification & Safe PoC Engine Smoke Suite
 *
 * Validates:
 * 1. Safe PoC Confirmation & Cryptographic Proof:
 *    - Injects inert canary or differential probe against vulnerable target endpoint.
 *    - Confirms exploitability deterministically, capturing SHA-256 hashes and proof record.
 * 2. Clean Refutation & Abstention Discipline:
 *    - Validates that sanitized or access-controlled targets return exploit_refuted with 0 false claims.
 * 3. Human Authorization Gate & WeakSet Brand Enforcement:
 *    - Blocks forged or unbranded decisions (preflight_denied: authorization_unconfirmed) with 0 network probes.
 *    - Blocks vector mismatches before any network dispatch.
 * 4. Double SSRF Gate & Target Circuit Breaker Containment:
 *    - Blocks internal/loopback and cloud-metadata addresses.
 *    - Respects TargetExecutionCoordinator circuit state and halts safely when circuit is OPEN.
 */

import assert from 'node:assert';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import { CIRCUIT_OPEN_REASON_CODE } from '../runtime/CircuitBreakerContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import {
  ACTIVE_VERIFICATION_CONTRACT_VERSION,
  ACTIVE_VERIFICATION_NON_CLAIMS,
  establishVerifiedExploitationDecision,
  type ActiveVerificationCommand,
  type VerificationHttpRequest,
  type VerificationHttpResponse,
  type VerificationHttpTransport,
} from '../verification/ActiveVerificationContracts.js';
import { ControlledActiveVerificationService } from '../verification/ControlledActiveVerificationService.js';

function createScopeGrant(domain: string): AuthorizedScopeGrant {
  const now = new Date();
  const expires = new Date(now.getTime() + 86400_000);

  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: `grant_${domain.replace(/[^a-z0-9]/gi, '_')}`,
    scanId: 'scan_m8_001',
    issuedAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    subject: {
      targetKind: 'domain',
      domain,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized Milestone 8 active verification test for ${domain}`,
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: false,
      lightValidation: true,
      activeValidation: true,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: [domain],
      allowedHosts: [domain, '93.184.216.34'],
      allowedOrigins: [`https://${domain}`, `http://${domain}`],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
    },
    constraints: {
      allowLoginRequiredAreas: false,
      allowStateChangingRequests: false,
      allowCredentialUse: false,
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
}

function setupAuthorizedExploitationContext(
  domain: string,
  candidateId: string,
  targetUrl: string,
  vector: 'parameter_reflection_canary' | 'cors_arbitrary_origin_reflection' | 'idor_read_differential' | 'security_header_enforcement'
) {
  const scopeGrant = createScopeGrant(domain);
  const nowIso = new Date().toISOString();

  const decisionResult = establishVerifiedExploitationDecision(
    {
      contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
      kind: 'establish_verified_exploitation_decision_request',
      assessmentId: 'asm_m8_001',
      scanId: 'scan_m8_001',
      authorizationDecisionId: `dec_m8_${candidateId}`,
      candidateId,
      targetUrl,
      allowedVector: vector,
      authorizedActor: { actorId: 'sec_operator_m8', actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant,
    },
    nowIso
  );

  if (decisionResult.status !== 'established') {
    throw new Error(`Failed to establish exploitation decision: ${decisionResult.reasonCode}`);
  }

  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'asm_m8_001',
    scanId: 'scan_m8_001',
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: decisionResult.decision.authorizationDecisionId,
    actorId: 'sec_operator_m8',
  };

  return { scopeGrant, decision: decisionResult.decision, lineage };
}

async function runMilestone8SmokeTests() {
  console.log('=== [M-8 SMOKE] Controlled Active Verification & Safe PoC Engine ===\n');

  // =========================================================================
  // Assertion 1: Safe PoC Confirmation & Cryptographic Proof
  // =========================================================================
  console.log('[*] Assertion 1: Safe PoC Confirmation & Cryptographic Proof...');
  {
    const domain = 'app.example.com';
    const targetUrl = `https://${domain}/search`;
    const candidateId = 'cand_refl_001';
    const canary = 'fgcanary12345678';

    const { scopeGrant, decision, lineage } = setupAuthorizedExploitationContext(
      domain,
      candidateId,
      targetUrl,
      'parameter_reflection_canary'
    );

    let networkCallCount = 0;
    const mockTransport: VerificationHttpTransport = async (req: VerificationHttpRequest) => {
      networkCallCount += 1;
      assert.ok(req.url.includes(canary), 'Canary must be present in request URL');
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        bodyText: `<html><body>Search results for: <b>${canary}</b></body></html>`,
        responseTimeMs: 25,
      };
    };

    const service = new ControlledActiveVerificationService(mockTransport);

    const command: ActiveVerificationCommand = {
      candidateId,
      targetUrl,
      vector: 'parameter_reflection_canary',
      canaryToken: canary,
      verifiedAuthorizationDecision: decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
      dnsResolver: async () => ['93.184.216.34'],
    };

    const result = await service.verifyActiveExploit(command);

    assert.strictEqual(result.status, 'exploit_confirmed', 'Status must be exploit_confirmed');
    assert.strictEqual(networkCallCount, 1, 'Network call must be dispatched exactly once');

    if (result.status === 'exploit_confirmed') {
      assert.strictEqual(result.proof.candidateId, candidateId);
      assert.strictEqual(result.proof.canaryReflected, true);
      assert.strictEqual(result.proof.statusCode, 200);
      assert.ok(result.proof.requestHash.length === 64, 'Request hash must be 64-char SHA-256 hex');
      assert.ok(result.proof.responseHash.length === 64, 'Response hash must be 64-char SHA-256 hex');
      assert.strictEqual(result.confirmedFindingCandidate.exploitConfidence, 1.0);
      assert.strictEqual(result.confirmedFindingCandidate.severity, 'medium');
      assert.deepStrictEqual(result.lineage, lineage);
    }
  }
  console.log('    [PASS] Safe PoC exploit confirmed with auditable SHA-256 cryptographic proof');

  // =========================================================================
  // Assertion 2: Clean Refutation & Abstention Discipline (Secure Target)
  // =========================================================================
  console.log('[*] Assertion 2: Clean Refutation & Abstention Discipline (Secure Target)...');
  {
    const domain = 'secure.example.com';
    const targetUrl = `https://${domain}/api/v1/user/101`;
    const candidateId = 'cand_idor_002';

    const { scopeGrant, decision, lineage } = setupAuthorizedExploitationContext(
      domain,
      candidateId,
      targetUrl,
      'idor_read_differential'
    );

    let networkCallCount = 0;
    const mockTransport: VerificationHttpTransport = async () => {
      networkCallCount += 1;
      // Secure target denies unauthorized differential access
      return {
        statusCode: 403,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ error: 'Forbidden', message: 'Unauthorized object access' }),
        responseTimeMs: 15,
      };
    };

    const service = new ControlledActiveVerificationService(mockTransport);

    const command: ActiveVerificationCommand = {
      candidateId,
      targetUrl,
      vector: 'idor_read_differential',
      verifiedAuthorizationDecision: decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
      dnsResolver: async () => ['93.184.216.34'],
    };

    const result = await service.verifyActiveExploit(command);

    assert.strictEqual(result.status, 'exploit_refuted', 'Secure target must yield exploit_refuted');
    assert.strictEqual(networkCallCount, 1);

    if (result.status === 'exploit_refuted') {
      assert.strictEqual(result.reasonCode, 'access_denied');
      assert.strictEqual(result.responseStatus, 403);
      assert.ok(result.responseHash.length === 64);
      assert.strictEqual(result.explicitNonClaims.executesDestructivePayloads, false);
    }
  }
  console.log('    [PASS] Secure target cleanly refuted with zero false alarm claims');

  // =========================================================================
  // Assertion 3: Human Authorization Gate & WeakSet Brand Enforcement
  // =========================================================================
  console.log('[*] Assertion 3: Human Authorization Gate & WeakSet Brand Enforcement...');
  {
    const domain = 'auth-test.example.com';
    const targetUrl = `https://${domain}/test`;
    const candidateId = 'cand_fake_003';
    const scopeGrant = createScopeGrant(domain);

    const lineage: AuthorizedActiveReconRequestLineage = {
      assessmentId: 'asm_m8_001',
      scanId: 'scan_m8_001',
      authorizationGrantId: scopeGrant.grantId,
      authorizationDecisionId: 'dec_unbranded_003',
      actorId: 'unauthorized_attacker',
    };

    let networkCalls = 0;
    const mockTransport: VerificationHttpTransport = async () => {
      networkCalls += 1;
      return { statusCode: 200, headers: {}, bodyText: 'ok', responseTimeMs: 10 };
    };

    const service = new ControlledActiveVerificationService(mockTransport);

    // 3A: Forged plain object literal without WeakSet brand
    const forgedDecision = {
      contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
      kind: 'verified_exploitation_authorization_decision' as const,
      assessmentId: 'asm_m8_001',
      scanId: 'scan_m8_001',
      authorizationGrantId: scopeGrant.grantId,
      authorizationDecisionId: 'dec_unbranded_003',
      candidateId,
      targetUrl,
      allowedVector: 'parameter_reflection_canary' as const,
      authorizedActor: { actorId: 'fake_actor', actorType: 'human' as const },
      decision: 'authorized' as const,
      decidedAt: new Date().toISOString(),
      scopeGrant,
      verification: { verifiedAt: new Date().toISOString(), method: 'trusted_application_boundary' as const },
    };

    const resultForged = await service.verifyActiveExploit({
      candidateId,
      targetUrl,
      vector: 'parameter_reflection_canary',
      verifiedAuthorizationDecision: forgedDecision,
      authorizedScopeGrant: scopeGrant,
      lineage,
      dnsResolver: async () => ['93.184.216.34'],
    });

    assert.strictEqual(resultForged.status, 'preflight_denied');
    assert.strictEqual(resultForged.reasonCode, 'authorization_unconfirmed');
    assert.strictEqual(networkCalls, 0, 'ZERO network calls must be made for unbranded decisions');

    // 3B: Vector mismatch denial
    const { decision: legitDecision, lineage: legitLineage } = setupAuthorizedExploitationContext(
      domain,
      candidateId,
      targetUrl,
      'cors_arbitrary_origin_reflection'
    );

    const resultMismatch = await service.verifyActiveExploit({
      candidateId,
      targetUrl,
      vector: 'parameter_reflection_canary', // mismatch with cors_arbitrary_origin_reflection
      verifiedAuthorizationDecision: legitDecision,
      authorizedScopeGrant: scopeGrant,
      lineage: legitLineage,
      dnsResolver: async () => ['93.184.216.34'],
    });

    assert.strictEqual(resultMismatch.status, 'preflight_denied');
    assert.strictEqual(resultMismatch.reasonCode, 'vector_mismatch');
    assert.strictEqual(networkCalls, 0, 'ZERO network calls on vector mismatch');
  }
  console.log('    [PASS] WeakSet brand validation and vector mismatch safely failed closed');

  // =========================================================================
  // Assertion 4: Double SSRF Gate & Target Circuit Breaker Containment
  // =========================================================================
  console.log('[*] Assertion 4: Double SSRF Gate & Target Circuit Breaker Containment...');
  {
    let networkCalls = 0;
    const mockTransport: VerificationHttpTransport = async () => {
      networkCalls += 1;
      return { statusCode: 200, headers: {}, bodyText: 'ok', responseTimeMs: 10 };
    };

    const service = new ControlledActiveVerificationService(mockTransport);

    // 4A: SSRF Denial (Metadata & Loopback)
    const ssrfTargets = [
      'http://169.254.169.254/latest/meta-data/',
      'http://127.0.0.1:8080/admin',
      'http://10.0.0.1/private',
    ];

    for (const ssrfUrl of ssrfTargets) {
      const { scopeGrant, decision, lineage } = setupAuthorizedExploitationContext(
        'example.com',
        'cand_ssrf',
        ssrfUrl,
        'parameter_reflection_canary'
      );

      const ssrfResult = await service.verifyActiveExploit({
        candidateId: 'cand_ssrf',
        targetUrl: ssrfUrl,
        vector: 'parameter_reflection_canary',
        verifiedAuthorizationDecision: decision,
        authorizedScopeGrant: scopeGrant,
        lineage,
        dnsResolver: async () => ['127.0.0.1'],
      });

      assert.strictEqual(ssrfResult.status, 'preflight_denied');
      assert.strictEqual(ssrfResult.reasonCode, 'ssrf_target_blocked');
      assert.strictEqual(networkCalls, 0, 'ZERO network calls dispatched to SSRF targets');
    }

    // 4B: Circuit Breaker Immediate Abort when OPEN
    const cbDomain = 'distressed.example.com';
    const cbUrl = `https://${cbDomain}/api`;
    const { scopeGrant: cbGrant, decision: cbDecision, lineage: cbLineage } =
      setupAuthorizedExploitationContext(cbDomain, 'cand_cb', cbUrl, 'security_header_enforcement');

    const coordinator = new TargetExecutionCoordinator({
      requestsPerSecond: 10,
      maxConcurrency: 2,
      circuitBreakerConfig: { consecutive5xxThreshold: 2, openCooldownMs: 60_000 },
    });

    // Trip circuit breaker to OPEN
    coordinator.recordTargetResponse(cbDomain, 503);
    coordinator.recordTargetResponse(cbDomain, 503);
    assert.strictEqual(coordinator.isCircuitOpen(cbDomain), true, 'Circuit must be OPEN');

    const cbResult = await service.verifyActiveExploit({
      candidateId: 'cand_cb',
      targetUrl: cbUrl,
      vector: 'security_header_enforcement',
      verifiedAuthorizationDecision: cbDecision,
      authorizedScopeGrant: cbGrant,
      lineage: cbLineage,
      coordinator,
      dnsResolver: async () => ['93.184.216.34'],
    });

    assert.strictEqual(cbResult.status, 'circuit_broken');
    assert.strictEqual(cbResult.reasonCode, CIRCUIT_OPEN_REASON_CODE);
    assert.strictEqual(networkCalls, 0, 'ZERO network calls when target circuit is OPEN');
  }
  console.log('    [PASS] SSRF targets rejected and Circuit Breaker OPEN state strictly respected');

  console.log('\n>>> ALL 4 MILESTONE 8 ASSERTIONS PASSED SUCCESSFULLY! <<<');
}

runMilestone8SmokeTests().catch((err) => {
  console.error('Milestone 8 Active Verification smoke suite failed:', err);
  process.exit(1);
});
