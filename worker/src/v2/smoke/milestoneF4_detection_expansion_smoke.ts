/**
 * Milestone F4 — Detection Coverage Expansion Smoke Test Suite
 *
 * Validates CORS Misconfiguration and Parameter Reflection detection engines:
 * 1. Vulnerable CORS detection produces confirmed Finding; secure CORS yields 0 findings.
 * 2. Unsanitized parameter reflection produces confirmed Finding; non-reflecting endpoint yields 0 findings.
 * 3. Evidence retention pruning properly discards transient bodies on abstentions.
 * 4. Preflight and session expiration fail-closed with 0 probes dispatched.
 */

import assert from 'node:assert';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { HttpProbeRequest, HttpProbeResponse, IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import { runCorsMisconfigurationDetection } from '../detection/CorsMisconfigurationDetectionService.js';
import { runParameterReflectionDetection } from '../detection/ParameterReflectionDetectionService.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { TargetSessionState } from '../core/SessionLifecycleContracts.js';

function createScopeGrant(overrides?: Partial<AuthorizedScopeGrant>): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_f4_001',
    scanId: 'scan_f4_001',
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'domain',
      domain: 'api.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone F4 detection expansion testing',
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
      assessmentId: 'assess_f4_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_f4_001',
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
      assessmentId: 'assess_f4_001',
      scanId: scopeGrant.scanId,
      authorizationGrantId: scopeGrant.grantId,
      authorizationDecisionId: 'decision_f4_001',
      actorId: 'sec_lead_1',
    },
  };
}

async function runMilestoneF4SmokeSuite(): Promise<void> {
  console.log('=== [M-F4 SMOKE] Detection Coverage Expansion (CORS & Parameter Reflection) ===\n');

  // -------------------------------------------------------------------------
  // Assertion 1: CORS Misconfiguration Detection Engine
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 1: Vulnerable CORS detection produces confirmed Finding; secure CORS yields 0 findings');
  {
    const auth = setupAuthorizedContext();
    const coordinator = new TargetExecutionCoordinator({ maxConcurrency: 2, requestsPerSecond: 10 });

    // 1a. Vulnerable Target: echoes arbitrary untrusted origin + credentials true
    const vulnerableCorsTransport: IdorHttpProbeTransport = async (
      req: HttpProbeRequest
    ): Promise<HttpProbeResponse> => {
      const origin = req.headers['origin'];
      if (origin && origin.includes('untrusted')) {
        const vulnHeaders: Record<string, string> = {
          'content-type': 'application/json',
          'access-control-allow-origin': origin,
          'access-control-allow-credentials': 'true',
        };
        return {
          statusCode: 200,
          headers: vulnHeaders,
          bodyText: JSON.stringify({ sensitiveUserData: 'confidential_records_101' }),
          responseTimeMs: 20,
        };
      }
      const defaultHeaders: Record<string, string> = {
        'content-type': 'application/json',
      };
      return {
        statusCode: 200,
        headers: defaultHeaders,
        bodyText: JSON.stringify({ status: 'ok' }),
        responseTimeMs: 15,
      };
    };

    const vulnResult = await runCorsMisconfigurationDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'cors_misconfiguration_detection_request',
      detectionId: 'det_f4_cors_001',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/user/profile',
      coordinator,
      transport: vulnerableCorsTransport,
      dnsResolver: async () => ['93.184.216.34'],
    });

    assert.strictEqual(vulnResult.status, 'vulnerability_detected');
    assert.strictEqual(vulnResult.reasonCode, 'cors_misconfiguration_proven');
    assert.strictEqual(vulnResult.reflectedOrigin, 'https://untrusted-cross-origin.example.com');
    assert.strictEqual(vulnResult.allowCredentials, true);
    assert.ok(vulnResult.findingCandidate, 'Finding candidate must be created');
    assert.ok(vulnResult.finding, 'Canonical Finding must be created');
    assert.strictEqual(vulnResult.finding.type, 'SECURITY_MISCONFIGURATION');
    assert.strictEqual(vulnResult.finding.severity, 'high');
    assert.strictEqual(vulnResult.lineage.scanId, auth.lineage.scanId);

    // 1b. Secure Target: rejects untrusted origin
    const secureCorsTransport: IdorHttpProbeTransport = async () => ({
      statusCode: 200,
      headers: {
        'content-type': 'application/json',
        'access-control-allow-origin': 'https://example.com',
      },
      bodyText: JSON.stringify({ status: 'ok' }),
      responseTimeMs: 15,
    });

    const secureResult = await runCorsMisconfigurationDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'cors_misconfiguration_detection_request',
      detectionId: 'det_f4_cors_002',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/user/profile',
      coordinator,
      transport: secureCorsTransport,
      dnsResolver: async () => ['93.184.216.34'],
    });

    assert.strictEqual(secureResult.status, 'secure_target_abstained');
    assert.strictEqual(secureResult.reasonCode, 'cors_policy_enforced');
    assert.strictEqual(secureResult.finding, undefined, 'Abstention must produce 0 findings');
    assert.strictEqual(secureResult.findingCandidate, undefined, 'Abstention must produce 0 candidates');

    coordinator.clear();
    console.log('    [PASS] Vulnerable CORS detected and promoted to HIGH severity Finding; secure CORS cleanly abstains with 0 findings');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: Parameter Reflection Detection Engine
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 2: Unsanitized parameter reflection produces confirmed Finding; non-reflecting endpoint yields 0 findings');
  {
    const auth = setupAuthorizedContext();
    const coordinator = new TargetExecutionCoordinator({ maxConcurrency: 2, requestsPerSecond: 10 });

    // 2a. Reflecting Target: reflects parameter canary raw in response body
    const reflectingTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest) => {
      const url = new URL(req.url);
      const query = url.searchParams.get('q') ?? '';
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html; charset=utf-8' },
        bodyText: `<html><body><div>Search results for: ${query}</div></body></html>`,
        responseTimeMs: 25,
      };
    };

    const reflectResult = await runParameterReflectionDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'parameter_reflection_detection_request',
      detectionId: 'det_f4_refl_001',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/search',
      parameterName: 'q',
      canaryPayload: 'fgcanary991test',
      coordinator,
      transport: reflectingTransport,
      dnsResolver: async () => ['93.184.216.34'],
    });

    assert.strictEqual(reflectResult.status, 'vulnerability_detected');
    assert.strictEqual(reflectResult.reasonCode, 'parameter_reflection_proven');
    assert.ok(reflectResult.findingCandidate, 'Finding candidate must be created');
    assert.ok(reflectResult.finding, 'Canonical Finding must be created');
    assert.strictEqual(reflectResult.finding.type, 'INPUT_VALIDATION_FLAW');
    assert.strictEqual(reflectResult.finding.severity, 'medium');
    assert.strictEqual(reflectResult.lineage.scanId, auth.lineage.scanId);

    // 2b. Non-Reflecting Target: ignores or safely encodes parameter
    const nonReflectingTransport: IdorHttpProbeTransport = async () => ({
      statusCode: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
      bodyText: '<html><body><div>Search query not displayed</div></body></html>',
      responseTimeMs: 20,
    });

    const nonReflectResult = await runParameterReflectionDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'parameter_reflection_detection_request',
      detectionId: 'det_f4_refl_002',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/search',
      parameterName: 'q',
      coordinator,
      transport: nonReflectingTransport,
      dnsResolver: async () => ['93.184.216.34'],
    });

    assert.strictEqual(nonReflectResult.status, 'secure_target_abstained');
    assert.strictEqual(nonReflectResult.reasonCode, 'parameter_not_reflected');
    assert.strictEqual(nonReflectResult.finding, undefined, 'Abstention must produce 0 findings');
    assert.strictEqual(nonReflectResult.findingCandidate, undefined, 'Abstention must produce 0 candidates');

    coordinator.clear();
    console.log('    [PASS] Unsanitized parameter reflection promoted to MEDIUM severity Finding; non-reflecting endpoint cleanly abstains');
  }

  // -------------------------------------------------------------------------
  // Assertion 3: Evidence Retention & Pruning Strategy
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 3: Evidence retention pruning properly discards transient bodies on abstentions');
  {
    const auth = setupAuthorizedContext();

    // CORS Abstention Pruning
    const corsSecureTransport: IdorHttpProbeTransport = async () => ({
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      bodyText: '{"transient":"payload_that_must_be_pruned"}',
      responseTimeMs: 10,
    });

    const corsAbstained = await runCorsMisconfigurationDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'cors_misconfiguration_detection_request',
      detectionId: 'det_f4_cors_prune',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/user/profile',
      transport: corsSecureTransport,
      dnsResolver: async () => ['93.184.216.34'],
    });

    assert.strictEqual(corsAbstained.status, 'secure_target_abstained');
    assert.strictEqual(corsAbstained.baselineSnapshot?.safeExcerpt, undefined, 'Baseline safeExcerpt must be purged');
    assert.strictEqual(corsAbstained.validationSnapshot?.safeExcerpt, undefined, 'Validation safeExcerpt must be purged');
    assert.ok(corsAbstained.baselineSnapshot?.bodyHash, 'Structural bodyHash must be preserved');
    assert.ok(corsAbstained.validationSnapshot?.bodyHash, 'Structural bodyHash must be preserved');

    // Reflection Abstention Pruning
    const reflSecureTransport: IdorHttpProbeTransport = async () => ({
      statusCode: 200,
      headers: { 'content-type': 'text/plain' },
      bodyText: 'Static non-reflecting text response',
      responseTimeMs: 10,
    });

    const reflAbstained = await runParameterReflectionDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'parameter_reflection_detection_request',
      detectionId: 'det_f4_refl_prune',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/search',
      parameterName: 'q',
      transport: reflSecureTransport,
      dnsResolver: async () => ['93.184.216.34'],
    });

    assert.strictEqual(reflAbstained.status, 'secure_target_abstained');
    assert.strictEqual(reflAbstained.baselineSnapshot?.safeExcerpt, undefined, 'Baseline safeExcerpt must be purged');
    assert.strictEqual(reflAbstained.validationSnapshot?.safeExcerpt, undefined, 'Validation safeExcerpt must be purged');
    assert.ok(reflAbstained.baselineSnapshot?.bodyHash, 'Structural bodyHash must be preserved');
    assert.ok(reflAbstained.validationSnapshot?.bodyHash, 'Structural bodyHash must be preserved');

    console.log('    [PASS] Transient excerpts safely purged on abstentions while preserving hashes and structural metadata');
  }

  // -------------------------------------------------------------------------
  // Assertion 4: Preflight & Session Expiration Fail-Closed Semantics
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 4: Preflight and session expiration fail-closed with 0 probes dispatched');
  {
    const auth = setupAuthorizedContext();
    let dispatchedProbeCount = 0;

    const monitoredTransport: IdorHttpProbeTransport = async () => {
      dispatchedProbeCount++;
      return {
        statusCode: 200,
        headers: {},
        bodyText: '',
        responseTimeMs: 10,
      };
    };

    // 4a. SSRF Target Blocking (RFC-1918 / Loopback)
    const ssrfResult = await runCorsMisconfigurationDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'cors_misconfiguration_detection_request',
      detectionId: 'det_f4_ssrf',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'http://169.254.169.254/latest/meta-data',
      transport: monitoredTransport,
    });

    assert.strictEqual(ssrfResult.status, 'preflight_denied');
    assert.strictEqual(dispatchedProbeCount, 0, 'Zero probes must be dispatched on SSRF target');

    // 4b. Expired Session Lifecycle
    const expiredSession: TargetSessionState = {
      state: 'expired',
      expiresAt: '2026-09-01T00:00:00.000Z',
    };

    const expiredResult = await runParameterReflectionDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'parameter_reflection_detection_request',
      detectionId: 'det_f4_exp',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/search',
      parameterName: 'q',
      authContext: {
        identityId: 'user_1',
        sessionState: expiredSession,
      },
      transport: monitoredTransport,
      dnsResolver: async () => ['93.184.216.34'],
    });

    assert.strictEqual(expiredResult.status, 'preflight_denied');
    assert.strictEqual(expiredResult.reasonCode, 'session_expired');
    assert.strictEqual(dispatchedProbeCount, 0, 'Zero probes must be dispatched on expired session');

    console.log('    [PASS] Preflight and session expiration fail-closed with strictly 0 network probes dispatched');
  }

  console.log('\n>>> ALL 4 MILESTONE F4 ASSERTIONS PASSED SUCCESSFULLY! <<<');
}

runMilestoneF4SmokeSuite().catch((err) => {
  console.error('[!] MILESTONE F4 SMOKE SUITE FAILED:', err);
  process.exit(1);
});
