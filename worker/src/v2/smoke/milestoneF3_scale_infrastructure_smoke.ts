/**
 * Milestone F3 — Cross-Cutting Scale Infrastructure Smoke Test Suite
 *
 * Validates:
 * 1. Session Lifecycle: Expired session triggers safe abort (session_expired) with 0 child probes dispatched; token refresh hook renews expired session.
 * 2. Target Concurrency Coordinator: Concurrent executions against the same target adhere to rate limits and max concurrency ceilings.
 * 3. Evidence Retention Pruning: Full bodies preserved for promoted findings; transient bodies pruned for abstained comparisons.
 * 4. Lineage tuple integrity preserved across all coordination states.
 */

import assert from 'node:assert';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { HttpProbeRequest, HttpProbeResponse, IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import { runIdorDifferentialDetection } from '../detection/IdorDifferentialDetectionService.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import { validateSessionHealth } from '../core/SessionLifecycleService.js';
import type { TargetSessionState } from '../core/SessionLifecycleContracts.js';
import { pruneTransientEvidence } from '../evidence/EvidenceRetentionService.js';

function createScopeGrant(overrides?: Partial<AuthorizedScopeGrant>): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_f3_001',
    scanId: 'scan_f3_001',
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'domain',
      domain: 'api.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone F3 scale infrastructure smoke testing',
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
      assessmentId: 'assess_f3_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_f3_001',
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
      assessmentId: 'assess_f3_001',
      scanId: scopeGrant.scanId,
      authorizationGrantId: scopeGrant.grantId,
      authorizationDecisionId: 'decision_f3_001',
      actorId: 'sec_lead_1',
    },
  };
}

async function runMilestoneF3SmokeTests() {
  console.log('=== [M-F3 SMOKE] Cross-Cutting Scale Infrastructure ===\n');

  // -------------------------------------------------------------------------
  // Assertion 1: Session Lifecycle & Pre-Probe Health Check
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 1: Session lifecycle health validation and token refresh orchestration');
  {
    const auth = setupAuthorizedContext();
    let networkCalls = 0;
    const trackingTransport: IdorHttpProbeTransport = async () => {
      networkCalls++;
      return { statusCode: 200, headers: {}, bodyText: '{}', responseTimeMs: 10 };
    };

    // Case 1a: Expired session without refresh hook -> fails closed with session_expired & 0 probes
    const expiredSession: TargetSessionState = {
      state: 'expired',
      expiresAt: '2020-01-01T00:00:00.000Z'
    };

    const expiredResult = await runIdorDifferentialDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'idor_differential_detection_request',
      detectionId: 'det_f3_001a',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/api/v1/documents/:id',
      resourceParamName: 'id',
      baselineResourceId: 'doc_f3_101',
      identityA: {
        identityId: 'user_a',
        sessionState: expiredSession
      },
      identityB: {
        identityId: 'user_b'
      },
      transport: trackingTransport,
      dnsResolver: async () => ['93.184.216.34']
    });

    assert.strictEqual(expiredResult.status, 'preflight_denied', 'Status must be preflight_denied');
    assert.strictEqual(expiredResult.reasonCode, 'session_expired', 'Reason code must be session_expired');
    assert.strictEqual(networkCalls, 0, 'Zero network probes must be dispatched on expired session');

    // Case 1b: Expired session with token refresh hook -> refreshes and dispatches probe with new header
    let refreshHookCalled = false;
    const receivedHeaders: Record<string, string>[] = [];
    const refreshableTransport: IdorHttpProbeTransport = async (req) => {
      receivedHeaders.push(req.headers as Record<string, string>);
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ documentId: 'doc_f3_101', owner: 'user_a' }),
        responseTimeMs: 15
      };
    };

    const expiringSessionWithHook: TargetSessionState = {
      state: 'expired',
      expiresAt: '2020-01-01T00:00:00.000Z',
      tokenRefreshHook: async () => {
        refreshHookCalled = true;
        return {
          ok: true,
          updatedHeaders: { 'x-refreshed-token': 'token_fresh_999' },
          newExpiresAt: '2030-01-01T00:00:00.000Z'
        };
      }
    };

    const refreshedResult = await runIdorDifferentialDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'idor_differential_detection_request',
      detectionId: 'det_f3_001b',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/api/v1/documents/:id',
      resourceParamName: 'id',
      baselineResourceId: 'doc_f3_101',
      identityA: {
        identityId: 'user_a',
        sessionState: expiringSessionWithHook
      },
      identityB: {
        identityId: 'user_b'
      },
      transport: refreshableTransport,
      dnsResolver: async () => ['93.184.216.34']
    });

    assert.strictEqual(refreshHookCalled, true, 'Token refresh hook must be executed on expired session');
    assert.strictEqual(refreshedResult.status, 'vulnerability_detected', 'Refreshed session permits execution');
    assert.strictEqual(receivedHeaders[0]?.['x-refreshed-token'], 'token_fresh_999', 'Refreshed header injected into probe');

    console.log('    [PASS] Pre-probe session health verified: expired fails closed; refresh hook orchestrates renewal');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: Target Execution Coordinator (Concurrency & Rate Limiting)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 2: Per-host concurrency ceiling and rate-limiting queue coordination');
  {
    const coordinator = new TargetExecutionCoordinator({
      maxConcurrency: 2,
      requestsPerSecond: 20,
      maxQueueDepth: 50
    });

    let maxObservedConcurrency = 0;
    let currentConcurrency = 0;
    const taskCount = 6;
    const tasks: Promise<number>[] = [];

    for (let i = 0; i < taskCount; i++) {
      tasks.push(
        coordinator.execute('api.example.com', async () => {
          currentConcurrency++;
          if (currentConcurrency > maxObservedConcurrency) {
            maxObservedConcurrency = currentConcurrency;
          }
          // Simulate network probe duration
          await new Promise((r) => setTimeout(r, 40));
          currentConcurrency--;
          return i;
        })
      );
    }

    const results = await Promise.all(tasks);
    assert.strictEqual(results.length, taskCount, 'All queued tasks must complete successfully');
    assert.ok(
      maxObservedConcurrency <= 2,
      `Observed concurrency (${maxObservedConcurrency}) must not exceed ceiling of 2`
    );

    const stats = coordinator.getHostStats('api.example.com');
    assert.strictEqual(stats.activeCount, 0, 'Active count must return to 0');
    assert.strictEqual(stats.totalCompleted, taskCount, 'Total completed must equal task count');

    coordinator.clear();
    console.log('    [PASS] Concurrency ceiling (max 2) strictly respected without request drops');
  }

  // -------------------------------------------------------------------------
  // Assertion 3: Evidence Retention & Pruning Strategy
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 3: Evidence retention boundaries (full on finding, pruned on abstention)');
  {
    const auth = setupAuthorizedContext();

    // 3a. Vulnerable target -> Full bodies, structural schemas, diffs, and candidates preserved
    const vulnerableTransport: IdorHttpProbeTransport = async () => ({
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      bodyText: JSON.stringify({ docId: 'doc_f3_103', owner: 'user_a', details: 'confidential' }),
      responseTimeMs: 25
    });

    const vulnResult = await runIdorDifferentialDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'idor_differential_detection_request',
      detectionId: 'det_f3_003a',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/api/v1/documents/:id',
      resourceParamName: 'id',
      baselineResourceId: 'doc_f3_103',
      identityA: { identityId: 'user_a' },
      identityB: { identityId: 'user_b' },
      transport: vulnerableTransport,
      dnsResolver: async () => ['93.184.216.34']
    });

    assert.strictEqual(vulnResult.status, 'vulnerability_detected');
    assert.ok(vulnResult.finding, 'Finding created on vulnerability');
    assert.ok(vulnResult.findingCandidate, 'Formal candidate preserved on vulnerability');
    assert.ok(vulnResult.baselineSnapshot?.bodyHash, 'Cryptographic hash preserved');

    // 3b. Secure target -> Transient bodies pruned, hashes and metadata preserved
    const secureTransport: IdorHttpProbeTransport = async (req) => {
      const isA = req.headers['x-user'] === 'a';
      if (isA) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({ docId: 'doc_f3_103', owner: 'user_a' }),
          responseTimeMs: 20
        };
      }
      return {
        statusCode: 403,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ error: 'Forbidden' }),
        responseTimeMs: 15
      };
    };

    const abstainedResult = await runIdorDifferentialDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'idor_differential_detection_request',
      detectionId: 'det_f3_003b',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/api/v1/documents/:id',
      resourceParamName: 'id',
      baselineResourceId: 'doc_f3_103',
      identityA: { identityId: 'user_a', headers: { 'x-user': 'a' } },
      identityB: { identityId: 'user_b', headers: { 'x-user': 'b' } },
      transport: secureTransport,
      dnsResolver: async () => ['93.184.216.34']
    });

    assert.strictEqual(abstainedResult.status, 'secure_target_abstained');
    assert.strictEqual(abstainedResult.finding, undefined, 'Finding must be undefined for abstention');
    assert.strictEqual(abstainedResult.findingCandidate, undefined, 'Candidate must be undefined for abstention');

    // Confirm pruning: safeExcerpt removed, while hashes, status, and shapeKind are strictly preserved
    assert.strictEqual(abstainedResult.baselineSnapshot?.safeExcerpt, undefined, 'Transient excerpt pruned');
    assert.strictEqual(abstainedResult.validationSnapshot?.safeExcerpt, undefined, 'Transient excerpt pruned');
    assert.ok(abstainedResult.baselineSnapshot?.bodyHash, 'Cryptographic bodyHash preserved');
    assert.ok(abstainedResult.validationSnapshot?.bodyHash, 'Cryptographic bodyHash preserved');
    assert.strictEqual(abstainedResult.baselineSnapshot?.statusCode, 200, 'Baseline status code preserved');
    assert.strictEqual(abstainedResult.validationSnapshot?.statusCode, 403, 'Validation status code preserved');

    console.log('    [PASS] Full bodies retained for promoted findings; transient bodies pruned for abstained comparisons');
  }

  // -------------------------------------------------------------------------
  // Assertion 4: Lineage Tuple Integrity Across Scale States
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 4: Continuous lineage tuple integrity across coordinated execution');
  {
    const auth = setupAuthorizedContext();

    const mockTransport: IdorHttpProbeTransport = async () => ({
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      bodyText: JSON.stringify({ resource: 'lineage_check' }),
      responseTimeMs: 20
    });

    const result = await runIdorDifferentialDetection({
      contractVersion: 'fixguard-detection/v0',
      kind: 'idor_differential_detection_request',
      detectionId: 'det_f3_004',
      assessmentId: auth.lineage.assessmentId,
      scanId: auth.lineage.scanId,
      authorizationGrantId: auth.lineage.authorizationGrantId,
      authorizationDecisionId: auth.lineage.authorizationDecisionId,
      actorId: auth.lineage.actorId,
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      scopeGrant: auth.scopeGrant,
      endpointUrl: 'https://api.example.com/api/v1/documents/:id',
      resourceParamName: 'id',
      baselineResourceId: 'doc_f3_104',
      identityA: { identityId: 'user_a' },
      identityB: { identityId: 'user_b' },
      transport: mockTransport,
      dnsResolver: async () => ['93.184.216.34']
    });

    assert.strictEqual(result.lineage.assessmentId, auth.lineage.assessmentId);
    assert.strictEqual(result.lineage.scanId, auth.lineage.scanId);
    assert.strictEqual(result.lineage.authorizationGrantId, auth.lineage.authorizationGrantId);
    assert.strictEqual(result.lineage.authorizationDecisionId, auth.lineage.authorizationDecisionId);
    assert.strictEqual(result.lineage.actorId, auth.lineage.actorId);

    // Verify lineage in promoted candidate
    assert.ok(result.findingCandidate, 'Finding candidate must exist');
    assert.strictEqual(result.findingCandidate.scanId, auth.lineage.scanId);

    // Verify lineage in Finding metadata
    const meta = result.finding?.metadata as { lineage?: typeof auth.lineage };
    assert.strictEqual(meta?.lineage?.assessmentId, auth.lineage.assessmentId);
    assert.strictEqual(meta?.lineage?.scanId, auth.lineage.scanId);
    assert.strictEqual(meta?.lineage?.authorizationGrantId, auth.lineage.authorizationGrantId);
    assert.strictEqual(meta?.lineage?.authorizationDecisionId, auth.lineage.authorizationDecisionId);
    assert.strictEqual(meta?.lineage?.actorId, auth.lineage.actorId);

    console.log('    [PASS] Lineage tuple preserved 100% across coordinated execution and candidate promotion');
  }

  console.log('\n>>> ALL 4 MILESTONE F3 ASSERTIONS PASSED SUCCESSFULLY! <<<\n');
}

runMilestoneF3SmokeTests().catch((err) => {
  console.error('\n[!] Smoke test execution failed:', err);
  process.exit(1);
});
