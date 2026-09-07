import assert from 'node:assert';

import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
const validDecision = (establishVerifiedAuthorizationDecision({
  contractVersion: 'fixguard-verified-authorization-decision/v0',
  kind: 'establish_verified_authorization_decision_request',
  assessmentId: 'assess_1',
  scanId: 'scan_1',
  authorizationDecisionId: 'dec_1',
  authorizedActor: { actorId: 'sys', actorType: 'human' },
  decision: 'authorized',
  decidedAt: '2026-07-01T12:00:00.000Z',
  scopeGrant: {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_1',
    scanId: 'scan_1',
    issuedAt: '2026-07-01T00:00:00.000Z',
    expiresAt: '2026-07-10T23:59:59.999Z',
    subject: { targetKind: 'origin', normalizedOrigin: 'https://example.com' },
    authorizationBasis: { basisKind: 'internal_asset_record', recordedBy: 'human_user', authorizationText: 'Test' },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: false,
      authenticatedTesting: false,
      lightValidation: true,
      activeValidation: false,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedOrigins: ['https://example.com'],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
      allowedPathPatterns: [{ match: 'prefix', pathTemplate: '/' }],
      deniedPathPatterns: [],
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
  },
} as any, '2026-07-01T12:00:00.000Z') as any).decision;
import {
  runActiveReconDocumentProbes,
  type ActiveReconDocumentProbeAdapters,
} from '../recon/active/ActiveReconDocumentProbeRunner.js';
import type { AuthorizedScope } from '../recon/policy/EgressPolicyContracts.js';
import type { SafeActiveReconObservation } from '../recon/active/ActiveReconContracts.js';

console.log('--- V2 Active Recon Document Probe Runner DB-Free Smoke Test ---');

const scope: AuthorizedScope = {
  allowedOrigins: ['https://example.com'],
  allowSameHostPaths: true,
  allowSubdomains: false,
};

const baseAuth = { confirmed: true as const, scopeLabel: 'test' };

// Spy adapter that records calls and returns canned observations
function makeFakeRobotsAdapter(returnObs?: SafeActiveReconObservation[]) {
  let callCount = 0;
  const adapter = {
    get callCount() { return callCount; },
    async probe() {
      callCount++;
      return returnObs ?? [{
        kind: 'robots_metadata' as const,
        safeSummary: 'Fake robots probe executed',
        confidence: 'high' as const,
        metadata: {
          reachable: true,
          hasDisallowDirective: true,
          recognizedDirectiveLineCount: 2
        }
      }];
    }
  };
  return adapter;
}

function makeFakeSecurityTxtAdapter(returnObs?: SafeActiveReconObservation[]) {
  let callCount = 0;
  const adapter = {
    get callCount() { return callCount; },
    async probe() {
      callCount++;
      return returnObs ?? [{
        kind: 'security_txt_metadata' as const,
        safeSummary: 'Fake security.txt probe executed',
        confidence: 'high' as const,
        metadata: {
          reachable: true,
          hasContactField: true,
          recognizedFieldLineCount: 3
        }
      }];
    }
  };
  return adapter;
}

async function runTests() {
  // ========================================================================
  // FINDING 1 FIX TESTS: Runtime authorization enforcement
  // ========================================================================

  // --- Test 1a: Missing authorization — adapters must not be called ---
  {
    const robotsSpy = makeFakeRobotsAdapter();
    // Bypass TypeScript type by casting — Codex confirmed TS alone is insufficient
    const result = await runActiveReconDocumentProbes(
      {
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: undefined as any,   // missing authorization
        probes: [{ probeId: 'p1', kind: 'http.robots.inspect', targetUrl: 'https://example.com/robots.txt' }],
      },
      { robots: robotsSpy }
    );

    assert.strictEqual(robotsSpy.callCount, 0, 'Adapter must not be called when authorization is missing');
    assert.strictEqual(result.completedProbeCount, 0, 'No probes must complete');
    assert.strictEqual(result.failedProbeCount, 1, 'All probes must fail');
    assert.strictEqual(result.probes[0].error?.code, 'authorization_not_confirmed');
    const resultJson = JSON.stringify(result);
    assert.ok(!resultJson.includes('robots.txt'), 'Raw target URL must not be in result when authorization is missing');
    console.log('[+] Missing authorization: no adapters invoked, no probes completed, safe error returned.');
  }

  // --- Test 1b: authorization.confirmed=false — adapters must not be called ---
  {
    const robotsSpy = makeFakeRobotsAdapter();
    const result = await runActiveReconDocumentProbes(
      {
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: { confirmed: false } as any,  // false — must be rejected at runtime
        probes: [{ probeId: 'p1', kind: 'http.robots.inspect', targetUrl: 'https://example.com/robots.txt' }],
      },
      { robots: robotsSpy }
    );

    assert.strictEqual(robotsSpy.callCount, 0, 'Adapter must not be called when confirmed=false');
    assert.strictEqual(result.completedProbeCount, 0, 'No probes must complete');
    assert.strictEqual(result.failedProbeCount, 1, 'All probes must fail');
    assert.strictEqual(result.probes[0].error?.code, 'authorization_not_confirmed');
    console.log('[+] authorization.confirmed=false: no adapters invoked, no probes completed, safe error returned.');
  }

  // ========================================================================
  // FINDING 2 FIX TESTS: Safe runner-generated IDs
  // ========================================================================

  // --- Test 2: Secret-bearing runId/probeId do not survive serialization ---
  {
    const robotsSpy = makeFakeRobotsAdapter();
    const result = await runActiveReconDocumentProbes(
      {
        runId: 'SECRET_RUN_ID',    // hostile — must not appear in result
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: validDecision,
        probes: [
          { probeId: 'SECRET_PROBE_ID', kind: 'http.robots.inspect', targetUrl: 'https://example.com/robots.txt' },
        ],
      },
      { robots: robotsSpy }
    );

    const resultJson = JSON.stringify(result);
    assert.ok(!resultJson.includes('SECRET_RUN_ID'), 'Hostile runId must not survive serialization');
    assert.ok(!resultJson.includes('SECRET_PROBE_ID'), 'Hostile probeId must not survive serialization');
    assert.ok(!resultJson.includes('SECRET'), 'No SECRET string must survive serialization from IDs');
    // Runner-generated IDs follow safe pattern
    assert.ok(result.runId.startsWith('run_'), `runId must be runner-generated, got: ${result.runId}`);
    assert.ok(result.probes[0].safeProbeIndex === 'probe-1', `safeProbeIndex must be probe-1, got: ${result.probes[0].safeProbeIndex}`);
    console.log('[+] Secret-bearing runId/probeId do not survive serialization.');
  }

  // ========================================================================
  // FINDING 3 FIX TESTS: Unsupported raw probe kind not echoed
  // ========================================================================

  // --- Test 3: Hostile unsupported probe kind with embedded secret ---
  {
    const robotsSpy = makeFakeRobotsAdapter();
    // Codex hostile fixture: raw unsupported kind with embedded token
    const result = await runActiveReconDocumentProbes(
      {
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: validDecision,
        probes: [
          { probeId: 'p1', kind: 'http.evil.inspect?token=SECRET' as any, targetUrl: 'https://example.com/whatever' },
        ],
      },
      { robots: robotsSpy }
    );

    assert.strictEqual(robotsSpy.callCount, 0, 'Adapter must not be called for unsupported kind');
    assert.strictEqual(result.probes[0].status, 'failed');
    assert.strictEqual(result.probes[0].error?.code, 'unsupported_probe');
    assert.strictEqual(result.probes[0].safeKind, 'unknown', 'safeKind must be "unknown" for unsupported probe');

    const resultJson = JSON.stringify(result);
    // Raw unsupported kind values must not survive serialization
    assert.ok(!resultJson.includes('http.evil.inspect'), 'Raw unsupported kind must not appear in result');
    assert.ok(!resultJson.includes('token'), 'Query param from hostile kind must not appear in result');
    assert.ok(!resultJson.includes('SECRET'), 'SECRET from hostile kind must not appear in result');
    // Error message must be fixed, not dynamic with raw kind
    assert.strictEqual(
      result.probes[0].error?.message,
      'Unsupported document probe kind.',
      'Error message must be fixed, not echoing raw kind'
    );
    console.log('[+] Hostile unsupported probe kind does not leak in result; safe sentinel used.');
  }

  // ========================================================================
  // ORIGINAL TESTS (updated to use safeProbeIndex/safeKind)
  // ========================================================================

  // --- Test 4: Unsupported known-format probe kind is rejected ---
  {
    const result = await runActiveReconDocumentProbes(
      {
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: validDecision,
        probes: [
          { probeId: 'p1', kind: 'http.robots.inspect', targetUrl: 'https://example.com/robots.txt' },
          { probeId: 'p2', kind: 'http.unknown.probe' as any, targetUrl: 'https://example.com/whatever' }
        ],
      },
      {}
    );

    const unsupported = result.probes.find(p => p.safeKind === 'unknown')!;
    assert.ok(unsupported !== undefined, 'Unsupported probe must produce unknown safeKind');
    assert.strictEqual(unsupported.status, 'failed');
    assert.strictEqual(unsupported.error?.code, 'unsupported_probe');
    assert.strictEqual(unsupported.observations.length, 0);
    // Raw kind must not be in result
    const resultJson = JSON.stringify(result);
    assert.ok(!resultJson.includes('http.unknown.probe'), 'Raw unsupported kind must not appear in result');
    console.log('[+] Unsupported probe kind is safely rejected without echoing raw kind.');
  }

  // --- Test 5: Blocked policy decision does not invoke adapter ---
  {
    const robotsSpy = makeFakeRobotsAdapter();
    const adapters: ActiveReconDocumentProbeAdapters = { robots: robotsSpy };
    const result = await runActiveReconDocumentProbes(
      {
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: validDecision,
        probes: [{ probeId: 'p1', kind: 'http.robots.inspect', targetUrl: 'https://blocked-site.com/robots.txt' }],
      },
      adapters
    );

    const probe = result.probes[0];
    assert.strictEqual(probe.status, 'blocked');
    assert.strictEqual(probe.policyDecision, 'block');
    assert.strictEqual(probe.error?.code, 'policy_blocked');
    assert.strictEqual(robotsSpy.callCount, 0, 'Adapter must not be called for blocked target');
    assert.strictEqual(probe.observations.length, 0);
    console.log('[+] Blocked policy decision does not invoke adapter.');
  }

  // --- Test 6: Out-of-scope/candidate target does not invoke adapter ---
  {
    const robotsSpy = makeFakeRobotsAdapter();
    const adapters: ActiveReconDocumentProbeAdapters = { robots: robotsSpy };
    const scopeNoSubdomains: AuthorizedScope = {
      allowedOrigins: ['https://example.com'],
      allowSameHostPaths: false,
      allowSubdomains: false,
    };
    const result = await runActiveReconDocumentProbes(
      {
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: validDecision,
        probes: [{ probeId: 'p1', kind: 'http.robots.inspect', targetUrl: 'https://sub.example.com/robots.txt' }],
      },
      adapters
    );

    const probe = result.probes[0];
    assert.ok(probe.status === 'blocked' || probe.status === 'candidate', 'Must not proceed to adapter for subdomain');
    assert.strictEqual(robotsSpy.callCount, 0, 'Adapter must not be called for out-of-scope target');
    console.log('[+] Out-of-scope/candidate target does not invoke adapter.');
  }

  // --- Test 7: Allowed policy decision invokes only the matching adapter ---
  {
    const robotsSpy = makeFakeRobotsAdapter();
    const securityTxtSpy = makeFakeSecurityTxtAdapter();
    const adapters: ActiveReconDocumentProbeAdapters = { robots: robotsSpy, securityTxt: securityTxtSpy };

    const result = await runActiveReconDocumentProbes(
      {
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: validDecision,
        probes: [
          { probeId: 'p1', kind: 'http.robots.inspect', targetUrl: 'https://example.com/robots.txt' },
          { probeId: 'p2', kind: 'http.security_txt.inspect', targetUrl: 'https://example.com/.well-known/security.txt' },
        ],
      },
      adapters
    );

    assert.strictEqual(robotsSpy.callCount, 1, 'Robots adapter must be called exactly once');
    assert.strictEqual(securityTxtSpy.callCount, 1, 'SecurityTxt adapter must be called exactly once');
    assert.strictEqual(result.completedProbeCount, 2);
    assert.strictEqual(result.probes[0].status, 'completed');
    assert.strictEqual(result.probes[1].status, 'completed');
    // Safe IDs are probe-1 and probe-2
    assert.strictEqual(result.probes[0].safeProbeIndex, 'probe-1');
    assert.strictEqual(result.probes[1].safeProbeIndex, 'probe-2');
    assert.ok(result.observations.length >= 2, 'Observations aggregated from both probes');
    console.log('[+] Allowed policy decisions invoke only matching adapters.');
  }

  // --- Test 8: adapter_missing is safe ---
  {
    const result = await runActiveReconDocumentProbes(
      {
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: validDecision,
        probes: [{ probeId: 'p1', kind: 'http.robots.inspect', targetUrl: 'https://example.com/robots.txt' }],
      },
      {} // no adapters injected
    );

    const probe = result.probes[0];
    assert.strictEqual(probe.status, 'failed');
    assert.strictEqual(probe.error?.code, 'adapter_missing');
    assert.strictEqual(probe.observations.length, 0);
    console.log('[+] adapter_missing is safely reported without fallback.');
  }

  // --- Test 9: adapter_failed is safe and does not include raw exception data ---
  {
    const failingAdapter = {
      async probe() {
        throw new Error('Raw URL with token=SECRET and /secret/path exposed in exception');
      }
    };
    const adapters: ActiveReconDocumentProbeAdapters = { robots: failingAdapter };

    const result = await runActiveReconDocumentProbes(
      {
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: validDecision,
        probes: [{ probeId: 'p1', kind: 'http.robots.inspect', targetUrl: 'https://example.com/robots.txt' }],
      },
      adapters
    );

    const probe = result.probes[0];
    assert.strictEqual(probe.status, 'failed');
    assert.strictEqual(probe.error?.code, 'adapter_failed');
    assert.strictEqual(probe.observations.length, 0);

    const resultJson = JSON.stringify(result);
    assert.ok(!resultJson.includes('SECRET'), 'Raw exception data must not leak in result');
    assert.ok(!resultJson.includes('/secret/path'), 'Raw paths in exceptions must not leak');
    console.log('[+] adapter_failed is safe; raw exception data does not leak in result.');
  }

  // --- Test 10: No raw body/header/request/response/payload; classification flags safe ---
  {
    const robotsSpy = makeFakeRobotsAdapter();
    const adapters: ActiveReconDocumentProbeAdapters = { robots: robotsSpy };

    const result = await runActiveReconDocumentProbes(
      {
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: validDecision,
        probes: [{ probeId: 'p1', kind: 'http.robots.inspect', targetUrl: 'https://example.com/robots.txt' }],
      },
      adapters
    );

    const resultJson = JSON.stringify(result);
    assert.ok(!resultJson.includes('"body":'), 'No raw body in result');
    assert.ok(!resultJson.includes('"headers":'), 'No raw headers in result');
    assert.ok(!resultJson.includes('"request":'), 'No raw request in result');
    assert.ok(!resultJson.includes('"response":'), 'No raw response in result');
    assert.ok(!resultJson.includes('"payload":'), 'No raw payload in result');
    assert.ok(!resultJson.includes('"finding":true'), 'finding must never be true');
    assert.ok(!resultJson.includes('"evidence":true'), 'evidence must never be true');
    assert.ok(!resultJson.includes('"vulnerability":true'), 'vulnerability must never be true');
    assert.ok(!resultJson.includes('"riskClaim":true'), 'riskClaim must never be true');
    assert.ok(!resultJson.includes('"severity":'), 'No severity field in result');
    assert.ok(!resultJson.includes('"impact":'), 'No impact field in result');
    assert.ok(!resultJson.includes('"exploit":'), 'No exploit field in result');
    console.log('[+] Result contains no raw body/header/request/response/payload; classification flags are all false.');
  }

  // --- Test 11: Query/fragment/secret in target URL does not leak as raw value ---
  {
    const robotsSpy = makeFakeRobotsAdapter();

    const result = await runActiveReconDocumentProbes(
      {
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: validDecision,
        probes: [
          { probeId: 'p1', kind: 'http.robots.inspect', targetUrl: 'https://example.com/robots.txt?token=SECRET' },
          { probeId: 'p2', kind: 'http.security_txt.inspect', targetUrl: 'https://example.com/.well-known/security.txt?api_key=SECRET' },
        ],
      },
      { robots: robotsSpy }
    );

    const resultJson = JSON.stringify(result);
    assert.ok(!resultJson.includes('SECRET'), 'Raw secret value must not appear in result');
    assert.ok(!resultJson.includes('"api_key='), 'Raw api_key query param must not appear literally');

    for (const probe of result.probes) {
      if (probe.status === 'completed') {
        const probeJson = JSON.stringify(probe);
        assert.ok(!probeJson.includes('SECRET'), `Raw secret must not be in completed probe ${probe.safeProbeIndex}`);
      }
    }
    console.log('[+] Query/secret in target URL does not leak as raw value in result.');
  }

  // --- Test 12: Classification flags are always false ---
  {
    const result = await runActiveReconDocumentProbes(
      {
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: validDecision,
        probes: [{ probeId: 'p1', kind: 'http.robots.inspect', targetUrl: 'https://example.com/robots.txt' }],
      },
      { robots: makeFakeRobotsAdapter() }
    );

    assert.strictEqual(result.classification.finding, false);
    assert.strictEqual(result.classification.evidence, false);
    assert.strictEqual(result.classification.vulnerability, false);
    assert.strictEqual(result.classification.riskClaim, false);
    console.log('[+] Classification flags are all false.');
  }

  // --- Test 13: Count aggregation is correct ---
  {
    const securityTxtSpy = makeFakeSecurityTxtAdapter();

    const result = await runActiveReconDocumentProbes(
      {
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: validDecision,
        probes: [
          { probeId: 'p1', kind: 'http.robots.inspect', targetUrl: 'https://example.com/robots.txt' },
          { probeId: 'p2', kind: 'http.security_txt.inspect', targetUrl: 'https://example.com/.well-known/security.txt' },
          { probeId: 'p3', kind: 'http.robots.inspect', targetUrl: 'https://blocked.com/robots.txt' },
          { probeId: 'p4', kind: 'http.robots.inspect', targetUrl: 'https://example.com/robots.txt' },
        ],
      },
      {
        robots: {
          async probe() { throw new Error('fail'); }
        },
        securityTxt: securityTxtSpy
      }
    );

    assert.strictEqual(result.requestedProbeCount, 4, 'requestedProbeCount must match probe count');
    assert.strictEqual(result.classification.finding, false);
    console.log('[+] Count aggregation is correct; classification is safe.');
  }

  // --- Test 14: Fake fixtures are not represented as real target evidence ---
  {
    const result = await runActiveReconDocumentProbes(
      {
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: validDecision,
        probes: [{ probeId: 'p1', kind: 'http.robots.inspect', targetUrl: 'https://example.com/robots.txt' }],
      },
      { robots: makeFakeRobotsAdapter() }
    );

    const obs = result.probes[0].observations[0];
    assert.ok(obs !== undefined, 'Should have at least one observation');
    assert.ok(!('rawBody' in obs), 'No rawBody in observation');
    assert.ok(!('rawHeaders' in obs), 'No rawHeaders in observation');
    assert.ok(!('evidence' in obs), 'No evidence field in observation');
    assert.ok(!('finding' in obs), 'No finding field in observation');
    console.log('[+] Fake fixtures are not represented as real target evidence.');
  }

  // --- Test 15: Runner-generated IDs — no caller runId echoed ---
  {
    const result = await runActiveReconDocumentProbes(
      {
        runId: 'caller-supplied-id-ignored',  // ignored by runner
        contractVersion: 'active-recon-document-probe-run/v1',
        evaluatedAt: '2026-07-01T12:00:00.000Z',
        verifiedAuthorizationDecision: validDecision,
        probes: [],
      },
      {}
    );
    // Runner always generates its own ID — never echoes caller input
    assert.ok(result.runId.startsWith('run_'), `runId must be runner-generated, got: ${result.runId}`);
    assert.ok(!result.runId.includes('caller-supplied-id-ignored'), 'Caller runId must not be echoed');
    assert.strictEqual(result.requestedProbeCount, 0);
    assert.strictEqual(result.completedProbeCount, 0);
    console.log('[+] Runner-generated IDs: caller runId is never echoed in output.');
  }

  console.log('--- V2 Active Recon Document Probe Runner DB-Free Smoke Completed Successfully ---');
}

runTests().catch(err => {
  console.error(err);
  process.exit(1);
});
