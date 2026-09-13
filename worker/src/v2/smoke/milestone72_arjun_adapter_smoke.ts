import assert from 'node:assert';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { ArjunAdapter } from '../recon/adapters/ArjunAdapter.js';

class MockProcessRunner implements ProcessRunner {
  public calls: ExecutionRequest[] = [];
  public arjunOutput: RawExecutionOutput = {
    stdout: '',
    stderr: '',
    exitCode: 0,
    durationMs: 75,
    timedOut: false,
  };

  async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    this.calls.push(request);
    return this.arjunOutput;
  }
}

function createScopeGrant(overrides?: Partial<AuthorizedScopeGrant>): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_m72_001',
    scanId: 'scan_m72_001',
    issuedAt: '2026-09-13T12:00:00.000Z',
    expiresAt: '2026-09-14T12:00:00.000Z',
    subject: {
      targetKind: 'domain',
      domain: 'example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for parameter discovery fuzzing in milestone 72',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: false,
      endpointDiscovery: true,
      activeCrawling: false,
      authenticatedTesting: false,
      lightValidation: false,
      activeValidation: true,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: ['example.com'],
      allowedHosts: ['example.com'],
      allowedOrigins: ['https://example.com'],
      allowedMethods: ['GET', 'POST'],
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
    ...overrides,
  };
}

function setupAuthorizedContext(scopeGrant = createScopeGrant()) {
  const establishResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'assess_m72_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_m72_001',
      authorizedActor: { actorId: 'pentest_lead_1', actorType: 'human' },
      decision: 'authorized',
      decidedAt: '2026-09-13T12:00:00.000Z',
      scopeGrant,
    },
    '2026-09-13T12:00:00.000Z'
  );

  if (establishResult.status !== 'established') {
    throw new Error(`Failed to establish verified decision: ${establishResult.safeMessage}`);
  }

  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'assess_m72_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'decision_m72_001',
    actorId: 'pentest_lead_1',
  };

  return {
    verifiedAuthorizationDecision: establishResult.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
  };
}

async function runMilestone72SmokeTests() {
  console.log('=== [M72 SMOKE] Active Parameter Discovery Tool Adapter (Arjun) ===\n');

  // -------------------------------------------------------------------------
  // Assertion 1: Happy Path Parameter Discovery & Non-Claims
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 1: Happy path parameter discovery with factual non-claims');
  {
    const runner = new MockProcessRunner();
    runner.arjunOutput = {
      stdout: JSON.stringify({
        'https://example.com/api/users': ['id', 'debug', 'limit'],
      }),
      stderr: '',
      exitCode: 0,
      durationMs: 85,
      timedOut: false,
    };

    const adapter = new ArjunAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverParameters({
      targetUrl: 'https://example.com/api/users',
      httpMethod: 'GET',
      ...auth,
      timeoutMs: 30_000,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.targetUrl, 'https://example.com/api/users');
      assert.strictEqual(result.observations.length, 3);

      const params = result.observations.map((o) => o.parameterName).sort();
      assert.deepStrictEqual(params, ['debug', 'id', 'limit']);

      for (const obs of result.observations) {
        assert.strictEqual(obs.method, 'GET');
        assert.strictEqual(obs.url, 'https://example.com/api/users');
      }

      // Verify anti-speculation non-claims: debug is not converted to critical finding
      assert.strictEqual(result.explicitNonClaims.severity, 'info');
      assert.strictEqual(result.explicitNonClaims.createsRealFindings, false);
      assert.strictEqual(result.explicitNonClaims.confirmsVulnerabilities, false);
      assert.strictEqual(result.explicitNonClaims.makesSeverityClaims, false);

      assert.strictEqual(runner.calls.length, 1);
      assert.strictEqual(runner.calls[0].binary, 'arjun');
      assert.strictEqual(runner.calls[0].args[0], '-u');
      assert.strictEqual(runner.calls[0].args[1], 'https://example.com/api/users');
      assert.strictEqual(runner.calls[0].args[2], '-m');
      assert.strictEqual(runner.calls[0].args[3], 'GET');
    }
    console.log('    -> Happy path verified: parameters parsed, non-claims intact, argument isolation confirmed');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: Evasion Knobs Mapping (ChunkSize, Delay, Method)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 2: Evasion knobs mapping (-c, -d, -m) and omission when undefined');
  {
    const runner = new MockProcessRunner();
    runner.arjunOutput = {
      stdout: JSON.stringify({
        'https://example.com/api/search': ['q'],
      }),
      stderr: '',
      exitCode: 0,
      durationMs: 40,
      timedOut: false,
    };

    const adapter = new ArjunAdapter(runner);
    const auth = setupAuthorizedContext();

    // 1. Explicit evasion knobs provided
    await adapter.discoverParameters({
      targetUrl: 'https://example.com/api/search',
      httpMethod: 'POST',
      chunkSize: 100,
      delaySeconds: 1.5,
      ...auth,
    });

    assert.strictEqual(runner.calls.length, 1);
    const explicitArgs = runner.calls[0].args;
    const mIdx = explicitArgs.indexOf('-m');
    assert(mIdx !== -1 && explicitArgs[mIdx + 1] === 'POST');

    const cIdx = explicitArgs.indexOf('-c');
    assert(cIdx !== -1 && explicitArgs[cIdx + 1] === '100');

    const dIdx = explicitArgs.indexOf('-d');
    assert(dIdx !== -1 && explicitArgs[dIdx + 1] === '1.5');

    const oJIdx = explicitArgs.indexOf('-oJ');
    assert(oJIdx !== -1 && explicitArgs[oJIdx + 1].includes('arjun-'));

    // 2. Undefined knobs MUST NOT be injected
    runner.calls = [];
    await adapter.discoverParameters({
      targetUrl: 'https://example.com/api/search',
      ...auth,
    });

    assert.strictEqual(runner.calls.length, 1);
    const omittedArgs = runner.calls[0].args;
    assert.strictEqual(omittedArgs.indexOf('-c'), -1, '-c must NOT be present when undefined');
    assert.strictEqual(omittedArgs.indexOf('-d'), -1, '-d must NOT be present when undefined');

    console.log('    -> Evasion knobs strictly mapped when defined and omitted when undefined');
  }

  // -------------------------------------------------------------------------
  // Assertion 3: Deep SSRF & Scope Egress Gate
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 3: Deep SSRF & Scope Egress Gate (Dropping parameters for restricted IP destinations)');
  {
    const runner = new MockProcessRunner();
    runner.arjunOutput = {
      stdout: JSON.stringify({
        'https://example.com/api/v1': ['safe_param'],
        'http://10.0.0.1/admin': ['internal_token'],
        'http://127.0.0.1/status': ['loopback_key'],
        'http://169.254.169.254/latest': ['meta_param'],
      }),
      stderr: '',
      exitCode: 0,
      durationMs: 50,
      timedOut: false,
    };

    const adapter = new ArjunAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverParameters({
      targetUrl: 'https://example.com/api/v1',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 1, 'Only in-scope non-SSRF endpoint must remain');
      assert.strictEqual(result.observations[0].url, 'https://example.com/api/v1');
      assert.strictEqual(result.observations[0].parameterName, 'safe_param');
    }
    console.log('    -> All SSRF-restricted IP parameters safely dropped by egress gate');
  }

  // -------------------------------------------------------------------------
  // Assertion 4: Atomic Preflight Denial (Missing or Spoofed Authorization Brand)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 4: Atomic Preflight Denial (Missing or spoofed authorization brand)');
  {
    const runner = new MockProcessRunner();
    const adapter = new ArjunAdapter(runner);
    const auth = setupAuthorizedContext();

    const spoofedDecision = {
      ...auth.verifiedAuthorizationDecision,
      decision: 'authorized' as const,
    };

    const result = await adapter.discoverParameters({
      targetUrl: 'https://example.com/api',
      verifiedAuthorizationDecision: spoofedDecision,
      authorizedScopeGrant: auth.authorizedScopeGrant,
      lineage: auth.lineage,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'authorization_unconfirmed');
    }
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned on unbranded decision');
    console.log('    -> Preflight safely denied unbranded decision with zero process invocations');
  }

  // -------------------------------------------------------------------------
  // Assertion 5: Atomic Preflight Denial (Target Outside Scope Boundaries)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 5: Atomic Preflight Denial (Target URL outside scope boundaries)');
  {
    const runner = new MockProcessRunner();
    const adapter = new ArjunAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverParameters({
      targetUrl: 'https://unauthorized-site.com/api',
      ...auth,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'target_out_of_scope');
    }
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for out-of-scope target');
    console.log('    -> Preflight safely denied out-of-scope target URL');
  }

  // -------------------------------------------------------------------------
  // Assertion 6: Atomic Preflight Denial (Missing Permissions)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 6: Atomic Preflight Denial (Grant lacks parameter discovery permissions)');
  {
    const runner = new MockProcessRunner();
    const adapter = new ArjunAdapter(runner);
    const restrictedGrant = createScopeGrant({
      permissionSet: {
        passiveRecon: false,
        technologyFingerprinting: false,
        endpointDiscovery: false,
        activeCrawling: false,
        authenticatedTesting: false,
        lightValidation: false,
        activeValidation: false,
        aggressiveValidation: false,
        oobTesting: false,
        destructiveOperations: false,
      },
    });
    const auth = setupAuthorizedContext(restrictedGrant);

    const result = await adapter.discoverParameters({
      targetUrl: 'https://example.com/api',
      ...auth,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'missing_permission');
    }
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned on permission denial');
    console.log('    -> Preflight safely denied execution lacking recon permissions');
  }

  // -------------------------------------------------------------------------
  // Assertion 7: Target URL SSRF Pre-Check Denial
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 7: Target URL SSRF Pre-Check Denial (Loopback / metadata targets)');
  {
    const runner = new MockProcessRunner();
    const adapter = new ArjunAdapter(runner);
    const auth = setupAuthorizedContext();

    // Loopback
    const loopbackResult = await adapter.discoverParameters({
      targetUrl: 'http://127.0.0.1:8080/api',
      ...auth,
    });
    assert.strictEqual(loopbackResult.status, 'preflight_denied');
    if (loopbackResult.status === 'preflight_denied') {
      assert.strictEqual(loopbackResult.reasonCode, 'ssrf_target_blocked');
    }

    // Cloud metadata
    const metadataResult = await adapter.discoverParameters({
      targetUrl: 'http://169.254.169.254/latest/meta-data',
      ...auth,
    });
    assert.strictEqual(metadataResult.status, 'preflight_denied');
    if (metadataResult.status === 'preflight_denied') {
      assert.strictEqual(metadataResult.reasonCode, 'ssrf_target_blocked');
    }

    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for SSRF targets');
    console.log('    -> All SSRF-restricted target URLs safely blocked in preflight');
  }

  // -------------------------------------------------------------------------
  // Assertion 8: Empty & Malformed Output Resilience
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 8: Empty & Malformed Output Resilience');
  {
    const runner = new MockProcessRunner();
    runner.arjunOutput = {
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 30,
      timedOut: false,
    };

    const adapter = new ArjunAdapter(runner);
    const auth = setupAuthorizedContext();

    // Empty output test
    const emptyResult = await adapter.discoverParameters({
      targetUrl: 'https://example.com/api',
      ...auth,
    });

    assert.strictEqual(emptyResult.status, 'success');
    if (emptyResult.status === 'success') {
      assert.strictEqual(emptyResult.observations.length, 0);
      assert.deepStrictEqual(emptyResult.observations, []);
    }

    // Malformed JSON output test
    runner.arjunOutput = {
      stdout: [
        'arjun starting...',
        '{ invalid json [',
        '',
        JSON.stringify({
          url: 'https://example.com/api',
          params: ['resilient_param'],
        }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 35,
      timedOut: false,
    };

    const resilientResult = await adapter.discoverParameters({
      targetUrl: 'https://example.com/api',
      ...auth,
    });

    assert.strictEqual(resilientResult.status, 'success');
    if (resilientResult.status === 'success') {
      assert.strictEqual(resilientResult.observations.length, 1);
      assert.strictEqual(resilientResult.observations[0].parameterName, 'resilient_param');
    }

    console.log('    -> Clean zero observations on empty output and fail-closed malformed line resilience verified');
  }

  console.log('\n[✔] ALL MILESTONE 72 PARAMETER DISCOVERY ADAPTER SMOKE ASSERTIONS PASSED SUCCESSFULLY.');
}

runMilestone72SmokeTests().catch((err) => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
