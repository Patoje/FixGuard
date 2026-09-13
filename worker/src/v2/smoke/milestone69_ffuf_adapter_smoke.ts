import assert from 'node:assert';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { FfufAdapter } from '../recon/adapters/FfufAdapter.js';

class MockProcessRunner implements ProcessRunner {
  public calls: ExecutionRequest[] = [];
  public ffufOutput: RawExecutionOutput = {
    stdout: '',
    stderr: '',
    exitCode: 0,
    durationMs: 85,
    timedOut: false,
  };

  async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    this.calls.push(request);
    return this.ffufOutput;
  }
}

function createScopeGrant(overrides?: Partial<AuthorizedScopeGrant>): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_m69_001',
    scanId: 'scan_m69_001',
    issuedAt: '2026-09-13T12:00:00.000Z',
    expiresAt: '2026-09-14T12:00:00.000Z',
    subject: {
      targetKind: 'domain',
      domain: 'example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for content discovery fuzzing in milestone 69',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: false,
      endpointDiscovery: true,
      activeCrawling: true,
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
      allowedMethods: ['GET'],
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
      assessmentId: 'assess_m69_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_m69_001',
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
    assessmentId: 'assess_m69_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'decision_m69_001',
    actorId: 'pentest_lead_1',
  };

  return {
    verifiedAuthorizationDecision: establishResult.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
  };
}

async function runMilestone69SmokeTests() {
  console.log('=== [M69 SMOKE] Exhaustive & Evasive Content Discovery Adapter (Ffuf) ===\n');

  // -------------------------------------------------------------------------
  // Assertion 1: Happy Path Discovery & Evasion Argument Isolation
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 1: Happy path discovery with evasion parameters and non-claims');
  {
    const runner = new MockProcessRunner();
    runner.ffufOutput = {
      stdout: JSON.stringify({
        results: [
          {
            input: { FUZZ: 'admin' },
            position: 1,
            status: 200,
            length: 1420,
            words: 60,
            lines: 15,
            'content-type': 'text/html; charset=utf-8',
            redirectlocation: '',
            url: 'https://example.com/admin',
          },
          {
            input: { FUZZ: 'api/v1/health' },
            position: 2,
            status: 200,
            length: 54,
            words: 3,
            lines: 1,
            'content-type': 'application/json',
            redirectlocation: '',
            url: 'https://example.com/api/v1/health',
          },
        ],
      }),
      stderr: '',
      exitCode: 0,
      durationMs: 110,
      timedOut: false,
    };

    const adapter = new FfufAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverContent({
      targetUrl: 'https://example.com',
      wordlistPath: 'wordlists/common.txt',
      autoCalibrate: true,
      rateLimit: 25,
      delaySeconds: 0.2,
      recursionDepth: 2,
      ...auth,
      timeoutMs: 40_000,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.targetUrl, 'https://example.com');
      assert.strictEqual(result.wordlistPath, 'wordlists/common.txt');
      assert.strictEqual(result.observations.length, 2);

      const adminObs = result.observations.find((o) => o.path === '/admin');
      assert(adminObs, 'admin endpoint must be found');
      assert.strictEqual(adminObs.statusCode, 200);
      assert.strictEqual(adminObs.contentLength, 1420);
      assert.strictEqual(adminObs.contentType, 'text/html; charset=utf-8');

      const healthObs = result.observations.find((o) => o.path === '/api/v1/health');
      assert(healthObs, 'health endpoint must be found');
      assert.strictEqual(healthObs.statusCode, 200);
      assert.strictEqual(healthObs.contentLength, 54);
      assert.strictEqual(healthObs.contentType, 'application/json');

      // Verify anti-speculation explicit non-claims
      assert.strictEqual(result.explicitNonClaims.severity, 'info');
      assert.strictEqual(result.explicitNonClaims.createsRealFindings, false);
      assert.strictEqual(result.explicitNonClaims.confirmsVulnerabilities, false);
      assert.strictEqual(result.explicitNonClaims.makesSeverityClaims, false);

      // Verify process isolation and evasion knobs
      assert.strictEqual(runner.calls.length, 1);
      assert.strictEqual(runner.calls[0].binary, 'ffuf');
      assert.deepStrictEqual(runner.calls[0].args, [
        '-u',
        'https://example.com/FUZZ',
        '-w',
        'wordlists/common.txt',
        '-json',
        '-ac',
        '-rate',
        '25',
        '-p',
        '0.2',
        '-recursion',
        '-recursion-depth',
        '2',
      ]);
      assert.strictEqual(runner.calls[0].timeoutMs, 40_000);
    }
    console.log('    -> Happy path verified: observations parsed, evasion knobs isolated, non-claims intact');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: Wordlist Path Traversal Denial
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 2: Wordlist Path Traversal Denial (Preflight strictly rejects ../ and OS dirs)');
  {
    const runner = new MockProcessRunner();
    const adapter = new FfufAdapter(runner);
    const auth = setupAuthorizedContext();

    // 1. Path traversal attempt with '../'
    const traversalResult = await adapter.discoverContent({
      targetUrl: 'https://example.com',
      wordlistPath: '../../../../etc/passwd',
      ...auth,
    });
    assert.strictEqual(traversalResult.status, 'preflight_denied');
    if (traversalResult.status === 'preflight_denied') {
      assert.strictEqual(traversalResult.reasonCode, 'unsafe_wordlist_path');
    }

    // 2. Forbidden /etc directory attempt
    const etcResult = await adapter.discoverContent({
      targetUrl: 'https://example.com',
      wordlistPath: '/etc/shadow',
      ...auth,
    });
    assert.strictEqual(etcResult.status, 'preflight_denied');
    if (etcResult.status === 'preflight_denied') {
      assert.strictEqual(etcResult.reasonCode, 'unsafe_wordlist_path');
    }

    // 3. Forbidden /var directory attempt
    const varResult = await adapter.discoverContent({
      targetUrl: 'https://example.com',
      wordlistPath: '/var/log/auth.log',
      ...auth,
    });
    assert.strictEqual(varResult.status, 'preflight_denied');
    if (varResult.status === 'preflight_denied') {
      assert.strictEqual(varResult.reasonCode, 'unsafe_wordlist_path');
    }

    // 4. Forbidden /root directory attempt
    const rootResult = await adapter.discoverContent({
      targetUrl: 'https://example.com',
      wordlistPath: '/root/.ssh/authorized_keys',
      ...auth,
    });
    assert.strictEqual(rootResult.status, 'preflight_denied');
    if (rootResult.status === 'preflight_denied') {
      assert.strictEqual(rootResult.reasonCode, 'unsafe_wordlist_path');
    }

    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for unsafe wordlist paths');
    console.log('    -> Wordlist path traversal attempts safely rejected in preflight with zero process spawns');
  }

  // -------------------------------------------------------------------------
  // Assertion 3: Deep SSRF Redirect Containment
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 3: Deep SSRF Redirect Containment (Dropping endpoints redirecting to restricted space)');
  {
    const runner = new MockProcessRunner();
    runner.ffufOutput = {
      stdout: JSON.stringify({
        results: [
          {
            input: { FUZZ: 'safe-page' },
            status: 200,
            length: 800,
            url: 'https://example.com/safe-page',
          },
          {
            input: { FUZZ: 'cloud-meta' },
            status: 302,
            length: 0,
            redirectlocation: 'http://169.254.169.254/latest/meta-data',
            url: 'https://example.com/cloud-meta',
          },
          {
            input: { FUZZ: 'loopback-admin' },
            status: 301,
            length: 0,
            redirectlocation: 'http://127.0.0.1:8080/admin',
            url: 'https://example.com/loopback-admin',
          },
          {
            input: { FUZZ: 'private-net' },
            status: 302,
            length: 0,
            redirectlocation: 'http://10.0.0.1/status',
            url: 'https://example.com/private-net',
          },
        ],
      }),
      stderr: '',
      exitCode: 0,
      durationMs: 70,
      timedOut: false,
    };

    const adapter = new FfufAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverContent({
      targetUrl: 'https://example.com',
      wordlistPath: 'wordlists/common.txt',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 1, 'Only safe non-SSRF endpoint must remain');
      assert.strictEqual(result.observations[0].url, 'https://example.com/safe-page');
    }
    console.log('    -> All endpoints redirecting to metadata, loopback, or RFC-1918 successfully dropped');
  }

  // -------------------------------------------------------------------------
  // Assertion 4: Atomic Preflight Denial (Missing or Spoofed Authorization Brand)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 4: Atomic Preflight Denial (Missing or spoofed authorization brand)');
  {
    const runner = new MockProcessRunner();
    const adapter = new FfufAdapter(runner);
    const auth = setupAuthorizedContext();

    const spoofedDecision = {
      ...auth.verifiedAuthorizationDecision,
      decision: 'authorized' as const,
    };

    const result = await adapter.discoverContent({
      targetUrl: 'https://example.com',
      wordlistPath: 'wordlists/common.txt',
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
  console.log('[*] Assertion 5: Atomic Preflight Denial (Target domain outside scope boundaries)');
  {
    const runner = new MockProcessRunner();
    const adapter = new FfufAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverContent({
      targetUrl: 'https://unauthorized-site.com',
      wordlistPath: 'wordlists/common.txt',
      ...auth,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'target_out_of_scope');
    }
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for out-of-scope target');
    console.log('    -> Preflight safely denied out-of-scope target domain');
  }

  // -------------------------------------------------------------------------
  // Assertion 6: Atomic Preflight Denial (Missing Permissions)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 6: Atomic Preflight Denial (Grant lacks content discovery permissions)');
  {
    const runner = new MockProcessRunner();
    const adapter = new FfufAdapter(runner);
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

    const result = await adapter.discoverContent({
      targetUrl: 'https://example.com',
      wordlistPath: 'wordlists/common.txt',
      ...auth,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'missing_permission');
    }
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned on permission denial');
    console.log('    -> Preflight safely denied execution lacking content discovery permissions');
  }

  // -------------------------------------------------------------------------
  // Assertion 7: Target URL SSRF Pre-Check Denial
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 7: Target URL SSRF Pre-Check Denial (Loopback and cloud metadata targets)');
  {
    const runner = new MockProcessRunner();
    const adapter = new FfufAdapter(runner);
    const auth = setupAuthorizedContext();

    // Loopback
    const loopbackResult = await adapter.discoverContent({
      targetUrl: 'http://127.0.0.1:8080',
      wordlistPath: 'wordlists/common.txt',
      ...auth,
    });
    assert.strictEqual(loopbackResult.status, 'preflight_denied');
    if (loopbackResult.status === 'preflight_denied') {
      assert.strictEqual(loopbackResult.reasonCode, 'ssrf_target_blocked');
    }

    // Cloud metadata
    const metadataResult = await adapter.discoverContent({
      targetUrl: 'http://169.254.169.254/latest',
      wordlistPath: 'wordlists/common.txt',
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
    runner.ffufOutput = {
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 30,
      timedOut: false,
    };

    const adapter = new FfufAdapter(runner);
    const auth = setupAuthorizedContext();

    // Empty output test
    const emptyResult = await adapter.discoverContent({
      targetUrl: 'https://example.com',
      wordlistPath: 'wordlists/common.txt',
      ...auth,
    });

    assert.strictEqual(emptyResult.status, 'success');
    if (emptyResult.status === 'success') {
      assert.strictEqual(emptyResult.observations.length, 0);
      assert.deepStrictEqual(emptyResult.observations, []);
    }

    // Malformed JSON lines test
    runner.ffufOutput = {
      stdout: [
        'ffuf starting...',
        '{ invalid json [',
        '',
        JSON.stringify({
          url: 'https://example.com/resilient-page',
          status: 200,
          length: 512,
        }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 40,
      timedOut: false,
    };

    const resilientResult = await adapter.discoverContent({
      targetUrl: 'https://example.com',
      wordlistPath: 'wordlists/common.txt',
      ...auth,
    });

    assert.strictEqual(resilientResult.status, 'success');
    if (resilientResult.status === 'success') {
      assert.strictEqual(resilientResult.observations.length, 1);
      assert.strictEqual(resilientResult.observations[0].path, '/resilient-page');
    }

    console.log('    -> Clean zero observations on empty output and fail-closed malformed line resilience verified');
  }

  console.log('\n[✔] ALL MILESTONE 69 CONTENT DISCOVERY ADAPTER SMOKE ASSERTIONS PASSED SUCCESSFULLY.');
}

runMilestone69SmokeTests().catch((err) => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
