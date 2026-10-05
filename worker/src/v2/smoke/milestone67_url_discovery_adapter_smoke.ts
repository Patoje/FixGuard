import assert from 'node:assert';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { CompositeUrlDiscoveryAdapter } from '../recon/adapters/CompositeUrlDiscoveryAdapter.js';
import type { UrlDiscoveryRequest } from '../recon/adapters/UrlDiscoveryContracts.js';

class MockProcessRunner implements ProcessRunner {
  public calls: ExecutionRequest[] = [];
  public katanaOutput: RawExecutionOutput = {
    stdout: '',
    stderr: '',
    exitCode: 0,
    durationMs: 60,
    timedOut: false,
  };
  public gauOutput: RawExecutionOutput = {
    stdout: '',
    stderr: '',
    exitCode: 0,
    durationMs: 40,
    timedOut: false,
  };

  async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    this.calls.push(request);
    if (request.binary === 'katana') {
      return this.katanaOutput;
    }
    if (request.binary === 'gau') {
      return this.gauOutput;
    }
    return {
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 10,
      timedOut: false,
    };
  }
}

function createScopeGrant(overrides?: Partial<AuthorizedScopeGrant>): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_m67_001',
    scanId: 'scan_m67_001',
    issuedAt: '2026-09-13T12:00:00.000Z',
    expiresAt: '2026-09-14T12:00:00.000Z',
    subject: {
      targetKind: 'domain',
      domain: 'example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for exhaustive URL discovery in milestone 67',
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
      assessmentId: 'assess_m67_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_m67_001',
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
    assessmentId: 'assess_m67_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'decision_m67_001',
    actorId: 'pentest_lead_1',
  };

  return {
    verifiedAuthorizationDecision: establishResult.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
  };
}

async function runMilestone67SmokeTests() {
  console.log('=== [M67 SMOKE] Exhaustive URL & Endpoint Discovery Adapter (Katana + Gau) ===\n');

  // -------------------------------------------------------------------------
  // Assertion 1: Composite Merging (Modern JS + Archive Legacy)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 1: Composite merging of modern and legacy outputs with attribution');
  {
    const runner = new MockProcessRunner();
    runner.katanaOutput = {
      stdout: [
        JSON.stringify({ request: { endpoint: 'https://example.com/api/v2/users' } }),
        JSON.stringify({ endpoint: 'https://example.com/dashboard/settings' }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 80,
      timedOut: false,
    };
    runner.gauOutput = {
      stdout: [
        JSON.stringify({ url: 'https://example.com/old-login.php?ref=1' }),
        JSON.stringify({ url: 'https://example.com/api/v2/users' }), // overlap!
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 50,
      timedOut: false,
    };

    const adapter = new CompositeUrlDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverUrls({
      targetUrlOrDomain: 'example.com',
      ...auth,
      timeoutMs: 30_000,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.targetUrlOrDomain, 'example.com');
      assert.strictEqual(result.observations.length, 3, 'Should deduplicate overlap into 3 observations');

      const userApi = result.observations.find((o) => o.path === '/api/v2/users');
      assert(userApi, 'api/v2/users should be found');
      assert.deepStrictEqual(userApi.sources, ['archive_legacy', 'modern_crawler']);

      const dashboard = result.observations.find((o) => o.path === '/dashboard/settings');
      assert(dashboard, 'dashboard/settings should be found');
      assert.deepStrictEqual(dashboard.sources, ['modern_crawler']);

      const legacyLogin = result.observations.find((o) => o.path === '/old-login.php');
      assert(legacyLogin, 'old-login.php should be found');
      assert.deepStrictEqual(legacyLogin.sources, ['archive_legacy']);
      assert.strictEqual(legacyLogin.query, 'ref=1');

      // Verify anti-speculation explicit non-claims
      assert.strictEqual(result.explicitNonClaims.severity, 'info');
      assert.strictEqual(result.explicitNonClaims.createsRealFindings, false);
      assert.strictEqual(result.explicitNonClaims.confirmsVulnerabilities, false);
      assert.strictEqual(result.explicitNonClaims.makesSeverityClaims, false);

      // Verify command argument isolation
      assert.strictEqual(runner.calls.length, 2);
      const katanaCall = runner.calls.find((c) => c.binary === 'katana');
      assert(katanaCall, 'Katana must be called');
      assert.deepStrictEqual(katanaCall.args, ['-u', 'https://example.com', '-silent', '-jsonl', '-depth', '3', '-jc', '-jsl']);

      const gauCall = runner.calls.find((c) => c.binary === 'gau');
      assert(gauCall, 'Gau must be called');
      assert.deepStrictEqual(gauCall.args, ['--json', 'example.com']);
    }
    console.log('    -> Verified clean composite deduplication, source attribution, and non-claims');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: Atomic Preflight Denial (Missing or Unbranded Authorization)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 2: Atomic Preflight Denial (Missing or spoofed authorization brand)');
  {
    const runner = new MockProcessRunner();
    const adapter = new CompositeUrlDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const spoofedDecision = {
      ...auth.verifiedAuthorizationDecision,
      decision: 'authorized' as const,
    };

    const result = await adapter.discoverUrls({
      targetUrlOrDomain: 'example.com',
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
  // Assertion 3: Atomic Preflight Denial (Scope Boundary Denial)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 3: Atomic Preflight Denial (Target domain outside scope boundaries)');
  {
    const runner = new MockProcessRunner();
    const adapter = new CompositeUrlDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverUrls({
      targetUrlOrDomain: 'unauthorized-site.com',
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
  // Assertion 4: Atomic Preflight Denial (Missing Permissions)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 4: Atomic Preflight Denial (Grant lacks crawling/discovery permissions)');
  {
    const runner = new MockProcessRunner();
    const adapter = new CompositeUrlDiscoveryAdapter(runner);
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

    const result = await adapter.discoverUrls({
      targetUrlOrDomain: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'missing_permission');
    }
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned on permission denial');
    console.log('    -> Preflight safely denied execution lacking crawling permissions');
  }

  // -------------------------------------------------------------------------
  // Assertion 5: Strict Scope Egress Gate (Dropping Third-Party URLs in JS)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 5: Strict Scope Egress Gate (Dropping out-of-scope third-party URLs)');
  {
    const runner = new MockProcessRunner();
    runner.katanaOutput = {
      stdout: [
        'https://cdn.thirdparty.com/bundle.js',
        'https://google-analytics.com/collect?v=1',
        'https://api.github.com/repos/fixguard',
        'https://example.com/valid-local-api',
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 70,
      timedOut: false,
    };
    runner.gauOutput = {
      stdout: 'https://twitter.com/share?url=example.com\nhttps://example.com/about',
      stderr: '',
      exitCode: 0,
      durationMs: 40,
      timedOut: false,
    };

    const adapter = new CompositeUrlDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverUrls({
      targetUrlOrDomain: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 2, 'Only in-scope example.com URLs must remain');
      assert.strictEqual(result.observations[0].url, 'https://example.com/about');
      assert.strictEqual(result.observations[1].url, 'https://example.com/valid-local-api');
    }
    console.log('    -> All third-party CDNs, analytics, and social URLs safely discarded');
  }

  // -------------------------------------------------------------------------
  // Assertion 6: SSRF Containment (Dropping Loopback, RFC-1918, and Metadata)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 6: SSRF Containment (Filtering loopback, RFC-1918, and cloud metadata)');
  {
    const runner = new MockProcessRunner();
    runner.katanaOutput = {
      stdout: [
        'http://127.0.0.1:8080/admin',
        'http://169.254.169.254/latest/meta-data',
        'http://10.0.0.1/status',
        'https://example.com/safe-endpoint',
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 50,
      timedOut: false,
    };
    runner.gauOutput = {
      stdout: 'http://192.168.1.1/internal-dashboard',
      stderr: '',
      exitCode: 0,
      durationMs: 30,
      timedOut: false,
    };

    const adapter = new CompositeUrlDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverUrls({
      targetUrlOrDomain: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 1, 'Only public example.com URL should remain');
      assert.strictEqual(result.observations[0].url, 'https://example.com/safe-endpoint');
    }
    console.log('    -> All SSRF-restricted IP addresses and loopback URLs safely blocked');
  }

  // -------------------------------------------------------------------------
  // Assertion 7: Malformed Output Resilience (Fail-Closed)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 7: Malformed CLI Output Resilience (Corrupted lines fail closed safely)');
  {
    const runner = new MockProcessRunner();
    runner.katanaOutput = {
      stdout: [
        '',
        '{ broken json',
        '[1, 2, 3]',
        '"not a url"',
        '{"missing_endpoint": true}',
        '   ',
        'https://example.com/resilient-page',
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 40,
      timedOut: false,
    };
    runner.gauOutput = {
      stdout: 'not-a-valid-url\nhttp://\n',
      stderr: '',
      exitCode: 0,
      durationMs: 30,
      timedOut: false,
    };

    const adapter = new CompositeUrlDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverUrls({
      targetUrlOrDomain: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 1);
      assert.strictEqual(result.observations[0].url, 'https://example.com/resilient-page');
    }
    console.log('    -> Successfully parsed valid observation while discarding corrupted lines');
  }

  // -------------------------------------------------------------------------
  // Assertion 8: Empty Output Handling
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 8: Empty output handling (Zero discoveries, zero hallucinations)');
  {
    const runner = new MockProcessRunner();
    runner.katanaOutput = {
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 25,
      timedOut: false,
    };
    runner.gauOutput = {
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 20,
      timedOut: false,
    };

    const adapter = new CompositeUrlDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverUrls({
      targetUrlOrDomain: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 0);
      assert.deepStrictEqual(result.observations, []);
    }
    console.log('    -> Empty tool outputs cleanly yielded zero observations without synthetic records');
  }

  // -------------------------------------------------------------------------
  // Assertion 9: Gau timeout → loud degrade, katana partial success
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 9: Gau timedOut degrades loud; katana-only success');
  {
    const runner = new MockProcessRunner();
    runner.katanaOutput = {
      stdout: JSON.stringify({ url: 'https://example.com/live' }) + '\n',
      stderr: '',
      exitCode: 0,
      durationMs: 40,
      timedOut: false,
    };
    runner.gauOutput = {
      stdout: '',
      stderr: 'killed',
      exitCode: 124,
      durationMs: 45_000,
      timedOut: true,
    };

    const adapter = new CompositeUrlDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverUrls({
      targetUrlOrDomain: 'example.com',
      ...auth,
      timeoutMs: 600_000, // request higher; adapter still caps gau at 4m and katana at 5m
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.ok(
        (result.warnings ?? []).some((w) => /gau timed out/i.test(w)),
        'Must surface gau timeout warning'
      );
      assert.ok(
        result.observations.some((o) => o.path === '/live'),
        'Katana results retained after gau timeout'
      );
      const gauCall = runner.calls.find((c) => c.binary === 'gau');
      assert(gauCall, 'Gau must be called');
      assert.strictEqual(
        gauCall.timeoutMs,
        240_000,
        `Gau hard timeout must be 4m, got ${gauCall.timeoutMs}`
      );
      const katanaCall = runner.calls.find((c) => c.binary === 'katana');
      assert(katanaCall, 'Katana must be called');
      assert.strictEqual(
        katanaCall.timeoutMs,
        300_000,
        `Katana hard timeout must be 5m, got ${katanaCall.timeoutMs}`
      );
    }
    console.log('    -> Gau timeout degraded loudly without failing the whole discovery');
  }

  // -------------------------------------------------------------------------
  // Assertion 10: Non-zero exit copies truncated stderr onto the warning
  // -------------------------------------------------------------------------
  {
    const marker = 'katana-stderr-marker-fixed';
    const runner = new MockProcessRunner();
    runner.katanaOutput = {
      stdout: JSON.stringify({ url: 'https://example.com/from-gau-only-not-used' }) + '\n',
      stderr: marker,
      exitCode: 2,
      durationMs: 30,
      timedOut: false,
    };
    runner.gauOutput = {
      stdout: JSON.stringify({ url: 'https://example.com/archive-live' }) + '\n',
      stderr: '',
      exitCode: 0,
      durationMs: 20,
      timedOut: false,
    };
    const failed = await new CompositeUrlDiscoveryAdapter(runner).discoverUrls({
      targetUrlOrDomain: 'example.com',
      ...setupAuthorizedContext(),
    });
    assert.strictEqual(failed.status, 'success');
    if (failed.status === 'success') {
      const warning = (failed.warnings ?? []).join('\n');
      assert.ok(warning.includes(marker), 'Non-zero katana stderr must be on the warning');
      assert.ok(warning.includes('katana exit 2'), 'Exit code stays on the warning');
      assert.equal(warning.includes('from-gau-only-not-used'), false);
      assert.ok(failed.observations.some((obs) => obs.path === '/archive-live'));
    }

    const quiet = new MockProcessRunner();
    quiet.katanaOutput = {
      stdout: JSON.stringify({ url: 'https://example.com/quiet-page' }) + '\n',
      stderr: 'silent-stderr-marker',
      exitCode: 0,
      durationMs: 10,
      timedOut: false,
    };
    quiet.gauOutput = {
      stdout: '',
      stderr: 'gau-silent-stderr-marker',
      exitCode: 0,
      durationMs: 10,
      timedOut: false,
    };
    const clean = await new CompositeUrlDiscoveryAdapter(quiet).discoverUrls({
      targetUrlOrDomain: 'example.com',
      ...setupAuthorizedContext(),
    });
    assert.strictEqual(clean.status, 'success');
    if (clean.status === 'success') {
      const warning = (clean.warnings ?? []).join('\n');
      assert.equal(warning.includes('silent-stderr-marker'), false);
      assert.equal(warning.includes('gau-silent-stderr-marker'), false);
    }

    const skippedArchive = new MockProcessRunner();
    skippedArchive.katanaOutput = {
      stdout: JSON.stringify({ url: 'https://example.com/kept-live' }) + '\n',
      stderr: '',
      exitCode: 0,
      durationMs: 10,
      timedOut: false,
    };
    skippedArchive.gauOutput = {
      stdout: JSON.stringify({ url: 'https://example.com/archive-skipped' }) + '\n',
      stderr: 'gau-exit-124-stderr',
      exitCode: 124,
      durationMs: 15,
      timedOut: false,
    };
    const gauExit = await new CompositeUrlDiscoveryAdapter(skippedArchive).discoverUrls({
      targetUrlOrDomain: 'example.com',
      ...setupAuthorizedContext(),
    });
    assert.strictEqual(gauExit.status, 'success');
    if (gauExit.status === 'success') {
      assert.equal(
        gauExit.observations.some((obs) => obs.path === '/archive-skipped'),
        false,
        'Gau exit 124 must skip archive parsing'
      );
      assert.ok(gauExit.observations.some((obs) => obs.path === '/kept-live'));
      assert.ok((gauExit.warnings ?? []).some((warning) => warning.includes('gau-exit-124-stderr')));
    }
  }

  console.log('\n[✔] ALL MILESTONE 67 URL DISCOVERY ADAPTER SMOKE ASSERTIONS PASSED SUCCESSFULLY.');
}

runMilestone67SmokeTests().catch((err) => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
