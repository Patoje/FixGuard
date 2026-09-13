import assert from 'node:assert';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { DnsxAdapter } from '../recon/adapters/DnsxAdapter.js';

class MockProcessRunner implements ProcessRunner {
  public calls: ExecutionRequest[] = [];
  public dnsxOutput: RawExecutionOutput = {
    stdout: '',
    stderr: '',
    exitCode: 0,
    durationMs: 65,
    timedOut: false,
  };

  async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    this.calls.push(request);
    return this.dnsxOutput;
  }
}

function createScopeGrant(overrides?: Partial<AuthorizedScopeGrant>): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_m70_001',
    scanId: 'scan_m70_001',
    issuedAt: '2026-09-13T12:00:00.000Z',
    expiresAt: '2026-09-14T12:00:00.000Z',
    subject: {
      targetKind: 'domain',
      domain: 'example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for DNS resolution in milestone 70',
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
      assessmentId: 'assess_m70_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_m70_001',
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
    assessmentId: 'assess_m70_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'decision_m70_001',
    actorId: 'pentest_lead_1',
  };

  return {
    verifiedAuthorizationDecision: establishResult.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
  };
}

async function runMilestone70SmokeTests() {
  console.log('=== [M70 SMOKE] Exhaustive DNS & Zone Enumeration Tool Adapter (Dnsx) ===\n');

  // -------------------------------------------------------------------------
  // Assertion 1: Happy Path Discovery & Explicit Non-Claims
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 1: Happy path DNS resolution with factual non-claims');
  {
    const runner = new MockProcessRunner();
    runner.dnsxOutput = {
      stdout: [
        JSON.stringify({
          host: 'example.com',
          a: ['93.184.216.34'],
          txt: ['v=spf1 -all'],
          mx: ['mail.example.com'],
        }),
        JSON.stringify({
          host: 'cdn.example.com',
          cname: ['edge.example.com'],
        }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 70,
      timedOut: false,
    };

    const adapter = new DnsxAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.resolveDns({
      targetDomain: 'example.com',
      wildcardFiltering: true,
      resolvers: ['1.1.1.1', '8.8.8.8'],
      ...auth,
      timeoutMs: 30_000,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.targetDomain, 'example.com');
      assert.strictEqual(result.observations.length, 4);

      const aObs = result.observations.find((o) => o.recordType === 'A');
      assert(aObs, 'A record observation must be present');
      assert.deepStrictEqual(aObs.values, ['93.184.216.34']);

      const txtObs = result.observations.find((o) => o.recordType === 'TXT');
      assert(txtObs, 'TXT record observation must be present');
      assert.deepStrictEqual(txtObs.values, ['v=spf1 -all']);

      const mxObs = result.observations.find((o) => o.recordType === 'MX');
      assert(mxObs, 'MX record observation must be present');
      assert.deepStrictEqual(mxObs.values, ['mail.example.com']);

      const cnameObs = result.observations.find((o) => o.recordType === 'CNAME');
      assert(cnameObs, 'CNAME record observation must be present');
      assert.strictEqual(cnameObs.domain, 'cdn.example.com');
      assert.deepStrictEqual(cnameObs.values, ['edge.example.com']);

      // Verify anti-speculation explicit non-claims
      assert.strictEqual(result.explicitNonClaims.severity, 'info');
      assert.strictEqual(result.explicitNonClaims.createsRealFindings, false);
      assert.strictEqual(result.explicitNonClaims.confirmsVulnerabilities, false);
      assert.strictEqual(result.explicitNonClaims.makesSeverityClaims, false);

      // Verify process runner execution arguments
      assert.strictEqual(runner.calls.length, 1);
      assert.strictEqual(runner.calls[0].binary, 'dnsx');
      assert.deepStrictEqual(runner.calls[0].args, [
        '-d',
        'example.com',
        '-json',
        '-a',
        '-aaaa',
        '-cname',
        '-txt',
        '-mx',
        '-wd',
        'example.com',
        '-r',
        '1.1.1.1,8.8.8.8',
      ]);
    }
    console.log('    -> Happy path verified: observations mapped cleanly, non-claims intact');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: Wildcard Filtering & Resolver Isolation Arguments
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 2: Wildcard filtering (-wd) and resolver containment (-r) argument isolation');
  {
    const runner = new MockProcessRunner();
    runner.dnsxOutput = {
      stdout: JSON.stringify({ host: 'example.com', a: ['93.184.216.34'] }),
      stderr: '',
      exitCode: 0,
      durationMs: 40,
      timedOut: false,
    };

    const adapter = new DnsxAdapter(runner);
    const auth = setupAuthorizedContext();

    await adapter.resolveDns({
      targetDomain: 'example.com',
      wildcardFiltering: true,
      resolvers: ['9.9.9.9'],
      ...auth,
    });

    assert.strictEqual(runner.calls.length, 1);
    const callArgs = runner.calls[0].args;
    const wdIndex = callArgs.indexOf('-wd');
    assert(wdIndex !== -1, '-wd argument must be present');
    assert.strictEqual(callArgs[wdIndex + 1], 'example.com');

    const rIndex = callArgs.indexOf('-r');
    assert(rIndex !== -1, '-r argument must be present');
    assert.strictEqual(callArgs[rIndex + 1], '9.9.9.9');

    console.log('    -> Wildcard filtering and safe public resolvers verified in CLI arguments');
  }

  // -------------------------------------------------------------------------
  // Assertion 3: Deep SSRF Egress Drop (Dropping RFC-1918, Loopback, and Metadata)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 3: Deep SSRF Egress Drop (Filtering private IP, loopback, and metadata resolutions)');
  {
    const runner = new MockProcessRunner();
    runner.dnsxOutput = {
      stdout: [
        JSON.stringify({ host: 'safe.example.com', a: ['93.184.216.34'] }),
        JSON.stringify({ host: 'internal.example.com', a: ['10.0.0.5'] }),
        JSON.stringify({ host: 'loopback.example.com', a: ['127.0.0.1'] }),
        JSON.stringify({ host: 'meta.example.com', a: ['169.254.169.254'] }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 50,
      timedOut: false,
    };

    const adapter = new DnsxAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.resolveDns({
      targetDomain: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 1, 'Only safe public IP resolution must remain');
      assert.strictEqual(result.observations[0].domain, 'safe.example.com');
      assert.deepStrictEqual(result.observations[0].values, ['93.184.216.34']);
    }
    console.log('    -> All private RFC-1918, loopback, and metadata DNS resolutions safely dropped');
  }

  // -------------------------------------------------------------------------
  // Assertion 4: Atomic Preflight Denial (Missing or Spoofed Authorization Brand)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 4: Atomic Preflight Denial (Missing or spoofed authorization brand)');
  {
    const runner = new MockProcessRunner();
    const adapter = new DnsxAdapter(runner);
    const auth = setupAuthorizedContext();

    const spoofedDecision = {
      ...auth.verifiedAuthorizationDecision,
      decision: 'authorized' as const,
    };

    const result = await adapter.resolveDns({
      targetDomain: 'example.com',
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
    const adapter = new DnsxAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.resolveDns({
      targetDomain: 'unauthorized-site.com',
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
  console.log('[*] Assertion 6: Atomic Preflight Denial (Grant lacks DNS resolution permissions)');
  {
    const runner = new MockProcessRunner();
    const adapter = new DnsxAdapter(runner);
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

    const result = await adapter.resolveDns({
      targetDomain: 'example.com',
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
  // Assertion 7: Target Domain SSRF Pre-Check Denial
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 7: Target Domain SSRF Pre-Check Denial (Loopback / invalid target domain)');
  {
    const runner = new MockProcessRunner();
    const adapter = new DnsxAdapter(runner);
    const auth = setupAuthorizedContext();

    // Invalid format
    const invalidFormatResult = await adapter.resolveDns({
      targetDomain: 'not_a_valid_fqdn!',
      ...auth,
    });
    assert.strictEqual(invalidFormatResult.status, 'preflight_denied');
    if (invalidFormatResult.status === 'preflight_denied') {
      assert.strictEqual(invalidFormatResult.reasonCode, 'invalid_target_domain');
    }

    // SSRF Loopback target domain
    const loopbackResult = await adapter.resolveDns({
      targetDomain: '127.0.0.1',
      ...auth,
    });
    assert.strictEqual(loopbackResult.status, 'preflight_denied');
    // Will be caught by FQDN regex or SSRF check
    assert(
      loopbackResult.status === 'preflight_denied' &&
        (loopbackResult.reasonCode === 'invalid_target_domain' ||
          loopbackResult.reasonCode === 'ssrf_target_blocked')
    );

    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for invalid/SSRF target domains');
    console.log('    -> Malformed and SSRF target domains safely blocked in preflight');
  }

  // -------------------------------------------------------------------------
  // Assertion 8: Empty & Malformed Output Resilience
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 8: Empty & Malformed Output Resilience');
  {
    const runner = new MockProcessRunner();
    runner.dnsxOutput = {
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 30,
      timedOut: false,
    };

    const adapter = new DnsxAdapter(runner);
    const auth = setupAuthorizedContext();

    // Empty output test
    const emptyResult = await adapter.resolveDns({
      targetDomain: 'example.com',
      ...auth,
    });

    assert.strictEqual(emptyResult.status, 'success');
    if (emptyResult.status === 'success') {
      assert.strictEqual(emptyResult.observations.length, 0);
      assert.deepStrictEqual(emptyResult.observations, []);
    }

    // Malformed JSON output test
    runner.dnsxOutput = {
      stdout: [
        'dnsx header line',
        '{ invalid json [',
        '',
        JSON.stringify({
          host: 'example.com',
          a: ['93.184.216.34'],
        }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 40,
      timedOut: false,
    };

    const resilientResult = await adapter.resolveDns({
      targetDomain: 'example.com',
      ...auth,
    });

    assert.strictEqual(resilientResult.status, 'success');
    if (resilientResult.status === 'success') {
      assert.strictEqual(resilientResult.observations.length, 1);
      assert.strictEqual(resilientResult.observations[0].recordType, 'A');
      assert.deepStrictEqual(resilientResult.observations[0].values, ['93.184.216.34']);
    }

    console.log('    -> Clean zero observations on empty output and fail-closed malformed line resilience verified');
  }

  console.log('\n[✔] ALL MILESTONE 70 DNS RESOLUTION ADAPTER SMOKE ASSERTIONS PASSED SUCCESSFULLY.');
}

runMilestone70SmokeTests().catch((err) => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
