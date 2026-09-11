import assert from 'node:assert';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { SubfinderAdapter } from '../recon/adapters/SubfinderAdapter.js';
import type { SubdomainDiscoveryRequest } from '../recon/adapters/SubdomainDiscoveryContracts.js';

class MockProcessRunner implements ProcessRunner {
  public calls: ExecutionRequest[] = [];
  public nextOutput: RawExecutionOutput = {
    stdout: '',
    stderr: '',
    exitCode: 0,
    durationMs: 42,
    timedOut: false,
  };

  async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    this.calls.push(request);
    return this.nextOutput;
  }
}

function createScopeGrant(overrides?: Partial<AuthorizedScopeGrant>): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_m64_001',
    scanId: 'scan_m64_001',
    issuedAt: '2026-09-11T12:00:00.000Z',
    expiresAt: '2026-09-12T12:00:00.000Z',
    subject: {
      targetKind: 'domain',
      domain: 'example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for security assessment in milestone 64',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: false,
      endpointDiscovery: true,
      activeCrawling: false,
      authenticatedTesting: false,
      lightValidation: false,
      activeValidation: false,
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
      assessmentId: 'assess_m64_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_m64_001',
      authorizedActor: { actorId: 'secops_analyst_1', actorType: 'human' },
      decision: 'authorized',
      decidedAt: '2026-09-11T12:00:00.000Z',
      scopeGrant,
    },
    '2026-09-11T12:00:00.000Z'
  );

  if (establishResult.status !== 'established') {
    throw new Error(`Failed to establish verified decision: ${establishResult.safeMessage}`);
  }

  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'assess_m64_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'decision_m64_001',
    actorId: 'secops_analyst_1',
  };

  return {
    verifiedAuthorizationDecision: establishResult.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
  };
}

async function runMilestone64SmokeTests() {
  console.log('=== [M64 SMOKE] Subdomain Discovery Tool Adapter (Subfinder) ===\n');

  // -------------------------------------------------------------------------
  // Assertion 1: Happy Path Discovery
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 1: Happy path discovery with isolated execution arguments');
  {
    const runner = new MockProcessRunner();
    runner.nextOutput = {
      stdout: [
        JSON.stringify({ host: 'api.example.com', ip: '93.184.216.34', sources: ['virustotal', 'censys'] }),
        JSON.stringify({ host: 'dev.example.com', ip: '93.184.216.35', sources: ['shodan'] }),
        JSON.stringify({ host: 'mail.example.com', sources: ['alienvault'] }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 120,
      timedOut: false,
    };

    const adapter = new SubfinderAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverSubdomains({
      targetDomain: 'example.com',
      ...auth,
      timeoutMs: 30_000,
    });

    assert.strictEqual(result.status, 'success', 'Expected success status');
    if (result.status === 'success') {
      assert.strictEqual(result.targetDomain, 'example.com');
      assert.strictEqual(result.observations.length, 3, 'Should discover exactly 3 subdomains');
      assert.strictEqual(result.observations[0].subdomain, 'api.example.com');
      assert.deepStrictEqual(result.observations[0].ipAddresses, ['93.184.216.34']);
      assert.deepStrictEqual(result.observations[0].sources, ['censys', 'virustotal']);
      assert.strictEqual(result.observations[1].subdomain, 'dev.example.com');
      assert.strictEqual(result.observations[2].subdomain, 'mail.example.com');

      // Verify anti-speculation explicit non-claims
      assert.strictEqual(result.explicitNonClaims.severity, 'info');
      assert.strictEqual(result.explicitNonClaims.createsRealFindings, false);
      assert.strictEqual(result.explicitNonClaims.confirmsVulnerabilities, false);
      assert.strictEqual(result.explicitNonClaims.makesSeverityClaims, false);

      // Verify command isolation
      assert.strictEqual(runner.calls.length, 1);
      assert.strictEqual(runner.calls[0].binary, 'subfinder');
      assert.deepStrictEqual(runner.calls[0].args, ['-d', 'example.com', '-silent', '-json']);
      assert.strictEqual(runner.calls[0].timeoutMs, 30_000);
    }
    console.log('    -> Verified clean discovery, arguments isolation, and explicit non-claims');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: Atomic Preflight Denial (Missing or Unbranded Authorization)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 2: Atomic Preflight Denial (Missing or spoofed authorization brand)');
  {
    const runner = new MockProcessRunner();
    const adapter = new SubfinderAdapter(runner);
    const auth = setupAuthorizedContext();

    // Fabricate an unbranded decision object
    const spoofedDecision = {
      ...auth.verifiedAuthorizationDecision,
      decision: 'authorized' as const,
    };

    const result = await adapter.discoverSubdomains({
      targetDomain: 'example.com',
      verifiedAuthorizationDecision: spoofedDecision,
      authorizedScopeGrant: auth.authorizedScopeGrant,
      lineage: auth.lineage,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'authorization_unconfirmed');
    }
    // Zero child processes spawned
    assert.strictEqual(runner.calls.length, 0, 'Must spawn zero child processes on preflight denial');
    console.log('    -> Preflight safely denied unbranded decision with zero process invocations');
  }

  // -------------------------------------------------------------------------
  // Assertion 3: Atomic Preflight Denial (Target Out of Scope)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 3: Atomic Preflight Denial (Target domain outside scope boundaries)');
  {
    const runner = new MockProcessRunner();
    const adapter = new SubfinderAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverSubdomains({
      targetDomain: 'malicious-target.com',
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
  // Assertion 4: Atomic Preflight Denial (Missing Scope Permissions)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 4: Atomic Preflight Denial (Grant lacks endpointDiscovery / passiveRecon)');
  {
    const runner = new MockProcessRunner();
    const adapter = new SubfinderAdapter(runner);
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

    const result = await adapter.discoverSubdomains({
      targetDomain: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'missing_permission');
    }
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for permission denial');
    console.log('    -> Preflight safely denied execution lacking recon permissions');
  }

  // -------------------------------------------------------------------------
  // Assertion 5: SSRF / Private IP Filtering (Egress Gate M30)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 5: SSRF & Scope Gate (Filtering RFC 1918, loopback, and cloud metadata)');
  {
    const runner = new MockProcessRunner();
    runner.nextOutput = {
      stdout: [
        JSON.stringify({ host: 'internal-corp.example.com', ip: '192.168.1.100', sources: ['alienvault'] }),
        JSON.stringify({ host: 'metadata.example.com', ip: '169.254.169.254', sources: ['censys'] }),
        JSON.stringify({ host: 'loopback.example.com', ip: '127.0.0.1', sources: ['virustotal'] }),
        JSON.stringify({ host: 'ten-net.example.com', ip: '10.0.5.2', sources: ['dnsdumpster'] }),
        JSON.stringify({ host: 'public-service.example.com', ip: '93.184.216.34', sources: ['certspotter'] }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 95,
      timedOut: false,
    };

    const adapter = new SubfinderAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverSubdomains({
      targetDomain: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 1, 'Only public service should remain');
      assert.strictEqual(result.observations[0].subdomain, 'public-service.example.com');
      assert.deepStrictEqual(result.observations[0].ipAddresses, ['93.184.216.34']);
    }
    console.log('    -> All RFC-1918, loopback, and cloud metadata records dropped by egress gate');
  }

  // -------------------------------------------------------------------------
  // Assertion 6: Out-of-Scope Hostname Filtering
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 6: Out-of-Scope Hostname Filtering (Dropping third-party/sibling domains)');
  {
    const runner = new MockProcessRunner();
    runner.nextOutput = {
      stdout: [
        JSON.stringify({ host: 'valid.example.com', ip: '93.184.216.34' }),
        JSON.stringify({ host: 'phishing-example.com', ip: '93.184.216.34' }),
        JSON.stringify({ host: 'evil-attacker.org', ip: '93.184.216.34' }),
        JSON.stringify({ host: 'sub.not-example.com', ip: '93.184.216.34' }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 80,
      timedOut: false,
    };

    const adapter = new SubfinderAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverSubdomains({
      targetDomain: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 1);
      assert.strictEqual(result.observations[0].subdomain, 'valid.example.com');
    }
    console.log('    -> Out-of-scope and sibling hostnames safely discarded');
  }

  // -------------------------------------------------------------------------
  // Assertion 7: Malformed CLI Output Resilience (Fail-Closed Robustness)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 7: Malformed CLI Output Resilience (Corrupted lines fail closed safely)');
  {
    const runner = new MockProcessRunner();
    runner.nextOutput = {
      stdout: [
        '',
        '{ not even json',
        '[1, 2, 3]',
        '"just-a-plain-string"',
        '{"missing_host": true}',
        '{"host": ""}',
        '{"host": "invalid..host.."}',
        '[INF] Found 1 subdomains for example.com in 1 seconds',
        JSON.stringify({ host: 'resilient.example.com', ip: '93.184.216.34', sources: ['crtsh'] }),
        '   ',
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 65,
      timedOut: false,
    };

    const adapter = new SubfinderAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverSubdomains({
      targetDomain: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 1);
      assert.strictEqual(result.observations[0].subdomain, 'resilient.example.com');
    }
    console.log('    -> Successfully parsed valid entries while safely ignoring corrupted lines');
  }

  // -------------------------------------------------------------------------
  // Assertion 8: Empty Output Discovery
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 8: Empty output handling (Zero discoveries, zero hallucinations)');
  {
    const runner = new MockProcessRunner();
    runner.nextOutput = {
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 45,
      timedOut: false,
    };

    const adapter = new SubfinderAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverSubdomains({
      targetDomain: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 0);
      assert.deepStrictEqual(result.observations, []);
    }
    console.log('    -> Empty tool output cleanly yielded zero observations without synthetic records');
  }

  console.log('\n[✔] ALL MILESTONE 64 SUBFINDER ADAPTER SMOKE ASSERTIONS PASSED SUCCESSFULLY.');
}

runMilestone64SmokeTests().catch((err) => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
