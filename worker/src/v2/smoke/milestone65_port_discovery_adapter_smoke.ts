import assert from 'node:assert';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { NaabuPortDiscoveryAdapter } from '../recon/adapters/NaabuPortDiscoveryAdapter.js';
import type { PortDiscoveryRequest } from '../recon/adapters/PortDiscoveryContracts.js';

class MockProcessRunner implements ProcessRunner {
  public calls: ExecutionRequest[] = [];
  public nextOutput: RawExecutionOutput = {
    stdout: '',
    stderr: '',
    exitCode: 0,
    durationMs: 35,
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
    grantId: 'grant_m65_001',
    scanId: 'scan_m65_001',
    issuedAt: '2026-09-13T12:00:00.000Z',
    expiresAt: '2026-09-14T12:00:00.000Z',
    subject: {
      targetKind: 'domain',
      domain: 'example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for active port discovery in milestone 65',
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
      allowedHosts: ['example.com', '93.184.216.34'],
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
      assessmentId: 'assess_m65_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_m65_001',
      authorizedActor: { actorId: 'secops_lead_1', actorType: 'human' },
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
    assessmentId: 'assess_m65_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'decision_m65_001',
    actorId: 'secops_lead_1',
  };

  return {
    verifiedAuthorizationDecision: establishResult.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
  };
}

async function runMilestone65SmokeTests() {
  console.log('=== [M65 SMOKE] Port & Service Discovery Tool Adapter (Naabu) ===\n');

  // -------------------------------------------------------------------------
  // Assertion 1: Happy Path Discovery
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 1: Happy path port discovery with isolated argument arrays');
  {
    const runner = new MockProcessRunner();
    runner.nextOutput = {
      stdout: [
        JSON.stringify({ host: 'example.com', ip: '93.184.216.34', port: 80 }),
        JSON.stringify({ host: 'example.com', ip: '93.184.216.34', port: 443 }),
        JSON.stringify({ host: 'example.com', ip: '93.184.216.34', port: 8080 }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 140,
      timedOut: false,
    };

    const adapter = new NaabuPortDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverPorts({
      targetHostOrIp: 'example.com',
      ...auth,
      timeoutMs: 30_000,
    });

    assert.strictEqual(result.status, 'success', 'Expected success status');
    if (result.status === 'success') {
      assert.strictEqual(result.targetHostOrIp, 'example.com');
      assert.strictEqual(result.observations.length, 3, 'Should discover exactly 3 open ports');
      assert.strictEqual(result.observations[0].port, 80);
      assert.strictEqual(result.observations[0].protocol, 'tcp');
      assert.strictEqual(result.observations[0].state, 'open');
      assert.strictEqual(result.observations[1].port, 443);
      assert.strictEqual(result.observations[2].port, 8080);

      // Verify anti-speculation explicit non-claims
      assert.strictEqual(result.explicitNonClaims.severity, 'info');
      assert.strictEqual(result.explicitNonClaims.createsRealFindings, false);
      assert.strictEqual(result.explicitNonClaims.confirmsVulnerabilities, false);
      assert.strictEqual(result.explicitNonClaims.makesSeverityClaims, false);

      // Verify command isolation
      assert.strictEqual(runner.calls.length, 1);
      assert.strictEqual(runner.calls[0].binary, 'naabu');
      assert.deepStrictEqual(runner.calls[0].args, ['-host', 'example.com', '-json', '-silent', '-rate', '1000']);
      assert.strictEqual(runner.calls[0].timeoutMs, 30_000);
    }
    console.log('    -> Verified clean port discovery, argument isolation, and factual non-claims');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: Atomic Preflight Denial (Missing or Unbranded Authorization)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 2: Atomic Preflight Denial (Missing or spoofed authorization brand)');
  {
    const runner = new MockProcessRunner();
    const adapter = new NaabuPortDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const spoofedDecision = {
      ...auth.verifiedAuthorizationDecision,
      decision: 'authorized' as const,
    };

    const result = await adapter.discoverPorts({
      targetHostOrIp: 'example.com',
      verifiedAuthorizationDecision: spoofedDecision,
      authorizedScopeGrant: auth.authorizedScopeGrant,
      lineage: auth.lineage,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'authorization_unconfirmed');
    }
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for unbranded decision');
    console.log('    -> Preflight safely denied unbranded decision with zero process invocations');
  }

  // -------------------------------------------------------------------------
  // Assertion 3: Atomic Preflight Denial (Target Out of Scope)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 3: Atomic Preflight Denial (Target host/IP outside scope boundaries)');
  {
    const runner = new MockProcessRunner();
    const adapter = new NaabuPortDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverPorts({
      targetHostOrIp: 'unauthorized-domain.com',
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
  console.log('[*] Assertion 4: Atomic Preflight Denial (Grant lacks port scan / active recon permissions)');
  {
    const runner = new MockProcessRunner();
    const adapter = new NaabuPortDiscoveryAdapter(runner);
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

    const result = await adapter.discoverPorts({
      targetHostOrIp: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'missing_permission');
    }
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned on permission denial');
    console.log('    -> Preflight safely denied execution lacking port scan permissions');
  }

  // -------------------------------------------------------------------------
  // Assertion 5: SSRF & Loopback Containment (Egress Gate M30)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 5: SSRF & Loopback Containment (Filtering RFC-1918, loopback, and metadata)');
  {
    const runner = new MockProcessRunner();
    runner.nextOutput = {
      stdout: [
        JSON.stringify({ host: 'example.com', ip: '127.0.0.1', port: 22 }),
        JSON.stringify({ host: 'example.com', ip: '10.0.0.1', port: 3306 }),
        JSON.stringify({ host: 'example.com', ip: '169.254.169.254', port: 80 }),
        JSON.stringify({ host: 'example.com', ip: '192.168.1.1', port: 5432 }),
        JSON.stringify({ host: 'example.com', ip: '93.184.216.34', port: 443 }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 90,
      timedOut: false,
    };

    const adapter = new NaabuPortDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverPorts({
      targetHostOrIp: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 1, 'Only public service port should be kept');
      assert.strictEqual(result.observations[0].port, 443);
      assert.strictEqual(result.observations[0].ip, '93.184.216.34');
    }
    console.log('    -> All RFC-1918, loopback, and cloud metadata ports dropped by egress gate');
  }

  // -------------------------------------------------------------------------
  // Assertion 6: Malformed CLI Output Resilience (Fail-Closed)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 6: Malformed CLI Output Resilience (Corrupted lines fail closed safely)');
  {
    const runner = new MockProcessRunner();
    runner.nextOutput = {
      stdout: [
        '',
        '{ broken json string',
        '[1, 2, 3]',
        '"plain-string"',
        '{"missing_port": true}',
        '{"host": "example.com", "port": 999999}',
        '{"host": "example.com", "port": -5}',
        '[INF] Found 1 port in 0.5s',
        JSON.stringify({ host: 'example.com', ip: '93.184.216.34', port: 80 }),
        '   ',
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 70,
      timedOut: false,
    };

    const adapter = new NaabuPortDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverPorts({
      targetHostOrIp: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 1);
      assert.strictEqual(result.observations[0].port, 80);
    }
    console.log('    -> Successfully parsed valid port entry while safely ignoring corrupted lines');
  }

  // -------------------------------------------------------------------------
  // Assertion 7: Empty Output Discovery
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 7: Empty output handling (Zero discoveries, zero hallucinations)');
  {
    const runner = new MockProcessRunner();
    runner.nextOutput = {
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 30,
      timedOut: false,
    };

    const adapter = new NaabuPortDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverPorts({
      targetHostOrIp: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 0);
      assert.deepStrictEqual(result.observations, []);
    }
    console.log('    -> Empty tool output cleanly yielded zero observations without synthetic records');
  }

  // -------------------------------------------------------------------------
  // Assertion 8: Port Selection Parameter (-p)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 8: Target port parameter passed safely as argument array');
  {
    const runner = new MockProcessRunner();
    runner.nextOutput = {
      stdout: JSON.stringify({ host: 'example.com', ip: '93.184.216.34', port: 8443 }),
      stderr: '',
      exitCode: 0,
      durationMs: 50,
      timedOut: false,
    };

    const adapter = new NaabuPortDiscoveryAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.discoverPorts({
      targetHostOrIp: 'example.com',
      targetPorts: [80, 443, 8443],
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    assert.strictEqual(runner.calls.length, 1);
    assert.deepStrictEqual(runner.calls[0].args, [
      '-host', 'example.com',
      '-json',
      '-silent',
      '-rate', '1000',
      '-p', '80,443,8443'
    ]);
    console.log('    -> Target ports correctly supplied via isolated array arguments');
  }

  console.log('\n[✔] ALL MILESTONE 65 PORT DISCOVERY ADAPTER SMOKE ASSERTIONS PASSED SUCCESSFULLY.');
}

runMilestone65SmokeTests().catch((err) => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
