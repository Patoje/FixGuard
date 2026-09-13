import assert from 'node:assert';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { HttpxInspectionAdapter } from '../recon/adapters/HttpxInspectionAdapter.js';
import type { WebInspectionRequest } from '../recon/adapters/WebInspectionContracts.js';

class MockProcessRunner implements ProcessRunner {
  public calls: ExecutionRequest[] = [];
  public nextOutput: RawExecutionOutput = {
    stdout: '',
    stderr: '',
    exitCode: 0,
    durationMs: 40,
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
    grantId: 'grant_m66_001',
    scanId: 'scan_m66_001',
    issuedAt: '2026-09-13T12:00:00.000Z',
    expiresAt: '2026-09-14T12:00:00.000Z',
    subject: {
      targetKind: 'domain',
      domain: 'example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for web inspection in milestone 66',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
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
      assessmentId: 'assess_m66_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_m66_001',
      authorizedActor: { actorId: 'appsec_analyst_1', actorType: 'human' },
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
    assessmentId: 'assess_m66_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'decision_m66_001',
    actorId: 'appsec_analyst_1',
  };

  return {
    verifiedAuthorizationDecision: establishResult.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
  };
}

async function runMilestone66SmokeTests() {
  console.log('=== [M66 SMOKE] Web Technology & Service Inspection Adapter (Httpx) ===\n');

  // -------------------------------------------------------------------------
  // Assertion 1: Happy Path Discovery
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 1: Happy path web inspection with isolated argument arrays');
  {
    const runner = new MockProcessRunner();
    runner.nextOutput = {
      stdout: JSON.stringify({
        url: 'https://example.com',
        status_code: 200,
        title: 'Example Domain',
        webserver: 'nginx/1.20',
        tech: ['Nginx', 'Cloudflare', 'React'],
        ip: '93.184.216.34',
        method: 'GET',
      }),
      stderr: '',
      exitCode: 0,
      durationMs: 150,
      timedOut: false,
    };

    const adapter = new HttpxInspectionAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.inspectWeb({
      targetUrl: 'https://example.com',
      ...auth,
      timeoutMs: 30_000,
    });

    assert.strictEqual(result.status, 'success', 'Expected success status');
    if (result.status === 'success') {
      assert.strictEqual(result.targetUrl, 'https://example.com');
      assert.strictEqual(result.observations.length, 1, 'Should parse exactly 1 observation');
      const obs = result.observations[0];
      assert.strictEqual(obs.url, 'https://example.com');
      assert.strictEqual(obs.statusCode, 200);
      assert.strictEqual(obs.title, 'Example Domain');
      assert.strictEqual(obs.webServer, 'nginx/1.20');
      assert.deepStrictEqual(obs.technologies, ['Cloudflare', 'Nginx', 'React']);
      assert.strictEqual(obs.resolvedIp, '93.184.216.34');

      // Verify anti-speculation explicit non-claims
      assert.strictEqual(result.explicitNonClaims.severity, 'info');
      assert.strictEqual(result.explicitNonClaims.createsRealFindings, false);
      assert.strictEqual(result.explicitNonClaims.confirmsVulnerabilities, false);
      assert.strictEqual(result.explicitNonClaims.makesSeverityClaims, false);

      // Verify command isolation
      assert.strictEqual(runner.calls.length, 1);
      assert.strictEqual(runner.calls[0].binary, 'httpx');
      assert.deepStrictEqual(runner.calls[0].args, [
        '-u', 'https://example.com',
        '-json',
        '-silent',
        '-title',
        '-tech-detect',
        '-status-code',
        '-follow-redirects',
      ]);
      assert.strictEqual(runner.calls[0].timeoutMs, 30_000);
    }
    console.log('    -> Verified clean web inspection, arguments isolation, and factual non-claims');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: Atomic Preflight Denial (Missing or Unbranded Authorization)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 2: Atomic Preflight Denial (Missing or spoofed authorization brand)');
  {
    const runner = new MockProcessRunner();
    const adapter = new HttpxInspectionAdapter(runner);
    const auth = setupAuthorizedContext();

    const spoofedDecision = {
      ...auth.verifiedAuthorizationDecision,
      decision: 'authorized' as const,
    };

    const result = await adapter.inspectWeb({
      targetUrl: 'https://example.com',
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
  console.log('[*] Assertion 3: Atomic Preflight Denial (Target URL host outside scope boundaries)');
  {
    const runner = new MockProcessRunner();
    const adapter = new HttpxInspectionAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.inspectWeb({
      targetUrl: 'https://evil-unauthorized.com/test',
      ...auth,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'target_out_of_scope');
    }
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for out-of-scope host');
    console.log('    -> Preflight safely denied out-of-scope target host');
  }

  // -------------------------------------------------------------------------
  // Assertion 4: Atomic Preflight Denial (Missing Permissions)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 4: Atomic Preflight Denial (Grant lacks web inspection / recon permissions)');
  {
    const runner = new MockProcessRunner();
    const adapter = new HttpxInspectionAdapter(runner);
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

    const result = await adapter.inspectWeb({
      targetUrl: 'https://example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'missing_permission');
    }
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned on permission denial');
    console.log('    -> Preflight safely denied execution lacking inspection permissions');
  }

  // -------------------------------------------------------------------------
  // Assertion 5: Deep SSRF Redirect Containment
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 5: Deep SSRF Redirect Containment (Filtering loopback, RFC-1918, and metadata redirects)');
  {
    const runner = new MockProcessRunner();
    runner.nextOutput = {
      stdout: [
        // Redirect to cloud metadata
        JSON.stringify({
          url: 'http://169.254.169.254/latest/meta-data',
          ip: '169.254.169.254',
          status_code: 200,
          title: 'Instance Metadata',
        }),
        // Redirect to loopback
        JSON.stringify({
          url: 'http://localhost:8080/internal-status',
          ip: '127.0.0.1',
          status_code: 200,
          title: 'Admin Panel',
        }),
        // Redirect to RFC-1918
        JSON.stringify({
          url: 'http://corp-router.local',
          ip: '10.0.0.1',
          status_code: 200,
        }),
        // Legitimate public destination
        JSON.stringify({
          url: 'https://example.com/welcome',
          ip: '93.184.216.34',
          status_code: 200,
          title: 'Welcome to Example',
          tech: ['Vue.js', 'Nginx'],
        }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 95,
      timedOut: false,
    };

    const adapter = new HttpxInspectionAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.inspectWeb({
      targetUrl: 'https://example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 1, 'Only legitimate public URL should be preserved');
      assert.strictEqual(result.observations[0].url, 'https://example.com/welcome');
      assert.strictEqual(result.observations[0].resolvedIp, '93.184.216.34');
      assert.deepStrictEqual(result.observations[0].technologies, ['Nginx', 'Vue.js']);
    }
    console.log('    -> All redirect hops to 169.254.169.254, 127.0.0.1, and 10.0.0.1 safely dropped');
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
        '{"missing_url": true}',
        '{"url": "not a valid url"}',
        '[INF] Starting HTTPX inspection engine',
        JSON.stringify({
          url: 'https://example.com/valid',
          status_code: 200,
          title: 'Valid Page',
          ip: '93.184.216.34',
        }),
        '   ',
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 75,
      timedOut: false,
    };

    const adapter = new HttpxInspectionAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.inspectWeb({
      targetUrl: 'https://example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 1);
      assert.strictEqual(result.observations[0].url, 'https://example.com/valid');
    }
    console.log('    -> Successfully parsed valid observation while discarding corrupted lines');
  }

  // -------------------------------------------------------------------------
  // Assertion 7: Empty Output Handling
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 7: Empty output handling (Zero discoveries, zero hallucinations)');
  {
    const runner = new MockProcessRunner();
    runner.nextOutput = {
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 35,
      timedOut: false,
    };

    const adapter = new HttpxInspectionAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.inspectWeb({
      targetUrl: 'https://example.com',
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
  // Assertion 8: URL Scheme Validation
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 8: Non-HTTP URL schemes fail preflight safely');
  {
    const runner = new MockProcessRunner();
    const adapter = new HttpxInspectionAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.inspectWeb({
      targetUrl: 'ftp://example.com/file.txt',
      ...auth,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'unsupported_url_protocol');
    }
    assert.strictEqual(runner.calls.length, 0);
    console.log('    -> Non-HTTP schemes safely rejected before process spawning');
  }

  console.log('\n[✔] ALL MILESTONE 66 HTTPX ADAPTER SMOKE ASSERTIONS PASSED SUCCESSFULLY.');
}

runMilestone66SmokeTests().catch((err) => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
