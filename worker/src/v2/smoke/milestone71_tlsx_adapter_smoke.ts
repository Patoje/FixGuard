import assert from 'node:assert';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { TlsxAdapter } from '../recon/adapters/TlsxAdapter.js';

class MockProcessRunner implements ProcessRunner {
  public calls: ExecutionRequest[] = [];
  public tlsxOutput: RawExecutionOutput = {
    stdout: '',
    stderr: '',
    exitCode: 0,
    durationMs: 70,
    timedOut: false,
  };

  async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    this.calls.push(request);
    return this.tlsxOutput;
  }
}

function createScopeGrant(overrides?: Partial<AuthorizedScopeGrant>): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_m71_001',
    scanId: 'scan_m71_001',
    issuedAt: '2026-09-13T12:00:00.000Z',
    expiresAt: '2026-09-14T12:00:00.000Z',
    subject: {
      targetKind: 'domain',
      domain: 'example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for TLS/SSL inspection in milestone 71',
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
      assessmentId: 'assess_m71_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_m71_001',
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
    assessmentId: 'assess_m71_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'decision_m71_001',
    actorId: 'pentest_lead_1',
  };

  return {
    verifiedAuthorizationDecision: establishResult.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
  };
}

async function runMilestone71SmokeTests() {
  console.log('=== [M71 SMOKE] Exhaustive TLS/SSL Inspection Adapter (Tlsx) ===\n');

  // -------------------------------------------------------------------------
  // Assertion 1: Happy Path TLS Profiling & Discipline of Claims
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 1: Happy path TLS inspection with SANs, protocols, ciphers, and non-claims');
  {
    const runner = new MockProcessRunner();
    runner.tlsxOutput = {
      stdout: [
        JSON.stringify({
          host: 'example.com',
          port: 443,
          ip: '93.184.216.34',
          tls_version: 'tls13',
          cipher: 'TLS_AES_128_GCM_SHA256',
          certificate_response: {
            subject_an: ['example.com', 'www.example.com'],
            issuer_dn: 'CN=DigiCert Global Root CA,O=DigiCert Inc,C=US',
            not_before: '2024-01-01T00:00:00Z',
            not_after: '2025-01-01T00:00:00Z',
            expired: false,
            self_signed: false,
          },
          version_enum: [
            { version: 'tls12', cipher: 'ECDHE-RSA-AES128-GCM-SHA256' },
            { version: 'tls13', cipher: 'TLS_AES_128_GCM_SHA256' },
          ],
        }),
        JSON.stringify({
          host: 'example.com',
          port: 8443,
          ip: '93.184.216.34',
          certificate_response: {
            subject_an: ['api.example.com'],
            issuer_dn: 'CN=DigiCert Global Root CA,O=DigiCert Inc,C=US',
            expired: true,
            self_signed: false,
          },
          version_enum: [
            { version: 'tls10', cipher: 'DES-CBC3-SHA' },
            { version: 'tls12', cipher: 'ECDHE-RSA-AES256-GCM-SHA384' },
          ],
        }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 80,
      timedOut: false,
    };

    const adapter = new TlsxAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.inspectTls({
      targetHostOrUrl: 'example.com',
      targetPorts: [443, 8443],
      ...auth,
      timeoutMs: 35_000,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.targetHost, 'example.com');
      assert.strictEqual(result.observations.length, 2);

      const p443 = result.observations.find((o) => o.port === 443);
      assert(p443, 'Port 443 observation must be present');
      assert.deepStrictEqual(p443.subjectAlternativeNames, ['example.com', 'www.example.com']);
      assert.deepStrictEqual(p443.supportedProtocols, ['tls12', 'tls13']);
      assert.strictEqual(p443.expired, false);
      assert.strictEqual(p443.selfSigned, false);
      assert(p443.cipherSuites.includes('TLS_AES_128_GCM_SHA256'));

      const p8443 = result.observations.find((o) => o.port === 8443);
      assert(p8443, 'Port 8443 observation must be present');
      assert.deepStrictEqual(p8443.subjectAlternativeNames, ['api.example.com']);
      assert.deepStrictEqual(p8443.supportedProtocols, ['tls10', 'tls12']);
      assert.strictEqual(p8443.expired, true);
      assert(p8443.cipherSuites.includes('DES-CBC3-SHA'));

      // Verify anti-speculation explicit non-claims (Discipline of Claims)
      assert.strictEqual(result.explicitNonClaims.severity, 'info');
      assert.strictEqual(result.explicitNonClaims.createsRealFindings, false);
      assert.strictEqual(result.explicitNonClaims.confirmsVulnerabilities, false);
      assert.strictEqual(result.explicitNonClaims.makesSeverityClaims, false);

      // Verify arguments
      assert.strictEqual(runner.calls.length, 1);
      assert.strictEqual(runner.calls[0].binary, 'tlsx');
      assert.deepStrictEqual(runner.calls[0].args, [
        '-u',
        'example.com',
        '-json',
        '-san',
        '-ve',
        '-p',
        '443,8443',
      ]);
    }
    console.log('    -> Happy path verified: SANs, protocols, ciphers, and factual non-claims mapped cleanly');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: Process Isolation & Port Argument Injection
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 2: Multi-port parameter isolation and -san, -ve argument validation');
  {
    const runner = new MockProcessRunner();
    runner.tlsxOutput = {
      stdout: JSON.stringify({ host: 'example.com', port: 9443 }),
      stderr: '',
      exitCode: 0,
      durationMs: 30,
      timedOut: false,
    };

    const adapter = new TlsxAdapter(runner);
    const auth = setupAuthorizedContext();

    await adapter.inspectTls({
      targetHostOrUrl: 'https://example.com:9443',
      ...auth,
    });

    assert.strictEqual(runner.calls.length, 1);
    const args = runner.calls[0].args;
    assert.strictEqual(args[0], '-u');
    assert.strictEqual(args[1], 'example.com');
    assert(args.includes('-san'), '-san must be present');
    assert(args.includes('-ve'), '-ve must be present');
    const pIdx = args.indexOf('-p');
    assert(pIdx !== -1, '-p must be present');
    assert.strictEqual(args[pIdx + 1], '9443');

    console.log('    -> Argument array isolation and dynamic port injection verified');
  }

  // -------------------------------------------------------------------------
  // Assertion 3: Deep SSRF Post-Execution Drop
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 3: Deep SSRF Post-Execution Drop (Dropping observations with restricted resolved IPs)');
  {
    const runner = new MockProcessRunner();
    runner.tlsxOutput = {
      stdout: [
        JSON.stringify({ host: 'example.com', port: 443, ip: '93.184.216.34' }),
        JSON.stringify({ host: 'example.com', port: 8443, ip: '10.0.0.1' }),
        JSON.stringify({ host: 'example.com', port: 9443, ip: '127.0.0.1' }),
        JSON.stringify({ host: 'example.com', port: 10443, ip: '169.254.169.254' }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 50,
      timedOut: false,
    };

    const adapter = new TlsxAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.inspectTls({
      targetHostOrUrl: 'example.com',
      targetPorts: [443, 8443, 9443, 10443],
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.observations.length, 1, 'Only public IP observation must remain');
      assert.strictEqual(result.observations[0].port, 443);
      assert.strictEqual(result.observations[0].ip, '93.184.216.34');
    }
    console.log('    -> All observations resolving to RFC-1918, loopback, and metadata safely dropped');
  }

  // -------------------------------------------------------------------------
  // Assertion 4: Atomic Preflight Denial (Missing or Spoofed Authorization Brand)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 4: Atomic Preflight Denial (Missing or spoofed authorization brand)');
  {
    const runner = new MockProcessRunner();
    const adapter = new TlsxAdapter(runner);
    const auth = setupAuthorizedContext();

    const spoofedDecision = {
      ...auth.verifiedAuthorizationDecision,
      decision: 'authorized' as const,
    };

    const result = await adapter.inspectTls({
      targetHostOrUrl: 'example.com',
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
  console.log('[*] Assertion 5: Atomic Preflight Denial (Target host outside scope boundaries)');
  {
    const runner = new MockProcessRunner();
    const adapter = new TlsxAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.inspectTls({
      targetHostOrUrl: 'unauthorized-site.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'target_out_of_scope');
    }
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for out-of-scope target');
    console.log('    -> Preflight safely denied out-of-scope target host');
  }

  // -------------------------------------------------------------------------
  // Assertion 6: Atomic Preflight Denial (Missing Permissions)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 6: Atomic Preflight Denial (Grant lacks TLS/fingerprinting permissions)');
  {
    const runner = new MockProcessRunner();
    const adapter = new TlsxAdapter(runner);
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

    const result = await adapter.inspectTls({
      targetHostOrUrl: 'example.com',
      ...auth,
    });

    assert.strictEqual(result.status, 'preflight_denied');
    if (result.status === 'preflight_denied') {
      assert.strictEqual(result.reasonCode, 'missing_permission');
    }
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned on permission denial');
    console.log('    -> Preflight safely denied execution lacking fingerprinting permissions');
  }

  // -------------------------------------------------------------------------
  // Assertion 7: Target Host SSRF Pre-Check Denial
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 7: Target Host SSRF Pre-Check Denial (Loopback / invalid target host)');
  {
    const runner = new MockProcessRunner();
    const adapter = new TlsxAdapter(runner);
    const auth = setupAuthorizedContext();

    // Invalid format
    const invalidResult = await adapter.inspectTls({
      targetHostOrUrl: 'invalid_fqdn_!',
      ...auth,
    });
    assert.strictEqual(invalidResult.status, 'preflight_denied');
    if (invalidResult.status === 'preflight_denied') {
      assert.strictEqual(invalidResult.reasonCode, 'invalid_target_host');
    }

    // SSRF Loopback host
    const loopbackResult = await adapter.inspectTls({
      targetHostOrUrl: '127.0.0.1',
      ...auth,
    });
    assert.strictEqual(loopbackResult.status, 'preflight_denied');
    assert(
      loopbackResult.status === 'preflight_denied' &&
        (loopbackResult.reasonCode === 'invalid_target_host' ||
          loopbackResult.reasonCode === 'ssrf_target_blocked')
    );

    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for SSRF target host');
    console.log('    -> Malformed and SSRF target hosts safely blocked in preflight');
  }

  // -------------------------------------------------------------------------
  // Assertion 8: Empty & Malformed Output Resilience
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 8: Empty & Malformed Output Resilience');
  {
    const runner = new MockProcessRunner();
    runner.tlsxOutput = {
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 25,
      timedOut: false,
    };

    const adapter = new TlsxAdapter(runner);
    const auth = setupAuthorizedContext();

    // Empty output test
    const emptyResult = await adapter.inspectTls({
      targetHostOrUrl: 'example.com',
      ...auth,
    });

    assert.strictEqual(emptyResult.status, 'success');
    if (emptyResult.status === 'success') {
      assert.strictEqual(emptyResult.observations.length, 0);
      assert.deepStrictEqual(emptyResult.observations, []);
    }

    // Malformed JSON output test
    runner.tlsxOutput = {
      stdout: [
        'tlsx connecting...',
        '{ invalid json [',
        '',
        JSON.stringify({
          host: 'example.com',
          port: 443,
          tls_version: 'tls13',
        }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 35,
      timedOut: false,
    };

    const resilientResult = await adapter.inspectTls({
      targetHostOrUrl: 'example.com',
      ...auth,
    });

    assert.strictEqual(resilientResult.status, 'success');
    if (resilientResult.status === 'success') {
      assert.strictEqual(resilientResult.observations.length, 1);
      assert.strictEqual(resilientResult.observations[0].port, 443);
      assert.deepStrictEqual(resilientResult.observations[0].supportedProtocols, ['tls13']);
    }

    console.log('    -> Clean zero observations on empty output and fail-closed malformed line resilience verified');
  }

  console.log('\n[✔] ALL MILESTONE 71 TLS/SSL INSPECTION ADAPTER SMOKE ASSERTIONS PASSED SUCCESSFULLY.');
}

runMilestone71SmokeTests().catch((err) => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
