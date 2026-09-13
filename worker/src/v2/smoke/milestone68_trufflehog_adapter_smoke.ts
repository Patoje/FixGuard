import assert from 'node:assert';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { TrufflehogAdapter, maskSecret } from '../recon/adapters/TrufflehogAdapter.js';

class MockProcessRunner implements ProcessRunner {
  public calls: ExecutionRequest[] = [];
  public trufflehogOutput: RawExecutionOutput = {
    stdout: '',
    stderr: '',
    exitCode: 0,
    durationMs: 75,
    timedOut: false,
  };

  async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    this.calls.push(request);
    return this.trufflehogOutput;
  }
}

function createScopeGrant(overrides?: Partial<AuthorizedScopeGrant>): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_m68_001',
    scanId: 'scan_m68_001',
    issuedAt: '2026-09-13T12:00:00.000Z',
    expiresAt: '2026-09-14T12:00:00.000Z',
    subject: {
      targetKind: 'domain',
      domain: 'example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for exposed credential discovery in milestone 68',
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
      assessmentId: 'assess_m68_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_m68_001',
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
    assessmentId: 'assess_m68_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'decision_m68_001',
    actorId: 'pentest_lead_1',
  };

  return {
    verifiedAuthorizationDecision: establishResult.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
  };
}

async function runMilestone68SmokeTests() {
  console.log('=== [M68 SMOKE] Secret Scanning & Exposed Credential Discovery Adapter (Trufflehog) ===\n');

  const RAW_SECRET_SAMPLE = 'AKIAIOSFODNN7EXAMPLE';

  // -------------------------------------------------------------------------
  // Assertion 1: Happy Path Discovery & Argument Isolation
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 1: Happy path discovery, strict redaction, non-claims, and argument isolation');
  {
    const runner = new MockProcessRunner();
    runner.trufflehogOutput = {
      stdout: JSON.stringify({
        SourceMetadata: {
          Data: {
            Git: {
              commit: 'a1b2c3d4e5f6',
              file: 'config/credentials.env',
              repository: 'https://example.com/repo.git',
            },
          },
        },
        DetectorName: 'AWS',
        Raw: RAW_SECRET_SAMPLE,
        Redacted: 'AKIA****************',
        Verified: false,
      }),
      stderr: '',
      exitCode: 183, // Trufflehog exit code 183 indicates findings detected
      durationMs: 95,
      timedOut: false,
    };

    const adapter = new TrufflehogAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.scanSecrets({
      targetUrlOrPath: 'https://example.com/repo.git',
      scanType: 'git',
      ...auth,
      timeoutMs: 45_000,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      assert.strictEqual(result.targetUrlOrPath, 'https://example.com/repo.git');
      assert.strictEqual(result.observations.length, 1);

      const obs = result.observations[0];
      assert.strictEqual(obs.detectorName, 'AWS');
      assert.strictEqual(obs.redactedSecret, 'AKIA****************');
      assert.strictEqual(obs.locationUrl, 'https://example.com/repo.git/config/credentials.env');
      assert.strictEqual(obs.verified, false);

      // Verify anti-speculation explicit non-claims
      assert.strictEqual(result.explicitNonClaims.severity, 'info');
      assert.strictEqual(result.explicitNonClaims.createsRealFindings, false);
      assert.strictEqual(result.explicitNonClaims.confirmsVulnerabilities, false);
      assert.strictEqual(result.explicitNonClaims.makesSeverityClaims, false);

      // Verify process isolation and arguments
      assert.strictEqual(runner.calls.length, 1);
      assert.strictEqual(runner.calls[0].binary, 'trufflehog');
      assert.deepStrictEqual(runner.calls[0].args, [
        'git',
        'https://example.com/repo.git',
        '--json',
        '--no-verification',
      ]);
      assert.strictEqual(runner.calls[0].timeoutMs, 45_000);
    }
    console.log('    -> Happy path verified: secret redacted, argument array isolated, non-claims intact');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: Deep Redaction Check (Raw Secret Never Leaks)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 2: Deep Redaction Check (Raw plaintext secret strictly prohibited in result)');
  {
    const runner = new MockProcessRunner();
    runner.trufflehogOutput = {
      stdout: JSON.stringify({
        SourceMetadata: {
          Data: {
            Git: {
              file: 'src/aws.ts',
            },
          },
        },
        DetectorName: 'AWS',
        Raw: RAW_SECRET_SAMPLE,
        Redacted: RAW_SECRET_SAMPLE, // Simulate tool omitting redaction
        Verified: true,
      }),
      stderr: '',
      exitCode: 183,
      durationMs: 80,
      timedOut: false,
    };

    const adapter = new TrufflehogAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.scanSecrets({
      targetUrlOrPath: 'https://example.com/repo.git',
      ...auth,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      const serialized = JSON.stringify(result);
      assert(
        !serialized.includes(RAW_SECRET_SAMPLE),
        'CRITICAL: Serialized result must NEVER contain raw plaintext secret!'
      );

      for (const obs of result.observations) {
        assert.strictEqual(obs.redactedSecret, 'AKIA****************');
        assert(!JSON.stringify(obs).includes(RAW_SECRET_SAMPLE));
      }
    }

    // Direct unit testing of maskSecret defense-in-depth helper
    assert.strictEqual(maskSecret(''), '[REDACTED]');
    assert.strictEqual(maskSecret('abc'), '****');
    assert.strictEqual(maskSecret('1234'), '****');
    assert.strictEqual(maskSecret('secret123'), 'secr*****');
    assert.strictEqual(maskSecret('AKIAIOSFODNN7EXAMPLE'), 'AKIA****************');
    assert.strictEqual(maskSecret('tok_0123456789abcdef'), 'tok_****************');

    console.log('    -> Deep Redaction Check PASSED: zero raw secrets leaked in memory or serialized DTO');
  }

  // -------------------------------------------------------------------------
  // Assertion 3: Atomic Preflight Denial (Missing or Unbranded Authorization)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 3: Atomic Preflight Denial (Missing or spoofed authorization brand)');
  {
    const runner = new MockProcessRunner();
    const adapter = new TrufflehogAdapter(runner);
    const auth = setupAuthorizedContext();

    const spoofedDecision = {
      ...auth.verifiedAuthorizationDecision,
      decision: 'authorized' as const,
    };

    const result = await adapter.scanSecrets({
      targetUrlOrPath: 'https://example.com/repo.git',
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
  // Assertion 4: Atomic Preflight Denial (Scope Boundary Denial)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 4: Atomic Preflight Denial (Target outside scope boundaries)');
  {
    const runner = new MockProcessRunner();
    const adapter = new TrufflehogAdapter(runner);
    const auth = setupAuthorizedContext();

    const result = await adapter.scanSecrets({
      targetUrlOrPath: 'https://unauthorized-site.com/repo.git',
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
  // Assertion 5: Atomic Preflight Denial (Missing Permissions)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 5: Atomic Preflight Denial (Grant lacks secret scanning permissions)');
  {
    const runner = new MockProcessRunner();
    const adapter = new TrufflehogAdapter(runner);
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

    const result = await adapter.scanSecrets({
      targetUrlOrPath: 'https://example.com/repo.git',
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
  // Assertion 6: SSRF Containment (Target URL Pointing to Loopback / Metadata)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 6: SSRF Containment (Filtering loopback and cloud metadata targets)');
  {
    const runner = new MockProcessRunner();
    const adapter = new TrufflehogAdapter(runner);
    const auth = setupAuthorizedContext();

    // Test loopback
    const loopbackResult = await adapter.scanSecrets({
      targetUrlOrPath: 'http://127.0.0.1/repo.git',
      ...auth,
    });
    assert.strictEqual(loopbackResult.status, 'preflight_denied');
    if (loopbackResult.status === 'preflight_denied') {
      assert.strictEqual(loopbackResult.reasonCode, 'ssrf_target_blocked');
    }

    // Test cloud metadata
    const metadataResult = await adapter.scanSecrets({
      targetUrlOrPath: 'http://169.254.169.254/latest/meta-data',
      ...auth,
    });
    assert.strictEqual(metadataResult.status, 'preflight_denied');
    if (metadataResult.status === 'preflight_denied') {
      assert.strictEqual(metadataResult.reasonCode, 'ssrf_target_blocked');
    }

    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for SSRF targets');
    console.log('    -> All SSRF-restricted IP targets safely denied in preflight');
  }

  // -------------------------------------------------------------------------
  // Assertion 7: Path Traversal Safety & Filesystem Isolation
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 7: Path Traversal Safety & Filesystem Isolation');
  {
    const runner = new MockProcessRunner();
    const adapter = new TrufflehogAdapter(runner);
    const auth = setupAuthorizedContext();

    // 1. Path traversal attempt with '..'
    const traversalResult = await adapter.scanSecrets({
      targetUrlOrPath: '../../etc/shadow',
      scanType: 'filesystem',
      ...auth,
    });
    assert.strictEqual(traversalResult.status, 'preflight_denied');
    if (traversalResult.status === 'preflight_denied') {
      assert.strictEqual(traversalResult.reasonCode, 'unsafe_target_path');
    }

    // 2. Forbidden system directory attempt
    const forbiddenDirResult = await adapter.scanSecrets({
      targetUrlOrPath: '/etc/passwd',
      scanType: 'filesystem',
      ...auth,
    });
    assert.strictEqual(forbiddenDirResult.status, 'preflight_denied');
    if (forbiddenDirResult.status === 'preflight_denied') {
      assert.strictEqual(forbiddenDirResult.reasonCode, 'unsafe_target_path');
    }

    // 3. Forbidden root attempt
    const rootDirResult = await adapter.scanSecrets({
      targetUrlOrPath: '/root/.ssh',
      scanType: 'filesystem',
      ...auth,
    });
    assert.strictEqual(rootDirResult.status, 'preflight_denied');
    if (rootDirResult.status === 'preflight_denied') {
      assert.strictEqual(rootDirResult.reasonCode, 'unsafe_target_path');
    }

    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for unsafe filesystem paths');

    // 4. Safe filesystem path executes with 'filesystem' CLI argument
    runner.trufflehogOutput = {
      stdout: JSON.stringify({
        SourceMetadata: {
          Data: {
            Filesystem: {
              file: 'workspace/project/config.py',
            },
          },
        },
        DetectorName: 'WebhookToken',
        Raw: 'https://example-webhook.internal.example.com/tokens/sample_fake_token_value',
        Redacted: 'https://example-webhook.internal.example.com/tokens/****************',
        Verified: false,
      }),
      stderr: '',
      exitCode: 183,
      durationMs: 50,
      timedOut: false,
    };

    const safeFsResult = await adapter.scanSecrets({
      targetUrlOrPath: 'workspace/project',
      scanType: 'filesystem',
      ...auth,
    });

    assert.strictEqual(safeFsResult.status, 'success');
    assert.strictEqual(runner.calls.length, 1);
    assert.deepStrictEqual(runner.calls[0].args, ['filesystem', 'workspace/project', '--json']);

    console.log('    -> Path traversal and forbidden directories safely rejected; safe path isolated');
  }

  // -------------------------------------------------------------------------
  // Assertion 8: Empty Output & Malformed Output Resilience
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 8: Empty Output & Malformed Output Resilience');
  {
    const runner = new MockProcessRunner();
    runner.trufflehogOutput = {
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 35,
      timedOut: false,
    };

    const adapter = new TrufflehogAdapter(runner);
    const auth = setupAuthorizedContext();

    const emptyResult = await adapter.scanSecrets({
      targetUrlOrPath: 'https://example.com/repo.git',
      ...auth,
    });

    assert.strictEqual(emptyResult.status, 'success');
    if (emptyResult.status === 'success') {
      assert.strictEqual(emptyResult.observations.length, 0);
      assert.deepStrictEqual(emptyResult.observations, []);
    }

    // Malformed JSON output resilience
    runner.trufflehogOutput = {
      stdout: [
        'not a json line',
        '{ invalid json [',
        '',
        JSON.stringify({
          DetectorName: 'GitHub',
          Raw: 'ghp_1234567890abcdef1234',
          SourceMetadata: { Data: { Git: { file: 'token.txt' } } },
        }),
      ].join('\n'),
      stderr: '',
      exitCode: 183,
      durationMs: 40,
      timedOut: false,
    };

    const resilientResult = await adapter.scanSecrets({
      targetUrlOrPath: 'https://example.com/repo.git',
      ...auth,
    });

    assert.strictEqual(resilientResult.status, 'success');
    if (resilientResult.status === 'success') {
      assert.strictEqual(resilientResult.observations.length, 1);
      assert.strictEqual(resilientResult.observations[0].detectorName, 'GitHub');
      assert.strictEqual(resilientResult.observations[0].redactedSecret, 'ghp_********************');
    }

    console.log('    -> Clean zero observations on empty output and fail-closed malformed line resilience verified');
  }

  console.log('\n[✔] ALL MILESTONE 68 SECRET DISCOVERY ADAPTER SMOKE ASSERTIONS PASSED SUCCESSFULLY.');
}

runMilestone68SmokeTests().catch((err) => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
