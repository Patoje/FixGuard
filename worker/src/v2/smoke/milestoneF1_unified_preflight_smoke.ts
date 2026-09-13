import assert from 'node:assert';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import {
  runAdapterPreflight,
  validateWordlistOrPath,
  validateDnsRebinding,
  type PreSpawnDnsResolver,
} from '../recon/adapters/AdapterPreflightPipeline.js';
import { SubfinderAdapter } from '../recon/adapters/SubfinderAdapter.js';
import { NaabuPortDiscoveryAdapter } from '../recon/adapters/NaabuPortDiscoveryAdapter.js';
import { HttpxInspectionAdapter } from '../recon/adapters/HttpxInspectionAdapter.js';
import { TrufflehogAdapter } from '../recon/adapters/TrufflehogAdapter.js';
import { FfufAdapter } from '../recon/adapters/FfufAdapter.js';
import { DnsxAdapter } from '../recon/adapters/DnsxAdapter.js';
import { TlsxAdapter } from '../recon/adapters/TlsxAdapter.js';
import { ArjunAdapter } from '../recon/adapters/ArjunAdapter.js';
import { CompositeUrlDiscoveryAdapter } from '../recon/adapters/CompositeUrlDiscoveryAdapter.js';

class MockProcessRunner implements ProcessRunner {
  public calls: ExecutionRequest[] = [];
  public defaultOutput: RawExecutionOutput = {
    stdout: '',
    stderr: '',
    exitCode: 0,
    durationMs: 20,
    timedOut: false,
  };

  async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    this.calls.push(request);
    return this.defaultOutput;
  }
}

function createScopeGrant(overrides?: Partial<AuthorizedScopeGrant>): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_f1_001',
    scanId: 'scan_f1_001',
    issuedAt: '2026-09-13T12:00:00.000Z',
    expiresAt: '2026-09-14T12:00:00.000Z',
    subject: {
      targetKind: 'domain',
      domain: 'example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for unified preflight verification testing',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: false,
      lightValidation: true,
      activeValidation: true,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: ['example.com'],
      allowedHosts: ['example.com', 'api.example.com', '93.184.216.34'],
      allowedOrigins: ['https://example.com', 'https://api.example.com'],
      allowedMethods: ['GET', 'HEAD', 'POST'],
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
      assessmentId: 'assess_f1_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_f1_001',
      authorizedActor: { actorId: 'sec_lead_1', actorType: 'human' },
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
    assessmentId: 'assess_f1_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'decision_f1_001',
    actorId: 'sec_lead_1',
  };

  return {
    verifiedAuthorizationDecision: establishResult.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
  };
}

async function runMilestoneF1SmokeTests() {
  console.log('=== [M-F1 SMOKE] Unified Execution Boundary & Adapter Preflight Pipeline ===\n');

  // -------------------------------------------------------------------------
  // Assertion 1: Shared Pipeline Happy Path Across Multiple Adapters
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 1: Shared pipeline happy path across distinct adapters');
  {
    const auth = setupAuthorizedContext();

    // 1. Direct Pipeline invocation for domain
    const preflightDomain = await runAdapterPreflight({
      target: 'example.com',
      targetKind: 'fqdn',
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      authorizedScopeGrant: auth.authorizedScopeGrant,
      lineage: auth.lineage,
      requiredPermissions: ['endpointDiscovery', 'passiveRecon'],
    });
    assert.strictEqual(preflightDomain.ok, true);
    if (preflightDomain.ok) {
      assert.strictEqual(preflightDomain.targetHost, 'example.com');
    }

    // 2. Direct Pipeline invocation for URL
    const preflightUrl = await runAdapterPreflight({
      target: 'https://example.com/api',
      targetKind: 'url',
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      authorizedScopeGrant: auth.authorizedScopeGrant,
      lineage: auth.lineage,
      requiredPermissions: ['endpointDiscovery'],
    });
    assert.strictEqual(preflightUrl.ok, true);
    if (preflightUrl.ok) {
      assert.strictEqual(preflightUrl.targetHost, 'example.com');
    }

    // 3. Direct Pipeline invocation for IP
    const preflightIp = await runAdapterPreflight({
      target: '93.184.216.34',
      targetKind: 'ipv4_or_fqdn',
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      authorizedScopeGrant: auth.authorizedScopeGrant,
      lineage: auth.lineage,
      requiredPermissions: ['endpointDiscovery'],
    });
    assert.strictEqual(preflightIp.ok, true);
    if (preflightIp.ok) {
      assert.strictEqual(preflightIp.targetHost, '93.184.216.34');
    }

    // 4. Subfinder adapter integration
    const subfinderRunner = new MockProcessRunner();
    subfinderRunner.defaultOutput = {
      stdout: JSON.stringify({ host: 'example.com' }),
      stderr: '',
      exitCode: 0,
      durationMs: 30,
      timedOut: false,
    };
    const subfinder = new SubfinderAdapter(subfinderRunner);
    const subfinderRes = await subfinder.discoverSubdomains({
      targetDomain: 'example.com',
      ...auth,
    });
    assert.strictEqual(subfinderRes.status, 'success');
    assert.strictEqual(subfinderRunner.calls.length, 1);

    // 5. Naabu adapter integration
    const naabuRunner = new MockProcessRunner();
    naabuRunner.defaultOutput = {
      stdout: JSON.stringify({ host: 'example.com', port: 443 }),
      stderr: '',
      exitCode: 0,
      durationMs: 30,
      timedOut: false,
    };
    const naabu = new NaabuPortDiscoveryAdapter(naabuRunner);
    const naabuRes = await naabu.discoverPorts({
      targetHostOrIp: 'example.com',
      ...auth,
    });
    assert.strictEqual(naabuRes.status, 'success');
    assert.strictEqual(naabuRunner.calls.length, 1);

    console.log('    -> Happy path verified across direct pipeline calls and Layer 6 adapters');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: Centralized Unbranded Authorization Brand (WeakSet) Denial
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 2: Centralized unbranded authorization decision denial (WeakSet)');
  {
    const auth = setupAuthorizedContext();
    // Forge an unbranded decision that mimics verified decision structure
    const forgedDecision = {
      ...auth.verifiedAuthorizationDecision,
      decision: 'authorized' as const,
    };

    const runner = new MockProcessRunner();
    const adapters = [
      new SubfinderAdapter(runner),
      new HttpxInspectionAdapter(runner),
      new DnsxAdapter(runner),
      new TlsxAdapter(runner),
      new TrufflehogAdapter(runner),
    ];

    const results = await Promise.all([
      (adapters[0] as SubfinderAdapter).discoverSubdomains({
        targetDomain: 'example.com',
        verifiedAuthorizationDecision: forgedDecision,
        authorizedScopeGrant: auth.authorizedScopeGrant,
        lineage: auth.lineage,
      }),
      (adapters[1] as HttpxInspectionAdapter).inspectWeb({
        targetUrl: 'https://example.com',
        verifiedAuthorizationDecision: forgedDecision,
        authorizedScopeGrant: auth.authorizedScopeGrant,
        lineage: auth.lineage,
      }),
      (adapters[2] as DnsxAdapter).resolveDns({
        targetDomain: 'example.com',
        verifiedAuthorizationDecision: forgedDecision,
        authorizedScopeGrant: auth.authorizedScopeGrant,
        lineage: auth.lineage,
      }),
      (adapters[3] as TlsxAdapter).inspectTls({
        targetHostOrUrl: 'example.com',
        verifiedAuthorizationDecision: forgedDecision,
        authorizedScopeGrant: auth.authorizedScopeGrant,
        lineage: auth.lineage,
      }),
      (adapters[4] as TrufflehogAdapter).scanSecrets({
        targetUrlOrPath: 'https://example.com',
        scanType: 'git',
        verifiedAuthorizationDecision: forgedDecision,
        authorizedScopeGrant: auth.authorizedScopeGrant,
        lineage: auth.lineage,
      }),
    ]);

    for (const res of results) {
      assert.strictEqual(res.status, 'preflight_denied');
      assert.strictEqual(res.reasonCode, 'authorization_unconfirmed');
    }
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned across all 5 adapters');
    console.log('    -> All adapters safely failed closed with authorization_unconfirmed and 0 spawns');
  }

  // -------------------------------------------------------------------------
  // Assertion 3: Dynamic DNS Rebinding Denial (Pre-Spawn Resolution Gate)
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 3: Dynamic DNS Rebinding Denial (Pre-spawn resolution check)');
  {
    const auth = setupAuthorizedContext();

    // 1. Standalone validateDnsRebinding tests
    const loopbackCheck = await validateDnsRebinding('rebinding.example.com', async () => ['127.0.0.1']);
    assert.strictEqual(loopbackCheck.ok, false);
    assert.strictEqual(loopbackCheck.blockedIp, '127.0.0.1');

    const metadataCheck = await validateDnsRebinding('rebinding.example.com', async () => ['169.254.169.254']);
    assert.strictEqual(metadataCheck.ok, false);
    assert.strictEqual(metadataCheck.blockedIp, '169.254.169.254');

    const rfc1918Check = await validateDnsRebinding('rebinding.example.com', async () => ['10.0.0.1']);
    assert.strictEqual(rfc1918Check.ok, false);
    assert.strictEqual(rfc1918Check.blockedIp, '10.0.0.1');

    const ipv6LoopbackCheck = await validateDnsRebinding('rebinding.example.com', async () => ['::1']);
    assert.strictEqual(ipv6LoopbackCheck.ok, false);

    const safePublicCheck = await validateDnsRebinding('safe.example.com', async () => ['93.184.216.34']);
    assert.strictEqual(safePublicCheck.ok, true);

    // 2. Adapter-level DNS Rebinding Denial: Mock DNS resolver returning loopback for example.com
    const rebindingResolver: PreSpawnDnsResolver = async (hostname: string) => {
      if (hostname === 'example.com') {
        return ['127.0.0.1']; // Simulates DNS rebinding attack flipping public host to loopback
      }
      return ['93.184.216.34'];
    };

    const runner = new MockProcessRunner();
    const rebindingSubfinder = new SubfinderAdapter(runner, rebindingResolver);
    const subfinderResult = await rebindingSubfinder.discoverSubdomains({
      targetDomain: 'example.com',
      ...auth,
    });
    assert.strictEqual(subfinderResult.status, 'preflight_denied');
    assert.strictEqual(subfinderResult.reasonCode, 'ssrf_target_blocked');
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned on DNS rebinding');

    const rebindingHttpx = new HttpxInspectionAdapter(runner, rebindingResolver);
    const httpxResult = await rebindingHttpx.inspectWeb({
      targetUrl: 'https://example.com',
      ...auth,
    });
    assert.strictEqual(httpxResult.status, 'preflight_denied');
    assert.strictEqual(httpxResult.reasonCode, 'ssrf_target_blocked');
    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned on DNS rebinding in Httpx');

    console.log('    -> Dynamic DNS rebinding attempts safely rejected with ssrf_target_blocked and 0 spawns');
  }

  // -------------------------------------------------------------------------
  // Assertion 4: Shared Wordlist Path Traversal Denial
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 4: Shared wordlist path traversal and system directory containment');
  {
    const auth = setupAuthorizedContext();
    const runner = new MockProcessRunner();
    const ffuf = new FfufAdapter(runner);

    const dangerousWordlists = [
      '../../../../etc/passwd',
      '../wordlists/common.txt',
      '/etc/shadow',
      '/var/log/audit.log',
      '/root/.ssh/id_rsa',
      '/proc/cpuinfo',
      '/dev/urandom',
    ];

    for (const wl of dangerousWordlists) {
      // 1. Direct utility check
      const direct = validateWordlistOrPath(wl, 'wordlist');
      assert.strictEqual(direct.valid, false, `Wordlist ${wl} must be marked invalid`);
      assert.strictEqual(direct.reasonCode, 'unsafe_wordlist_path');

      // 2. Adapter check
      const res = await ffuf.discoverContent({
        targetUrl: 'https://example.com',
        wordlistPath: wl,
        ...auth,
      });
      assert.strictEqual(res.status, 'preflight_denied');
      assert.strictEqual(res.reasonCode, 'unsafe_wordlist_path');
    }

    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for dangerous wordlist paths');
    console.log('    -> All dangerous wordlist path attempts safely rejected with unsafe_wordlist_path');
  }

  // -------------------------------------------------------------------------
  // Assertion 5: Shared Filesystem Path Traversal Denial
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 5: Shared filesystem path traversal and system directory containment');
  {
    const auth = setupAuthorizedContext();
    const runner = new MockProcessRunner();
    const trufflehog = new TrufflehogAdapter(runner);

    const dangerousPaths = [
      '../../secrets',
      '/etc/nginx/nginx.conf',
      '/root/.bash_history',
      '/sys/class',
      '/dev/null',
      '/boot/vmlinuz',
    ];

    for (const p of dangerousPaths) {
      // 1. Direct utility check
      const direct = validateWordlistOrPath(p, 'filesystem');
      assert.strictEqual(direct.valid, false, `Filesystem path ${p} must be marked invalid`);
      assert.strictEqual(direct.reasonCode, 'unsafe_target_path');

      // 2. Trufflehog filesystem scan
      const res = await trufflehog.scanSecrets({
        targetUrlOrPath: p,
        scanType: 'filesystem',
        ...auth,
      });
      assert.strictEqual(res.status, 'preflight_denied');
      assert.strictEqual(res.reasonCode, 'unsafe_target_path');
    }

    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for dangerous filesystem paths');
    console.log('    -> All dangerous filesystem path attempts safely rejected with unsafe_target_path');
  }

  // -------------------------------------------------------------------------
  // Assertion 6: Continuous Lineage Tuple Mismatch Denial Across Adapters
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 6: Continuous lineage tuple mismatch denial across adapters');
  {
    const auth = setupAuthorizedContext();
    const runner = new MockProcessRunner();

    const adapters = [
      new NaabuPortDiscoveryAdapter(runner),
      new DnsxAdapter(runner),
      new TlsxAdapter(runner),
    ];

    // Tampered lineage (mismatched scanId)
    const tamperedLineage: AuthorizedActiveReconRequestLineage = {
      ...auth.lineage,
      scanId: 'scan_tampered_999',
    };

    const resNaabu = await (adapters[0] as NaabuPortDiscoveryAdapter).discoverPorts({
      targetHostOrIp: 'example.com',
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      authorizedScopeGrant: auth.authorizedScopeGrant,
      lineage: tamperedLineage,
    });
    assert.strictEqual(resNaabu.status, 'preflight_denied');
    assert.strictEqual(resNaabu.reasonCode, 'lineage_mismatch');

    const resDnsx = await (adapters[1] as DnsxAdapter).resolveDns({
      targetDomain: 'example.com',
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      authorizedScopeGrant: auth.authorizedScopeGrant,
      lineage: tamperedLineage,
    });
    assert.strictEqual(resDnsx.status, 'preflight_denied');
    assert.strictEqual(resDnsx.reasonCode, 'lineage_mismatch');

    const resTlsx = await (adapters[2] as TlsxAdapter).inspectTls({
      targetHostOrUrl: 'example.com',
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      authorizedScopeGrant: auth.authorizedScopeGrant,
      lineage: tamperedLineage,
    });
    assert.strictEqual(resTlsx.status, 'preflight_denied');
    assert.strictEqual(resTlsx.reasonCode, 'lineage_mismatch');

    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned on lineage mismatch');
    console.log('    -> Lineage tuple mismatch safely aborted all adapter runs before execution');
  }

  // -------------------------------------------------------------------------
  // Assertion 7: Scope Boundary Out-of-Scope Denial Across Adapters
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 7: Scope boundary out-of-scope denial across adapters');
  {
    const auth = setupAuthorizedContext();
    const runner = new MockProcessRunner();

    const subfinder = new SubfinderAdapter(runner);
    const arjun = new ArjunAdapter(runner);
    const compositeUrl = new CompositeUrlDiscoveryAdapter(runner);

    const outOfScopeTarget = 'unauthorized-target.com';

    const resSub = await subfinder.discoverSubdomains({
      targetDomain: outOfScopeTarget,
      ...auth,
    });
    assert.strictEqual(resSub.status, 'preflight_denied');
    assert.strictEqual(resSub.reasonCode, 'target_out_of_scope');

    const resArjun = await arjun.discoverParameters({
      targetUrl: `https://${outOfScopeTarget}/search`,
      ...auth,
    });
    assert.strictEqual(resArjun.status, 'preflight_denied');
    assert.strictEqual(resArjun.reasonCode, 'target_out_of_scope');

    const resUrl = await compositeUrl.discoverUrls({
      targetUrlOrDomain: outOfScopeTarget,
      ...auth,
    });
    assert.strictEqual(resUrl.status, 'preflight_denied');
    assert.strictEqual(resUrl.reasonCode, 'target_out_of_scope');

    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for out-of-scope targets');
    console.log('    -> All out-of-scope targets safely denied with target_out_of_scope and 0 spawns');
  }

  // -------------------------------------------------------------------------
  // Assertion 8: Missing Capability Permission Denial Across Adapters
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 8: Missing capability permission denial across adapters');
  {
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
    const runner = new MockProcessRunner();

    const httpx = new HttpxInspectionAdapter(runner);
    const ffuf = new FfufAdapter(runner);
    const tlsx = new TlsxAdapter(runner);

    const resHttpx = await httpx.inspectWeb({
      targetUrl: 'https://example.com',
      ...auth,
    });
    assert.strictEqual(resHttpx.status, 'preflight_denied');
    assert.strictEqual(resHttpx.reasonCode, 'missing_permission');

    const resFfuf = await ffuf.discoverContent({
      targetUrl: 'https://example.com',
      wordlistPath: 'wordlists/common.txt',
      ...auth,
    });
    assert.strictEqual(resFfuf.status, 'preflight_denied');
    assert.strictEqual(resFfuf.reasonCode, 'missing_permission');

    const resTlsx = await tlsx.inspectTls({
      targetHostOrUrl: 'example.com',
      ...auth,
    });
    assert.strictEqual(resTlsx.status, 'preflight_denied');
    assert.strictEqual(resTlsx.reasonCode, 'missing_permission');

    assert.strictEqual(runner.calls.length, 0, 'Zero child processes spawned for denied permissions');
    console.log('    -> Missing capability permissions safely rejected with missing_permission and 0 spawns');
  }

  console.log('\n[✔] ALL MILESTONE F1 UNIFIED ADAPTER PREFLIGHT SMOKE ASSERTIONS PASSED SUCCESSFULLY.');
}

runMilestoneF1SmokeTests().catch((err) => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
