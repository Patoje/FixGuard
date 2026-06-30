import assert from 'node:assert';
import { runActiveReconOriginProbes } from '../recon/active/ActiveReconOriginRunService.js';
import type { AuthorizedScope } from '../recon/policy/EgressPolicyContracts.js';
import type { SafeActiveReconObservation } from '../recon/active/ActiveReconContracts.js';
import type { ActiveReconOriginRunRequest } from '../recon/active/ActiveReconOriginRunContracts.js';

console.log('--- V2 Active Recon Origin Run DB-Free Smoke Test ---');

const scope: AuthorizedScope = {
  allowedOrigins: ['https://example.com'],
  allowSameHostPaths: true,
  allowSubdomains: false,
};

const baseAuth = { confirmed: true as const, scopeLabel: 'test' };

// Fake adapters
function makeFakeRobotsAdapter() {
  let callCount = 0;
  return {
    get callCount() { return callCount; },
    async probe() {
      callCount++;
      return [{
        kind: 'robots_metadata' as const,
        safeSummary: 'Fake robots',
        confidence: 'high' as const,
        metadata: { reachable: true, hasDisallowDirective: true, recognizedDirectiveLineCount: 2 }
      }] as SafeActiveReconObservation[];
    }
  };
}

function makeFakeSecurityTxtAdapter() {
  let callCount = 0;
  return {
    get callCount() { return callCount; },
    async probe() {
      callCount++;
      return [{
        kind: 'security_txt_metadata' as const,
        safeSummary: 'Fake security.txt',
        confidence: 'high' as const,
        metadata: { reachable: true, hasContactField: true, recognizedFieldLineCount: 3 }
      }] as SafeActiveReconObservation[];
    }
  };
}

async function runTests() {
  // 1. authorization.confirmed !== true fails closed
  {
    const robotsSpy = makeFakeRobotsAdapter();
    const result = await runActiveReconOriginProbes(
      {
        contractVersion: 'active-recon-origin-run/v0',
        authorization: { confirmed: false } as any,
        authorizedScope: scope,
        origin: 'https://example.com',
        probes: [{ family: 'document', probe: 'http.robots.inspect' }],
      },
      { robots: robotsSpy }
    );
    assert.strictEqual(robotsSpy.callCount, 0);
    assert.strictEqual(result.status, 'failed');
    assert.strictEqual(result.probes[0].error?.code, 'authorization_not_confirmed');
    console.log('[+] false authorization fails closed');
  }

  // 2. missing authorization fails closed
  {
    const result = await runActiveReconOriginProbes(
      {
        contractVersion: 'active-recon-origin-run/v0',
        authorization: undefined as any,
        authorizedScope: scope,
        origin: 'https://example.com',
        probes: [{ family: 'document', probe: 'http.robots.inspect' }],
      },
      {}
    );
    assert.strictEqual(result.status, 'failed');
    assert.strictEqual(result.probes[0].error?.code, 'authorization_not_confirmed');
    console.log('[+] missing authorization fails closed');
  }

  // 4, 5, 6, 7: Origin Validation
  const badOrigins = [
    'not-a-url',
    'ftp://example.com',
    'https://example.com/path',
    'https://example.com?query=1',
    'https://example.com#hash',
    'https://user:pass@example.com',
    'https://127.0.0.1', // unsafe literal IP
    'https://[::1]',
    'https://169.254.169.254'
  ];

  for (const badOrigin of badOrigins) {
    const result = await runActiveReconOriginProbes(
      {
        contractVersion: 'active-recon-origin-run/v0',
        authorization: baseAuth,
        authorizedScope: scope,
        origin: badOrigin,
        probes: [{ family: 'document', probe: 'http.robots.inspect' }],
      },
      {}
    );
    assert.strictEqual(result.status, 'failed', `Origin ${badOrigin} should fail`);
    assert.strictEqual(result.probes[0].error?.code, 'invalid_origin');
  }
  console.log('[+] invalid, credentials, path/query/fragment, unsupported schemes, and unsafe IP origins fail closed');

  // 8. unsupported probe kinds
  {
    const result = await runActiveReconOriginProbes(
      {
        contractVersion: 'active-recon-origin-run/v0',
        authorization: baseAuth,
        authorizedScope: scope,
        origin: 'https://example.com',
        probes: [{ family: 'document', probe: 'http.evil.inspect?token=SECRET' as any }],
      },
      {}
    );
    assert.strictEqual(result.probes[0].error?.code, 'unsupported_probe');
    assert.strictEqual(result.probes[0].safeKind, 'unknown');
    const resStr = JSON.stringify(result);
    assert.ok(!resStr.includes('http.evil.inspect'), 'raw unsupported kind must not be echoed');
    assert.ok(!resStr.includes('SECRET'), 'secret in probe name must not be echoed');
    console.log('[+] unsupported probe kinds are sanitized and not echoed');
  }

  // 9. empty probe set
  {
    const result = await runActiveReconOriginProbes(
      {
        contractVersion: 'active-recon-origin-run/v0',
        authorization: baseAuth,
        authorizedScope: scope,
        origin: 'https://example.com',
        probes: [],
      },
      {}
    );
    assert.strictEqual(result.status, 'failed');
    assert.strictEqual(result.runErrors[0]?.code, 'empty_probe_set');
    console.log('[+] empty probe set fails closed and returns explicit empty_probe_set error');
  }

  // 10. duplicate probes
  {
    const robotsSpy = makeFakeRobotsAdapter();
    const result = await runActiveReconOriginProbes(
      {
        contractVersion: 'active-recon-origin-run/v0',
        authorization: baseAuth,
        authorizedScope: scope,
        origin: 'https://example.com',
        probes: [
          { family: 'document', probe: 'http.robots.inspect' },
          { family: 'document', probe: 'http.robots.inspect' },
        ],
      },
      { robots: robotsSpy }
    );
    assert.strictEqual(robotsSpy.callCount, 1);
    assert.strictEqual(result.plannedProbeCount, 1);
    console.log('[+] duplicate probes are deduplicated safely');
  }

  // 11, 12, 13, 14, 15, 16, 17, 18, 20, 21. Valid run & exact targets
  {
    const robotsSpy = makeFakeRobotsAdapter();
    const securitySpy = makeFakeSecurityTxtAdapter();
    const result = await runActiveReconOriginProbes(
      {
        contractVersion: 'active-recon-origin-run/v0',
        authorization: baseAuth,
        authorizedScope: scope,
        origin: 'https://example.com',
        probes: [
          { family: 'document', probe: 'http.robots.inspect' },
          { family: 'document', probe: 'http.security_txt.inspect' },
        ],
      },
      { robots: robotsSpy, securityTxt: securitySpy }
    );
    
    assert.strictEqual(robotsSpy.callCount, 1);
    assert.strictEqual(securitySpy.callCount, 1);
    assert.strictEqual(result.status, 'completed');
    assert.strictEqual(result.completedProbeCount, 2);
    
    // Assert target paths internally translated correctly in M38 output mapping
    // M38 result outputs only normalizedOrigin and safeDisplayUrl, not raw targetUrl
    for (const p of result.probes) {
      assert.ok(p.target.safeDisplayUrl?.includes('robots.txt') || p.target.safeDisplayUrl?.includes('security.txt'));
      assert.ok(!p.target.safeDisplayUrl?.includes('security.txt') || p.target.safeDisplayUrl?.includes('.well-known/security.txt'), 'Must use /.well-known/security.txt');
    }
    console.log('[+] valid origin generates exact targets, invokes exact adapters via M38 runner');
  }

  // 19. blocked decisions don't invoke adapter
  {
    const robotsSpy = makeFakeRobotsAdapter();
    const result = await runActiveReconOriginProbes(
      {
        contractVersion: 'active-recon-origin-run/v0',
        authorization: baseAuth,
        authorizedScope: scope,
        origin: 'https://blocked-site.com',
        probes: [{ family: 'document', probe: 'http.robots.inspect' }],
      },
      { robots: robotsSpy }
    );
    assert.strictEqual(robotsSpy.callCount, 0);
    assert.strictEqual(result.status, 'failed'); // since 0 completed
    assert.strictEqual(result.probes[0].status, 'blocked');
    console.log('[+] blocked/candidate policy decisions still do not invoke adapters');
  }

  // 22. no raw ID survives
  {
    const result = await runActiveReconOriginProbes(
      {
        contractVersion: 'active-recon-origin-run/v0',
        requestId: 'SECRET_REQUEST_ID',
        authorization: baseAuth,
        authorizedScope: scope,
        origin: 'https://example.com',
        probes: [{ family: 'document', probe: 'http.robots.inspect' }],
      },
      { robots: makeFakeRobotsAdapter() }
    );
    const resStr = JSON.stringify(result);
    assert.ok(!resStr.includes('SECRET_REQUEST_ID'));
    assert.ok(result.runId.startsWith('origin_run_'));
    console.log('[+] no raw requestId/runId survives');
  }

  // 24. No findings/risk claims
  {
    const result = await runActiveReconOriginProbes(
      {
        contractVersion: 'active-recon-origin-run/v0',
        authorization: baseAuth,
        authorizedScope: scope,
        origin: 'https://example.com',
        probes: [{ family: 'document', probe: 'http.robots.inspect' }],
      },
      { robots: makeFakeRobotsAdapter() }
    );
    assert.strictEqual(result.classification.finding, false);
    assert.strictEqual(result.classification.evidence, false);
    assert.strictEqual(result.classification.riskClaim, false);
    console.log('[+] no findings/evidence/risk claims');
  }

  // 25. Fake outputs
  {
    const result = await runActiveReconOriginProbes(
      {
        contractVersion: 'active-recon-origin-run/v0',
        authorization: baseAuth,
        authorizedScope: scope,
        origin: 'https://example.com',
        probes: [{ family: 'document', probe: 'http.robots.inspect' }],
      },
      { robots: makeFakeRobotsAdapter() }
    );
    const obs = result.observations[0];
    assert.ok(!('rawBody' in obs));
    assert.ok(!('evidence' in obs));
    console.log('[+] fake outputs are not real target evidence');
  }

  console.log('--- V2 Active Recon Origin Run DB-Free Smoke Completed Successfully ---');
}

runTests().catch(err => {
  console.error(err);
  process.exit(1);
});
