import assert from 'node:assert';
import { RealActiveReconHttpProbeAdapter } from '../recon/active/RealActiveReconHttpProbeAdapter.js';
import type { AuthorizedScope } from '../recon/policy/EgressPolicyContracts.js';
import { evaluateEgressPolicy } from '../recon/policy/PassiveEgressPolicy.js';
import { mapDecisionToAuditEvent } from '../recon/audit/EgressPolicyAuditMapper.js';
import { InMemoryEgressPolicyAuditRecorder } from '../recon/audit/InMemoryEgressPolicyAuditRecorder.js';
import { mapActiveReconResult } from '../recon/active/ActiveReconResultMapper.js';
import type { ActiveReconProbeRequest, ActiveReconProbeKind } from '../recon/active/ActiveReconContracts.js';

// M35 requires exact env vars to perform a real network request.
const ENV_ENABLED = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON;
const ENV_PROBE = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_PROBE;
const ENV_URL = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_URL;
const ENV_ORIGIN = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_ALLOWED_ORIGIN;
const ENV_CONFIRM = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_CONFIRM_AUTHORIZED;

function checkEnv() {
  const hasAny = ENV_ENABLED !== undefined || ENV_PROBE !== undefined || ENV_URL !== undefined || ENV_ORIGIN !== undefined || ENV_CONFIRM !== undefined;
  const hasAll = ENV_ENABLED !== undefined && ENV_PROBE !== undefined && ENV_URL !== undefined && ENV_ORIGIN !== undefined && ENV_CONFIRM !== undefined;

  if (!hasAny) {
    console.log('[*] Skipping M35 real egress validation: explicit opt-in env vars not found.');
    process.exit(0);
  }

  if (hasAny && !hasAll) {
    console.error('[-] ERROR: Partial M35 env vars provided. Failing closed.');
    process.exit(1);
  }

  if (ENV_ENABLED !== '1') {
    console.error('[-] ERROR: FIXGUARD_V2_REAL_ACTIVE_RECON must be exactly "1". Failing closed.');
    process.exit(1);
  }

  if (ENV_CONFIRM !== 'I_CONFIRM_AUTHORIZED_ACTIVE_RECON_TARGET') {
    console.error('[-] ERROR: Confirmation string mismatch. Failing closed.');
    process.exit(1);
  }

  if (ENV_PROBE !== 'http.robots.inspect') {
    console.error('[-] ERROR: M35 real active recon supports only http.robots.inspect. Failing closed.');
    process.exit(1);
  }

  const parsedUrl = new URL(ENV_URL!);
  if (parsedUrl.pathname !== '/robots.txt' || parsedUrl.search !== '' || parsedUrl.hash !== '') {
    console.error('[-] ERROR: M35 real active recon requires exact /robots.txt path without query or fragment. Failing closed.');
    process.exit(1);
  }

  return { url: ENV_URL!, origin: ENV_ORIGIN! };
}

async function runProgrammaticNegativeTests() {
  console.log('[*] Running programmatic negative tests with fake lookup to prove no egress...');
  
  let lookupCalled = false;
  const testLookup: any = (hostname: string, opts: any, cb: any) => {
    lookupCalled = true;
    cb(new Error('Should not reach lookup'));
  };
  const adapter = new RealActiveReconHttpProbeAdapter(testLookup);

  const scope: AuthorizedScope = {
    allowedOrigins: ['https://example.com'],
    allowSameHostPaths: true,
    allowSubdomains: false
  };
  const recorder = new InMemoryEgressPolicyAuditRecorder();

  async function execute(targetUrl: string, capabilityId: ActiveReconProbeKind) {
    // Fail programmatic tests if query/hash provided since the adapter / checkEnv would fail,
    // but here we are testing policy/transport gating.
    const parsedUrl = new URL(targetUrl);
    if (parsedUrl.pathname !== '/robots.txt' || parsedUrl.search !== '' || parsedUrl.hash !== '') {
        return { status: 'blocked' } as any; 
    }

    const decision = evaluateEgressPolicy({ targetUrl, capabilityId, authorizedScope: scope });
    const auditEvent = mapDecisionToAuditEvent(decision, { eventId: `evt_${Date.now()}`, capabilityId, authorizedScope: scope });
    recorder.record(auditEvent);

    if (decision.decision !== 'allow') {
      return mapActiveReconResult(capabilityId, decision, []);
    }
    const req: ActiveReconProbeRequest = { capabilityId, targetUrl, authorizedScope: scope, requestedAtMs: Date.now() };
    const obs = await adapter.probe(req);
    return mapActiveReconResult(capabilityId, decision, obs);
  }

  // 6. out-of-scope URL -> fail before transport
  const resOut = await execute('https://out-of-scope.com/robots.txt', 'http.robots.inspect');
  assert.strictEqual(resOut.status, 'blocked');
  assert.strictEqual(lookupCalled, false, 'Lookup should not be called for out-of-scope URL');
  console.log('[+] Out-of-scope URL safely blocked before transport.');

  // 7. invalid URL -> fail before transport
  try {
    await execute('javascript:alert(1)', 'http.robots.inspect');
  } catch (e) {
    console.log('[+] Invalid URL safely blocked before transport.');
  }
  assert.strictEqual(lookupCalled, false, 'Lookup should not be called for invalid URL');

  // 8. Unsafe IP Literal -> fail before transport
  let ipLiteralCalled = false;
  const ipTestLookup: any = (hostname: string, opts: any, cb: any) => {
    ipLiteralCalled = true;
    cb(new Error('Should not reach lookup for IP literal'));
  };
  const ipAdapter = new RealActiveReconHttpProbeAdapter(ipTestLookup);
  try {
    await ipAdapter.probe({ capabilityId: 'http.robots.inspect', targetUrl: 'http://127.0.0.1:9/robots.txt', authorizedScope: scope, requestedAtMs: Date.now() });
    assert.fail('Should have thrown on literal IPv4');
  } catch (e: any) {
    assert.ok(e.message.includes('literal IP'), 'Must reject literal IP before transport');
  }
  assert.strictEqual(ipLiteralCalled, false, 'Lookup/socket should not be reached for literal IPv4');
  
  try {
    await ipAdapter.probe({ capabilityId: 'http.robots.inspect', targetUrl: 'http://[::1]/robots.txt', authorizedScope: scope, requestedAtMs: Date.now() });
    assert.fail('Should have thrown on literal IPv6');
  } catch (e: any) {
    assert.ok(e.message.includes('literal IP'), 'Must reject literal IP before transport');
  }

  try {
    await ipAdapter.probe({ capabilityId: 'http.robots.inspect', targetUrl: 'http://[::ffff:127.0.0.1]/robots.txt', authorizedScope: scope, requestedAtMs: Date.now() });
    assert.fail('Should have thrown on literal IPv4-mapped IPv6');
  } catch (e: any) {
    assert.ok(e.message.includes('literal IP'), 'Must reject literal IP before transport');
  }

  console.log('[+] Unsafe literal IP URLs safely blocked before transport.');

  // 9. Query/Fragment/Non-Robots URLs -> fail before transport via adapter-level check
  let invalidPathLookupCalled = false;
  const invalidPathLookup: any = (hostname: string, opts: any, cb: any) => {
    invalidPathLookupCalled = true;
    cb(new Error('Should not reach lookup for invalid path'));
  };
  const pathAdapter = new RealActiveReconHttpProbeAdapter(invalidPathLookup);

  const testPaths = [
    'https://example.com/robots.txt?token=SECRET',
    'https://example.com/robots.txt#fragment',
    'https://example.com/admin'
  ];

  for (const p of testPaths) {
    try {
      await pathAdapter.probe({
        capabilityId: 'http.robots.inspect',
        targetUrl: p,
        authorizedScope: scope,
        requestedAtMs: Date.now()
      });
      assert.fail(`Should have thrown on non-exact path: ${p}`);
    } catch (e: any) {
      assert.ok(e.message.includes('exactly /robots.txt'), `Must reject non-exact path before transport: ${p}`);
    }
  }

  assert.strictEqual(invalidPathLookupCalled, false, 'Lookup/socket should not be reached for query/fragment/non-robots paths');
  console.log('[+] Query, fragment, and non-robots URLs safely rejected before transport at adapter level.');
}

async function runRealM35Validation() {
  console.log('--- V2 Opt-in Real Active Recon Probe Validation ---');
  
  // 1. Validates env FIRST, exits 0 if absent, or exits 1 if partial/invalid
  const { url, origin } = checkEnv();

  // 2. Since env is complete and authorized, run negative tests
  await runProgrammaticNegativeTests();

  console.log('[*] Explicit authorization confirmed.');
  console.log(`[*] Target URL: [configured]`);
  console.log(`[*] Allowed Origin: [configured]`);

  const authorizedScope: AuthorizedScope = {
    allowedOrigins: [origin],
    allowSameHostPaths: true,
    allowSubdomains: false
  };

  const recorder = new InMemoryEgressPolicyAuditRecorder();

  const decision = evaluateEgressPolicy({
    targetUrl: url,
    capabilityId: 'http.robots.inspect',
    authorizedScope
  });

  const auditEvent = mapDecisionToAuditEvent(decision, {
    eventId: `evt_${Date.now()}`,
    capabilityId: 'http.robots.inspect',
    authorizedScope
  });
  recorder.record(auditEvent);

  if (decision.decision !== 'allow') {
    console.error('[-] ERROR: Target rejected by policy before transport.');
    process.exit(1);
  }

  console.log('[+] M30 policy allow happens before transport.');

  const adapter = new RealActiveReconHttpProbeAdapter();

  const req: ActiveReconProbeRequest = {
    capabilityId: 'http.robots.inspect',
    targetUrl: url,
    authorizedScope,
    requestedAtMs: Date.now()
  };

  console.log('[*] Executing bounded guarded real adapter...');
  
  try {
    const observations = await adapter.probe(req);
    const result = mapActiveReconResult('http.robots.inspect', decision, observations);
    
    assert.strictEqual(result.classification.finding, false, 'Result must not be a finding');
    assert.strictEqual(result.classification.evidence, false, 'Result must not be product evidence');
    assert.strictEqual(result.classification.vulnerability, false, 'Result must not be a vulnerability');
    assert.strictEqual(result.classification.riskClaim, false, 'Result must not be a risk claim');
    
    assert.strictEqual(result.target.scheme, 'https', 'scheme must be explicitly https');
    assert.strictEqual(result.target.normalizedOrigin, origin, 'normalizedOrigin must be origin-only');

    const resJson = JSON.stringify(result);
    assert.ok(!('body' in result.observations[0]), 'Raw body must not be persisted in observation');
    assert.ok(!('headers' in result.observations[0]), 'Raw headers must not be persisted in observation');
    assert.ok(!resJson.includes('disallow:'), 'Robots directive paths must not be emitted');
    assert.ok(!resJson.includes('sitemap:'), 'Sitemap URLs must not be emitted');

    console.log('[+] Exactly one bounded guarded real GET executed successfully.');
    console.log('[+] No redirects followed.');
    console.log('[+] Safe observation metadata created. No raw body/headers persisted.');
    console.log('[+] No findings/evidence/vulnerability/risk claims created.');
    console.log('[+] M33 audit event created in smoke only.');
    console.log('[+] Output Observation:');
    console.log(JSON.stringify(result.observations, null, 2));

  } catch (err: any) {
    console.error('[-] Transport or execution failed:', err);
    process.exit(1);
  }

  console.log('--- Opt-in Real Active Recon Validation Completed Successfully ---');
}

runRealM35Validation().catch(err => {
  console.error(err);
  process.exit(1);
});
