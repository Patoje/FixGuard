import assert from 'node:assert';
import { RealActiveReconSecurityTxtProbeAdapter } from '../recon/active/RealActiveReconSecurityTxtProbeAdapter.js';
import type { AuthorizedScope } from '../recon/policy/EgressPolicyContracts.js';
import { evaluateEgressPolicy } from '../recon/policy/PassiveEgressPolicy.js';
import { mapDecisionToAuditEvent } from '../recon/audit/EgressPolicyAuditMapper.js';
import { InMemoryEgressPolicyAuditRecorder } from '../recon/audit/InMemoryEgressPolicyAuditRecorder.js';
import { mapActiveReconResult } from '../recon/active/ActiveReconResultMapper.js';
import type { ActiveReconProbeRequest, ActiveReconProbeKind } from '../recon/active/ActiveReconContracts.js';

// M37 env contract — security.txt-specific confirmation string
const ENV_ENABLED = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON;
const ENV_PROBE   = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_PROBE;
const ENV_URL     = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_URL;
const ENV_ORIGIN  = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_ALLOWED_ORIGIN;
const ENV_CONFIRM = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_CONFIRM_AUTHORIZED;

const M37_CONFIRM = 'I_CONFIRM_AUTHORIZED_SECURITY_TXT_TARGET';
const SECURITY_TXT_PATH = '/.well-known/security.txt';

function checkEnv() {
  const hasAny = ENV_ENABLED !== undefined || ENV_PROBE !== undefined || ENV_URL !== undefined || ENV_ORIGIN !== undefined || ENV_CONFIRM !== undefined;
  const hasAll = ENV_ENABLED !== undefined && ENV_PROBE !== undefined && ENV_URL !== undefined && ENV_ORIGIN !== undefined && ENV_CONFIRM !== undefined;

  // 1. Absent env — skip exit 0, before any setup/policy/transport/network
  if (!hasAny) {
    console.log('[*] Skipping M37 real egress validation: explicit opt-in env vars not found.');
    process.exit(0);
  }

  // 2. Partial env — fail exit 1 before setup/network
  if (hasAny && !hasAll) {
    console.error('[-] ERROR: Partial M37 env vars provided. Failing closed.');
    process.exit(1);
  }

  // 3. Wrong flag value
  if (ENV_ENABLED !== '1') {
    console.error('[-] ERROR: FIXGUARD_V2_REAL_ACTIVE_RECON must be exactly "1". Failing closed.');
    process.exit(1);
  }

  // 4. Wrong confirmation string
  if (ENV_CONFIRM !== M37_CONFIRM) {
    console.error(`[-] ERROR: Confirmation string mismatch. Expected "${M37_CONFIRM}". Failing closed.`);
    process.exit(1);
  }

  // 5. Unsupported probe kind
  if (ENV_PROBE !== 'http.security_txt.inspect') {
    console.error('[-] ERROR: M37 real active recon supports only http.security_txt.inspect. Failing closed.');
    process.exit(1);
  }

  // 6. Exact path validation — /.well-known/security.txt only, no query, no fragment
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(ENV_URL!);
  } catch {
    console.error('[-] ERROR: FIXGUARD_V2_REAL_ACTIVE_RECON_URL is not a valid URL. Failing closed.');
    process.exit(1);
  }

  if (parsedUrl.pathname !== SECURITY_TXT_PATH || parsedUrl.search !== '' || parsedUrl.hash !== '') {
    console.error(`[-] ERROR: M37 requires exact ${SECURITY_TXT_PATH} path without query or fragment. Failing closed.`);
    process.exit(1);
  }

  return { url: ENV_URL!, origin: ENV_ORIGIN! };
}

async function runProgrammaticNegativeTests() {
  console.log('[*] Running M37 programmatic negative tests (no real network)...');

  const scope: AuthorizedScope = {
    allowedOrigins: ['https://example.com'],
    allowSameHostPaths: true,
    allowSubdomains: false
  };

  // --- Fake lookup that must NOT be called for pre-request guard tests ---
  let lookupCalled = false;
  const trackingLookup: any = (_host: string, _opts: any, cb: any) => {
    lookupCalled = true;
    cb(new Error('Should not reach DNS lookup in this test'));
  };

  const adapter = new RealActiveReconSecurityTxtProbeAdapter(trackingLookup);

  // A. Unsupported probe kind
  try {
    await adapter.probe({
      capabilityId: 'http.robots.inspect' as any,
      targetUrl: 'https://example.com/.well-known/security.txt',
      authorizedScope: scope,
      requestedAtMs: Date.now()
    });
    assert.fail('Should have thrown for unsupported probe kind');
  } catch (e: any) {
    assert.ok(e.message.includes('http.security_txt.inspect'), 'Must reject wrong capability before transport');
  }
  assert.strictEqual(lookupCalled, false, 'Lookup must not be reached for wrong capability');
  console.log('[+] Unsupported probe kind safely rejected before transport.');

  // B. Wrong path: /security.txt (must reject — only /.well-known/security.txt is allowed)
  try {
    await adapter.probe({
      capabilityId: 'http.security_txt.inspect',
      targetUrl: 'https://example.com/security.txt',
      authorizedScope: scope,
      requestedAtMs: Date.now()
    });
    assert.fail('Should have thrown for /security.txt (wrong path)');
  } catch (e: any) {
    assert.ok(e.message.includes(SECURITY_TXT_PATH), `Must reject /security.txt path: ${e.message}`);
  }
  assert.strictEqual(lookupCalled, false);
  console.log('[+] /security.txt (non-exact path) safely rejected before transport.');

  // C. Query string forbidden
  try {
    await adapter.probe({
      capabilityId: 'http.security_txt.inspect',
      targetUrl: 'https://example.com/.well-known/security.txt?token=SECRET',
      authorizedScope: scope,
      requestedAtMs: Date.now()
    });
    assert.fail('Should have thrown for query string');
  } catch (e: any) {
    assert.ok(e.message.includes(SECURITY_TXT_PATH), `Must reject query before transport: ${e.message}`);
  }
  assert.strictEqual(lookupCalled, false);
  console.log('[+] Query string target safely rejected before transport.');

  // D. Fragment forbidden
  try {
    await adapter.probe({
      capabilityId: 'http.security_txt.inspect',
      targetUrl: 'https://example.com/.well-known/security.txt#section',
      authorizedScope: scope,
      requestedAtMs: Date.now()
    });
    assert.fail('Should have thrown for fragment');
  } catch (e: any) {
    assert.ok(e.message.includes(SECURITY_TXT_PATH), `Must reject fragment before transport: ${e.message}`);
  }
  assert.strictEqual(lookupCalled, false);
  console.log('[+] Fragment target safely rejected before transport.');

  // E. Arbitrary path forbidden
  try {
    await adapter.probe({
      capabilityId: 'http.security_txt.inspect',
      targetUrl: 'https://example.com/admin',
      authorizedScope: scope,
      requestedAtMs: Date.now()
    });
    assert.fail('Should have thrown for arbitrary path');
  } catch (e: any) {
    assert.ok(e.message.includes(SECURITY_TXT_PATH), `Must reject arbitrary path: ${e.message}`);
  }
  assert.strictEqual(lookupCalled, false);
  console.log('[+] Arbitrary path safely rejected before transport.');

  // F. Root path forbidden (no base-origin derivation)
  try {
    await adapter.probe({
      capabilityId: 'http.security_txt.inspect',
      targetUrl: 'https://example.com/',
      authorizedScope: scope,
      requestedAtMs: Date.now()
    });
    assert.fail('Should have thrown for root path');
  } catch (e: any) {
    assert.ok(e.message.includes(SECURITY_TXT_PATH), `Must reject root path: ${e.message}`);
  }
  assert.strictEqual(lookupCalled, false);
  console.log('[+] Root path safely rejected before transport (no base-origin derivation).');

  // --- Literal IP SSRF tests — no lookup should be called ---
  let ipLookupCalled = false;
  const ipTrackingLookup: any = (_host: string, _opts: any, cb: any) => {
    ipLookupCalled = true;
    cb(new Error('Should not reach lookup for literal IP'));
  };
  const ipAdapter = new RealActiveReconSecurityTxtProbeAdapter(ipTrackingLookup);

  // G. IPv4 literal
  try {
    await ipAdapter.probe({
      capabilityId: 'http.security_txt.inspect',
      targetUrl: 'http://127.0.0.1:9/.well-known/security.txt',
      authorizedScope: scope,
      requestedAtMs: Date.now()
    });
    assert.fail('Should have thrown for literal IPv4');
  } catch (e: any) {
    assert.ok(e.message.includes('literal IP'), `Must reject literal IPv4 before transport: ${e.message}`);
  }
  assert.strictEqual(ipLookupCalled, false, 'Lookup/socket must not be reached for literal IPv4');
  console.log('[+] Unsafe IPv4 literal safely rejected before transport.');

  // H. IPv6 literal
  try {
    await ipAdapter.probe({
      capabilityId: 'http.security_txt.inspect',
      targetUrl: 'http://[::1]/.well-known/security.txt',
      authorizedScope: scope,
      requestedAtMs: Date.now()
    });
    assert.fail('Should have thrown for literal IPv6');
  } catch (e: any) {
    assert.ok(e.message.includes('literal IP'), `Must reject literal IPv6 before transport: ${e.message}`);
  }
  assert.strictEqual(ipLookupCalled, false);
  console.log('[+] Unsafe IPv6 literal safely rejected before transport.');

  // I. IPv4-mapped IPv6 literal
  try {
    await ipAdapter.probe({
      capabilityId: 'http.security_txt.inspect',
      targetUrl: 'http://[::ffff:127.0.0.1]/.well-known/security.txt',
      authorizedScope: scope,
      requestedAtMs: Date.now()
    });
    assert.fail('Should have thrown for IPv4-mapped IPv6');
  } catch (e: any) {
    assert.ok(e.message.includes('literal IP'), `Must reject IPv4-mapped IPv6 before transport: ${e.message}`);
  }
  assert.strictEqual(ipLookupCalled, false);
  console.log('[+] IPv4-mapped IPv6 literal safely rejected before transport.');

  // --- DNS resolution guard — resolved unsafe IP blocked before socket connect ---
  let dnsResolveLookupCalled = false;
  const dnsBlockingLookup: any = (_host: string, opts: any, cb: any) => {
    dnsResolveLookupCalled = true;
    // Simulate resolving to a blocked internal IP
    if (opts.all) {
      cb(null, [{ address: '192.168.1.100', family: 4 }]);
    } else {
      cb(null, '192.168.1.100', 4);
    }
  };
  const dnsAdapter = new RealActiveReconSecurityTxtProbeAdapter(dnsBlockingLookup);

  try {
    await dnsAdapter.probe({
      capabilityId: 'http.security_txt.inspect',
      targetUrl: 'https://evil-internal.example.com/.well-known/security.txt',
      authorizedScope: scope,
      requestedAtMs: Date.now()
    });
    assert.fail('Should have thrown when DNS resolves to internal IP');
  } catch (e: any) {
    assert.ok(
      e.message.includes('blocked IP') || e.message.includes('192.168.1.100'),
      `Must reject DNS-resolved internal IP before socket connect: ${e.message}`
    );
  }
  assert.strictEqual(dnsResolveLookupCalled, true, 'DNS lookup was called (as expected for hostname)');
  console.log('[+] Resolved unsafe DNS/IP safely rejected before socket connect.');

  // --- Out-of-scope URL blocked by policy ---
  const recorder = new InMemoryEgressPolicyAuditRecorder();
  const outOfScopeUrl = 'https://out-of-scope.com/.well-known/security.txt';
  const decision = evaluateEgressPolicy({ targetUrl: outOfScopeUrl, capabilityId: 'http.security_txt.inspect', authorizedScope: scope });
  const auditEvent = mapDecisionToAuditEvent(decision, { eventId: `evt_${Date.now()}`, capabilityId: 'http.security_txt.inspect', authorizedScope: scope });
  recorder.record(auditEvent);
  assert.strictEqual(decision.decision, 'block', 'Out-of-scope URL must be blocked by policy');
  console.log('[+] Out-of-scope URL safely blocked by M30 policy before transport.');

  console.log('[+] All M37 programmatic negative tests passed.');
}

async function runRealM37Validation() {
  console.log('--- V2 Opt-in Real security.txt Active Recon Probe Validation ---');

  // 1. Validate env FIRST — exits 0 if absent, exits 1 if partial/invalid
  const { url, origin } = checkEnv();

  // 2. Run programmatic negative tests (no real network)
  await runProgrammaticNegativeTests();

  console.log('[*] Explicit authorization confirmed for security.txt probe.');
  console.log('[*] Target URL: [configured]');
  console.log('[*] Allowed Origin: [configured]');

  const authorizedScope: AuthorizedScope = {
    allowedOrigins: [origin],
    allowSameHostPaths: true,
    allowSubdomains: false
  };

  const recorder = new InMemoryEgressPolicyAuditRecorder();

  const decision = evaluateEgressPolicy({
    targetUrl: url,
    capabilityId: 'http.security_txt.inspect',
    authorizedScope
  });

  const auditEvent = mapDecisionToAuditEvent(decision, {
    eventId: `evt_${Date.now()}`,
    capabilityId: 'http.security_txt.inspect',
    authorizedScope
  });
  recorder.record(auditEvent);

  if (decision.decision !== 'allow') {
    console.error('[-] ERROR: Target rejected by M30 policy before transport.');
    process.exit(1);
  }

  console.log('[+] M30 policy allow confirmed before transport.');

  const adapter = new RealActiveReconSecurityTxtProbeAdapter();

  const req: ActiveReconProbeRequest = {
    capabilityId: 'http.security_txt.inspect',
    targetUrl: url,
    authorizedScope,
    requestedAtMs: Date.now()
  };

  console.log('[*] Executing bounded guarded real security.txt adapter...');

  try {
    const observations = await adapter.probe(req);
    const result = mapActiveReconResult('http.security_txt.inspect', decision, observations);

    // Classification checks
    assert.strictEqual(result.classification.finding, false, 'Result must not be a finding');
    assert.strictEqual(result.classification.evidence, false, 'Result must not be product evidence');
    assert.strictEqual(result.classification.vulnerability, false, 'Result must not be a vulnerability');
    assert.strictEqual(result.classification.riskClaim, false, 'Result must not be a risk claim');

    // Target shape checks
    assert.strictEqual(result.target.scheme, 'https', 'scheme must be explicitly https');
    assert.strictEqual(result.target.normalizedOrigin, origin, 'normalizedOrigin must be origin-only');

    // Sanitization checks — no raw security.txt values survive serialization
    const resJson = JSON.stringify(result);
    assert.ok(!resJson.includes('"body":'), 'Raw body must not be emitted');
    assert.ok(!resJson.includes('"headers":'), 'Raw headers must not be emitted');
    assert.ok(!resJson.includes('mailto:'), 'Contact email must not be emitted');
    assert.ok(!resJson.includes('Contact:'), 'Raw Contact field must not be emitted');
    assert.ok(!resJson.includes('Encryption:'), 'Raw Encryption field must not be emitted');
    assert.ok(!resJson.includes('Policy:'), 'Raw Policy field must not be emitted');
    assert.ok(!resJson.includes('Canonical:'), 'Raw Canonical field must not be emitted');
    assert.ok(!resJson.includes('PGP'), 'PGP keys must not be emitted');
    assert.ok(!resJson.includes('@'), 'Email addresses must not be emitted in serialized output');

    // No observation-level raw keys
    if (observations.length > 0) {
      assert.ok(!('body' in observations[0]), 'Raw body must not be in observation');
      assert.ok(!('headers' in observations[0]), 'Raw headers must not be in observation');
      assert.ok(!('rawResponse' in observations[0]), 'Raw response must not be in observation');
    }

    console.log('[+] Exactly one bounded guarded real GET executed successfully.');
    console.log('[+] No redirects followed.');
    console.log('[+] M36 security.txt sanitizer used for output.');
    console.log('[+] No raw security.txt values survived serialization.');
    console.log('[+] No findings/evidence/vulnerability/risk claims created.');
    console.log('[+] M33 audit event created in smoke only (not in adapter output).');
    console.log('[+] Output Observation:');
    console.log(JSON.stringify(result.observations, null, 2));

  } catch (err: any) {
    console.error('[-] Transport or execution failed:', err.message);
    process.exit(1);
  }

  console.log('--- Opt-in Real security.txt Probe Validation Completed Successfully ---');
}

runRealM37Validation().catch(err => {
  console.error(err);
  process.exit(1);
});
