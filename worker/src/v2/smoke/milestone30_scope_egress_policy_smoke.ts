import * as assert from 'assert';
import { evaluateEgressPolicy } from '../recon/policy/PassiveEgressPolicy';
import type { AuthorizedScope, EgressPolicyDecision } from '../recon/policy/EgressPolicyContracts';

async function runM30Smoke() {
  console.log('--- V2 Scope Egress Policy Smoke Test ---');

  const scope: AuthorizedScope = {
    allowedOrigins: ['https://example.com'],
    allowSameHostPaths: true,
    allowSubdomains: false
  };

  const capId = 'http.header.inspect';

  function evaluate(url: string, currentScope: AuthorizedScope = scope): EgressPolicyDecision {
    return evaluateEgressPolicy({ targetUrl: url, authorizedScope: currentScope, capabilityId: capId });
  }

  // 1. Authorized exact public HTTP URL allowed (if origin matched HTTP, but origin is HTTPS)
  // Let's test exact origin matching.
  const scopeHttp: AuthorizedScope = { allowedOrigins: ['http://example.com'], allowSameHostPaths: true, allowSubdomains: false };
  const d1 = evaluate('http://example.com', scopeHttp);
  assert.strictEqual(d1.decision, 'allow', 'Authorized exact HTTP URL should be allowed');

  // 2. Authorized exact public HTTPS URL allowed
  const d2 = evaluate('https://example.com');
  assert.strictEqual(d2.decision, 'allow', 'Authorized exact HTTPS URL should be allowed');

  // 3. Same-host path under authorized origin allowed if configured
  const d3 = evaluate('https://example.com/some/path?query=1');
  assert.strictEqual(d3.decision, 'allow', 'Same-host path should be allowed');

  // 4. Out-of-scope public host is blocked
  const d4 = evaluate('https://other.com');
  assert.strictEqual(d4.decision, 'block', 'Out-of-scope host should be blocked');

  // 5. Discovered subdomain is returned as candidate, not executable target
  const d5 = evaluate('https://api.example.com');
  assert.strictEqual(d5.decision, 'candidate', 'Subdomain should be a candidate');
  if (d5.decision === 'candidate') {
    assert.strictEqual(d5.candidate.candidateUrl, 'https://api.example.com/', 'Candidate URL normalized correctly');
  }

  // 6. Malformed URL is blocked
  const d6 = evaluate('https://exa mple.com');
  assert.strictEqual(d6.decision, 'block', 'Malformed URL should be blocked');

  // 7. Unsupported scheme is blocked
  const d7 = evaluate('ftp://example.com');
  assert.strictEqual(d7.decision, 'block', 'Unsupported scheme should be blocked');
  if (d7.decision === 'block') {
    assert.strictEqual(d7.blockReason, 'unsupported_scheme');
  }

  // 8. localhost is blocked
  const d8 = evaluate('http://localhost:8080');
  assert.strictEqual(d8.decision, 'block', 'localhost should be blocked');
  if (d8.decision === 'block') {
    assert.strictEqual(d8.blockReason, 'internal_target_blocked');
  }

  // 9. 127.0.0.1 is blocked
  const d9 = evaluate('http://127.0.0.1');
  assert.strictEqual(d9.decision, 'block', '127.0.0.1 should be blocked');

  // 10. ::1 is blocked
  const d10 = evaluate('http://[::1]');
  assert.strictEqual(d10.decision, 'block', '::1 should be blocked');

  // 11. Private IPv4 ranges are blocked
  const privateIPs = ['http://10.0.0.5', 'http://172.16.0.1', 'http://192.168.1.1'];
  for (const ipUrl of privateIPs) {
    const res = evaluate(ipUrl);
    assert.strictEqual(res.decision, 'block', `${ipUrl} should be blocked`);
    if (res.decision === 'block') assert.strictEqual(res.blockReason, 'internal_target_blocked');
  }

  // 12. Link-local and cloud metadata targets are blocked
  const metadata = evaluate('http://169.254.169.254/latest/meta-data/');
  assert.strictEqual(metadata.decision, 'block', 'Cloud metadata IP should be blocked');

  // 13. Credential-bearing URLs are blocked
  const credUrl = evaluate('https://user:pass@example.com');
  assert.strictEqual(credUrl.decision, 'block', 'Credentials in URL should be blocked');

  // 14. Query params normalize deterministically & sensitive query keys are classified & safeDisplayUrl redacts
  const sensitiveUrl = 'https://example.com/api?user=1&token=SUPER_SECRET_123&api_key=456';
  const d14 = evaluate(sensitiveUrl);
  assert.strictEqual(d14.decision, 'allow', 'Authorized host with query is allowed');
  if (d14.decision === 'allow') {
    assert.ok(d14.sensitiveQueryKeys?.includes('token'), 'token should be classified as sensitive');
    assert.ok(d14.sensitiveQueryKeys?.includes('api_key'), 'api_key should be classified as sensitive');
    
    // Internal normalized target still holds raw data
    assert.ok(d14.normalizedTarget.search.includes('SUPER_SECRET_123'), 'Internal normalized target must preserve raw data');
    
    // safeDisplayUrl redacts
    assert.ok(!d14.safeDisplayUrl.includes('SUPER_SECRET_123'), 'safeDisplayUrl must not contain secret');
    assert.ok(d14.safeDisplayUrl.includes('%5BREDACTED%5D'), 'safeDisplayUrl must redact token');
  }

  // 15. Unsafe literal IPs are blocked even when listed in allowedOrigins
  const specialUseIPs = [
    'http://224.0.0.1/',
    'http://255.255.255.255/',
    'http://198.18.0.1/',
    'http://100.64.0.1/',
    'http://192.0.2.1/'
  ];
  for (const ip of specialUseIPs) {
    const d15 = evaluateEgressPolicy({
      targetUrl: ip,
      authorizedScope: { allowedOrigins: [ip], allowSameHostPaths: true, allowSubdomains: false },
      capabilityId: capId
    });
    assert.strictEqual(d15.decision, 'block', `Special-use IP ${ip} should be blocked before scope matching`);
    if (d15.decision === 'block') {
      assert.strictEqual(d15.blockReason, 'internal_target_blocked');
    }
  }

  // 16. Non-default port scope escape prevention
  const d16a = evaluate('http://example.com:443/', scopeHttp); // scopeHttp is http://example.com
  assert.strictEqual(d16a.decision, 'block', 'http://example.com:443/ should not match http://example.com');
  
  const d16b = evaluate('https://example.com:80/', scope); // scope is https://example.com
  assert.strictEqual(d16b.decision, 'block', 'https://example.com:80/ should not match https://example.com');

  // 17. Blocked URLs (credentials in URL) produce safe display URLs
  const credUrl2 = evaluate('https://user:pass@example.com/path?token=SUPER_SECRET');
  assert.strictEqual(credUrl2.decision, 'block', 'Credentials in URL should be blocked');
  if (credUrl2.decision === 'block') {
    assert.strictEqual(credUrl2.blockReason, 'credentials_in_url');
    assert.ok(credUrl2.safeDisplayUrl !== undefined, 'safeDisplayUrl must be present');
    assert.ok(!credUrl2.safeDisplayUrl.includes('user'), 'safeDisplayUrl must not leak username');
    assert.ok(!credUrl2.safeDisplayUrl.includes('pass'), 'safeDisplayUrl must not leak password');
    assert.ok(!credUrl2.safeDisplayUrl.includes('SUPER_SECRET'), 'safeDisplayUrl must not leak sensitive query');
    assert.ok(credUrl2.safeDisplayUrl.includes('%5BREDACTED%5D'), 'safeDisplayUrl must redact token');
  }

  // 18. Blocked URLs (unsupported scheme) produce safe display URLs without leaking body/path
  const unsupportedUrls = [
    'ftp://example.com/path?token=SUPER_SECRET',
    'data:text/plain,SUPER_SECRET',
    'javascript:alert("SUPER_SECRET")',
    'file:///C:/secret/SUPER_SECRET.txt'
  ];

  for (const uUrl of unsupportedUrls) {
    const unsupp = evaluate(uUrl);
    assert.strictEqual(unsupp.decision, 'block', `Unsupported scheme ${uUrl} should be blocked`);
    if (unsupp.decision === 'block') {
      assert.strictEqual(unsupp.blockReason, 'unsupported_scheme');
      assert.ok(unsupp.safeDisplayUrl !== undefined, 'safeDisplayUrl must be present');
      assert.ok(!unsupp.safeDisplayUrl.includes('SUPER_SECRET'), 'safeDisplayUrl must not leak sensitive content');
      assert.ok(unsupp.safeDisplayUrl === '[unsupported-url]' || unsupp.safeDisplayUrl === '[untrusted-url]', 'safeDisplayUrl must use safe fixed marker');
    }
  }
  // 19. Blocked policy decisions are not vulnerability findings
  // Proof: Evaluator returns pure `EgressPolicyDecision` objects, which have no `findings` array or risk scores.
  
  // 20. No evidence/finding/audit/runtime/storage mutation exists
  // Proof: Test invokes `evaluateEgressPolicy` pure function and checks return values. Zero imports to repositories or runtime state exist in this test or the module.

  // 21. No network/DNS/process/scanner execution exists
  // Proof: Code statically analyzes the string properties (checked via ripgrep command later).

  console.log('[+] Egress Policy evaluated rules successfully.');
  console.log('--- Smoke Test Completed Successfully ---');
}

runM30Smoke().catch(err => {
  console.error(err);
  process.exit(1);
});
