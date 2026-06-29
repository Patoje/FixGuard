import assert from 'node:assert';
import { GuardedHttpHeaderInspectAdapter } from '../recon/passive/GuardedHttpHeaderInspectAdapter';
import { FakeHttpHeaderInspectTransport } from '../recon/passive/FakeHttpHeaderInspectTransport';
import type { CapabilityRequest } from '../core/ExecutionContracts';

async function runM31Smoke() {
  console.log('--- V2 Guarded HTTP Header Inspect Adapter Smoke Test ---');

  const fakeTransport = new FakeHttpHeaderInspectTransport();
  const authorizedScope = {
    allowedOrigins: ['https://example.com'],
    allowSameHostPaths: true,
    allowSubdomains: false
  };

  const adapter = new GuardedHttpHeaderInspectAdapter(fakeTransport, authorizedScope);

  // 1. Allowed policy invokes transport exactly once
  console.log('[*] Testing allowed target...');
  const allowReq: CapabilityRequest = {
    capability: 'http.header.inspect',
    target: { uri: 'https://example.com/safe/path' },
    config: {}
  };
  
  const allowEv = await adapter.execute(allowReq);
  assert.strictEqual(fakeTransport.lastRequestedUrl, 'https://example.com/safe/path', 'Transport must be called with normalized URL');
  assert.strictEqual(allowEv.findings.length, 0, 'Evidence must have findings: []');
  assert.strictEqual(allowEv.metadata.statusCode, 200);
  const headers = allowEv.metadata.headers as Record<string, string>;
  assert.strictEqual(headers['server'], 'FakeServer', 'Safe header is preserved');
  assert.strictEqual(headers['set-cookie'], '[REDACTED]', 'Set-Cookie is redacted');
  assert.strictEqual(headers['authorization'], '[REDACTED]', 'Authorization is redacted');
  assert.strictEqual(headers['x-api-key'], '[REDACTED]', 'x-api-key is redacted');
  assert.strictEqual(headers['PassWd'], '[REDACTED]', 'PassWd is redacted');
  assert.strictEqual(headers['location'], 'https://example.com/redirect?secret=%5BREDACTED%5D', 'Location query params are redacted safely');
  assert.ok(!('body' in allowEv.metadata), 'Response body must be absent');
  console.log('[+] Allowed target correctly fetched and evidence sanitized.');

  // 2. Blocked policy invokes transport zero times
  console.log('[*] Testing blocked target...');
  fakeTransport.lastRequestedUrl = undefined;
  const blockReq: CapabilityRequest = {
    capability: 'http.header.inspect',
    target: { uri: 'https://evil.com/path' },
    config: {}
  };

  try {
    await adapter.execute(blockReq);
    assert.fail('Should have thrown policy error');
  } catch (err: any) {
    assert.ok(err.message.includes('Policy enforcement failed'), 'Throws controlled policy error');
  }
  assert.strictEqual(fakeTransport.lastRequestedUrl, undefined, 'Transport must not be invoked for blocked target');
  console.log('[+] Blocked target correctly rejected before transport.');

  // 3. Candidate policy invokes transport zero times
  console.log('[*] Testing candidate target...');
  const candidateReq: CapabilityRequest = {
    capability: 'http.header.inspect',
    target: { uri: 'https://sub.example.com/path' },
    config: {}
  };

  try {
    await adapter.execute(candidateReq);
    assert.fail('Should have thrown policy error');
  } catch (err: any) {
    assert.ok(err.message.includes('Policy enforcement failed'), 'Throws controlled policy error');
  }
  assert.strictEqual(fakeTransport.lastRequestedUrl, undefined, 'Transport must not be invoked for candidate target');
  console.log('[+] Candidate target correctly rejected before transport.');

  // 4. Transport timeout creates controlled failure
  console.log('[*] Testing transport timeout...');
  fakeTransport.shouldFail = true;
  try {
    await adapter.execute(allowReq);
    assert.fail('Should have thrown transport error');
  } catch (err: any) {
    assert.ok(err.message.includes('Transport failed'), 'Throws controlled transport error');
  }
  console.log('[+] Timeout correctly propagated as controlled failure.');

  // 5. Real Transport IP Guard
  console.log('[*] Testing Real Transport DNS Guard (Network-free Localhost)...');
  const { RealHttpHeaderInspectTransport } = await import('../recon/passive/RealHttpHeaderInspectTransport');
  const realTransport = new RealHttpHeaderInspectTransport();
  try {
    await realTransport.execute('http://localhost:8080/test', 3000);
    assert.fail('Should have thrown DNS blocked error');
  } catch (err: any) {
    assert.ok(err.message.includes('DNS resolved to blocked IP'), 'Throws DNS blocked error on localhost');
  }
  console.log('[+] Real transport blocked resolved IP locally before connection path.');

  // 6. IPv6 Real Transport Guard using custom test lookup
  console.log('[*] Testing Real Transport IPv6 Guard via custom lookup injection...');
  const blockedIpv6Addresses = [
    // Loopback / unspecified
    '::1',
    // Link-local
    'fe80::1',
    // Unique-local
    'fc00::1',
    'fd00::1',
    // IPv4-mapped: dotted decimal
    '::ffff:127.0.0.1',
    // IPv4-mapped: compressed hex
    '::ffff:7f00:1',
    '::ffff:0a00:0001',
    '::ffff:ac10:0001',
    '::ffff:c0a8:0001',
    '::ffff:a9fe:a9fe',
    // IPv4-mapped: expanded hex (0:0:0:0:0:ffff:...)
    '0:0:0:0:0:ffff:7f00:1',
    '0:0:0:0:0:ffff:0a00:0001',
    '0:0:0:0:0:ffff:ac10:0001',
    '0:0:0:0:0:ffff:c0a8:0001',
    '0:0:0:0:0:ffff:a9fe:a9fe',
    // Bracketed compressed hex
    '[::ffff:7f00:1]',
    '[::ffff:0a00:0001]',
    '[::ffff:ac10:0001]',
    '[::ffff:c0a8:0001]',
    '[::ffff:a9fe:a9fe]',
    // Bracketed expanded hex
    '[0:0:0:0:0:ffff:7f00:1]',
    '[0:0:0:0:0:ffff:0a00:0001]',
    '[0:0:0:0:0:ffff:ac10:0001]',
    '[0:0:0:0:0:ffff:c0a8:0001]',
    '[0:0:0:0:0:ffff:a9fe:a9fe]'
  ];

  for (const ip of blockedIpv6Addresses) {
    const testLookup = (
      hostname: string,
      options: any,
      callback: (err: NodeJS.ErrnoException | null, address: string, family: number) => void
    ) => {
      // Simulate DNS resolving to the unsafe IPv6 address
      callback(null, ip, 6);
    };

    const ipv6Transport = new RealHttpHeaderInspectTransport(testLookup as any);
    try {
      await ipv6Transport.execute('https://example.com/test', 3000);
      assert.fail(`Should have thrown DNS blocked error for IPv6 ${ip}`);
    } catch (err: any) {
      assert.ok(
        err.message.includes('DNS resolved to blocked IP'),
        `Throws DNS blocked error for unbracketed IPv6: ${ip}`
      );
    }
  }
  console.log('[+] Real transport blocked unbracketed IPv6 addresses safely before connection path.');

  console.log('--- Smoke Test Completed Successfully ---');
}

runM31Smoke().catch(err => {
  console.error(err);
  process.exit(1);
});
