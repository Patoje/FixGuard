import assert from 'node:assert';
import { GuardedHttpHeaderInspectAdapter } from '../recon/passive/GuardedHttpHeaderInspectAdapter';
import { RealHttpHeaderInspectTransport } from '../recon/passive/RealHttpHeaderInspectTransport';
import type { CapabilityRequest } from '../core/ExecutionContracts';

// M32 requires exact env vars to perform a real network request.
const ENV_ENABLED = process.env.FIXGUARD_V2_REAL_HTTP_HEADER_INSPECT;
const ENV_URL = process.env.FIXGUARD_V2_REAL_HTTP_HEADER_INSPECT_URL;
const ENV_ORIGIN = process.env.FIXGUARD_V2_REAL_HTTP_HEADER_INSPECT_ALLOWED_ORIGIN;
const ENV_CONFIRM = process.env.FIXGUARD_V2_REAL_HTTP_HEADER_INSPECT_CONFIRM_AUTHORIZED;

function checkEnv() {
  const hasAny = ENV_ENABLED !== undefined || ENV_URL !== undefined || ENV_ORIGIN !== undefined || ENV_CONFIRM !== undefined;
  const hasAll = ENV_ENABLED !== undefined && ENV_URL !== undefined && ENV_ORIGIN !== undefined && ENV_CONFIRM !== undefined;

  if (!hasAny) {
    console.log('[*] Skipping M32 real egress validation: explicit opt-in env vars not found.');
    process.exit(0);
  }

  if (hasAny && !hasAll) {
    console.error('[-] ERROR: Partial M32 env vars provided. All 4 required vars must be set to run real egress.');
    process.exit(1);
  }

  if (ENV_ENABLED !== '1') {
    console.error('[-] ERROR: FIXGUARD_V2_REAL_HTTP_HEADER_INSPECT must be exactly "1".');
    process.exit(1);
  }

  if (ENV_CONFIRM !== 'I_CONFIRM_AUTHORIZED_TEST_TARGET') {
    console.error('[-] ERROR: Confirmation string mismatch.');
    process.exit(1);
  }

  return { url: ENV_URL!, origin: ENV_ORIGIN! };
}

async function runRealM32Validation() {
  console.log('--- V2 Opt-in Real HTTP Header Inspect Validation ---');
  
  const { url, origin } = checkEnv();

  console.log('[*] Explicit authorization confirmed.');
  console.log(`[*] Target URL: [configured]`);
  console.log(`[*] Allowed Origin: [configured]`);

  const authorizedScope = {
    allowedOrigins: [origin],
    allowSameHostPaths: true,
    allowSubdomains: false
  };

  const transport = new RealHttpHeaderInspectTransport();
  const adapter = new GuardedHttpHeaderInspectAdapter(transport, authorizedScope);

  const req: CapabilityRequest = {
    capability: 'http.header.inspect',
    target: { uri: url },
    config: {}
  };

  console.log('[*] Executing bounded guarded adapter...');
  
  try {
    const evidence = await adapter.execute(req);
    
    assert.strictEqual(evidence.findings.length, 0, 'Evidence must not create findings');
    assert.ok(!('body' in evidence.metadata), 'Response body must not be read or persisted');
    
    const headers = evidence.metadata.headers as Record<string, string>;
    const setCookie = headers['set-cookie'];
    assert.ok(setCookie === undefined || setCookie === '[REDACTED]', 'set-cookie must be omitted or redacted');
    
    // Check if redacting works if they were present
    if (headers['authorization']) assert.strictEqual(headers['authorization'], '[REDACTED]', 'authorization must be redacted if present');

    console.log('[+] Target correctly fetched and evidence sanitized.');
    console.log('[+] Output Observation Metadata:');
    console.log(JSON.stringify(evidence.metadata, null, 2));

  } catch (err: any) {
    if (err.message.includes('Policy enforcement failed')) {
      console.error('[-] ERROR: Target rejected by policy before transport.');
      console.error(err.message);
      process.exit(1);
    }
    console.error('[-] Transport or execution failed:', err);
    process.exit(1);
  }

  console.log('--- Opt-in Real Validation Completed Successfully ---');
}

runRealM32Validation().catch(err => {
  console.error(err);
  process.exit(1);
});
