import assert from 'node:assert';
import process from 'node:process';
import { executeAndPersistActiveReconOriginRun } from '../recon/active/ActiveReconRunExecutionPersistenceService.js';
import { InMemoryActiveReconOriginRunRepository } from '../recon/active/InMemoryActiveReconOriginRunRepository.js';
import { RealActiveReconHttpProbeAdapter } from '../recon/active/RealActiveReconHttpProbeAdapter.js';
import { RealActiveReconSecurityTxtProbeAdapter } from '../recon/active/RealActiveReconSecurityTxtProbeAdapter.js';
import type { ActiveReconOriginRunRequest } from '../recon/active/ActiveReconOriginRunContracts.js';

async function runTests() {
  const flag = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_PERSISTED_RUN;
  const originStr = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_PERSISTED_RUN_ORIGIN;
  const probesStr = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_PERSISTED_RUN_PROBES;
  const confirm = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_PERSISTED_RUN_CONFIRM;

  if (!flag && !originStr && !probesStr && !confirm) {
    console.log('--- Real Active Recon Execution Persistence Smoke Skipped ---');
    console.log('Reason: All DB env vars absent.');
    process.exit(0);
  }

  if (flag !== '1' || confirm !== 'I_CONFIRM_AUTHORIZED_ACTIVE_RECON_PERSISTED_RUN_TARGET') {
    console.error('Invalid M42 real execution persistence environment.');
    process.exit(1);
  }

  if (!originStr) {
    console.error('Invalid or unsafe origin.');
    process.exit(1);
  }

  try {
    const url = new URL(originStr);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      console.error('Invalid origin scheme');
      process.exit(1);
    }
    if (url.username !== '' || url.password !== '') {
      console.error('Invalid origin credentials');
      process.exit(1);
    }
    if (url.pathname !== '/' && url.pathname !== '') {
      console.error('Invalid origin path');
      process.exit(1);
    }
    if (url.search !== '') {
      console.error('Invalid origin search');
      process.exit(1);
    }
    if (url.hash !== '') {
      console.error('Invalid origin hash');
      process.exit(1);
    }
  } catch {
    console.error('Invalid origin URL');
    process.exit(1);
  }

  const requestedProbes = (probesStr || '').split(',').map(s => s.trim());
  const allowedProbes = ['http.robots.inspect', 'http.security_txt.inspect'];
  for (const p of requestedProbes) {
    if (!allowedProbes.includes(p)) {
      console.error('Unsupported origin probe selection.');
      process.exit(1);
    }
  }

  console.log('--- V2 Real Active Recon Execution Persistence Smoke Test ---');

  // Construct real adapters ONLY after env validation
  const adapters = {
    robots: new RealActiveReconHttpProbeAdapter(),
    securityTxt: new RealActiveReconSecurityTxtProbeAdapter(),
  };

  const repository = new InMemoryActiveReconOriginRunRepository();

  const request: ActiveReconOriginRunRequest = {
    contractVersion: 'active-recon-origin-run/v0',
    requestId: 'real_m42_smoke_req_1',
    origin: originStr,
    authorization: { confirmed: true, scopeLabel: 'auth_real' },
    authorizedScope: { allowedOrigins: [originStr], allowSameHostPaths: true, allowSubdomains: false },
    probes: requestedProbes.map(p => ({ family: 'document', probe: p })) as any
  };

  const res = await executeAndPersistActiveReconOriginRun({
    request,
    adapters,
    repository
  });

  if (res.status === 'failed' && res.persistenceErrors.length > 0) {
    console.error('M42 real execution persistence failed.');
    process.exit(1);
  }

  assert.ok(res.persistedRecord);
  assert.strictEqual(res.reloadVerified, true);
  
  // Validation
  const serialized = JSON.stringify(res.persistedRecord);
  const forbidden = [
    'targetUrl', 'raw', 'headers', 'body', 'request', 'response', 'payload', 
    'cookie', 'authorization', 'password', 'api_key', 'token', 'secret', 
    'severity', 'impact', 'exploit', '"finding":true'
  ];
  for (const f of forbidden) {
    assert(!serialized.includes(`"${f}"`), `Found forbidden string in DB: ${f}`);
  }

  console.log('[+] Real M39 run executed, persisted via M40 into in-memory repo, reloaded safely.');
  console.log('[+] No raw body/headers/targetUrl/secret-bearing values persist.');
  console.log('[+] No findings/evidence/risk claims.');
  console.log('[+] No fake target evidence claim.');
  
  console.log('--- Real Active Recon Execution Persistence Smoke Completed Successfully ---');
}

runTests().catch(err => {
  console.error('M42 real execution persistence failed.');
  process.exit(1);
});
