import assert from 'node:assert';

import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
const validDecision = (establishVerifiedAuthorizationDecision({ contractVersion: 'fixguard-verified-authorization-decision/v0', kind: 'establish_verified_authorization_decision_request', assessmentId: 'assess_1', scanId: 'scan_1', authorizationDecisionId: 'dec_1', authorizedActor: { actorId: 'sys', actorType: 'human' }, decision: 'authorized', decidedAt: '2026-07-01T12:00:00.000Z', scopeGrant: { contractVersion: 'fixguard-authorized-scope-policy/v0', kind: 'authorized_scope_policy', grantId: 'grant_1', scanId: 'scan_1', subject: { targetKind: 'origin', normalizedOrigin: 'https://example.com' }, permissionSet: { endpointDiscovery: true, activeValidation: false }, boundaries: { allowedOrigins: ['https://example.com'], allowedMethods: ['GET'], allowedPathPatterns: [{ pathTemplate: '/' }] }, constraints: { allowCredentialUse: false }, classification: { executesNetwork: false } } } as any, '2026-07-01T12:00:00.000Z') as any).decision;
import {
  runActiveReconDocumentProbes,
  type ActiveReconDocumentProbeAdapters,
} from '../recon/active/ActiveReconDocumentProbeRunner.js';
import { RealActiveReconHttpProbeAdapter } from '../recon/active/RealActiveReconHttpProbeAdapter.js';
import { RealActiveReconSecurityTxtProbeAdapter } from '../recon/active/RealActiveReconSecurityTxtProbeAdapter.js';
import type { AuthorizedScope } from '../recon/policy/EgressPolicyContracts.js';

// M38 real combined opt-in env contract
const ENV_ENABLED   = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_RUN;
const ENV_PROBES    = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_RUN_PROBES;
const ENV_ROBOTS_URL   = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_ROBOTS_URL;
const ENV_SECURITY_URL = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_SECURITY_TXT_URL;
const ENV_ORIGIN    = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_ALLOWED_ORIGIN;
const ENV_CONFIRM   = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_CONFIRM_AUTHORIZED;

const EXPECTED_CONFIRM = 'I_CONFIRM_AUTHORIZED_ACTIVE_RECON_RUN_TARGET';
const SUPPORTED_PROBES = new Set(['http.robots.inspect', 'http.security_txt.inspect']);

function checkEnv() {
  const hasAny = [ENV_ENABLED, ENV_PROBES, ENV_ROBOTS_URL, ENV_SECURITY_URL, ENV_ORIGIN, ENV_CONFIRM]
    .some(v => v !== undefined);
  const hasAll = [ENV_ENABLED, ENV_PROBES, ENV_ROBOTS_URL, ENV_SECURITY_URL, ENV_ORIGIN, ENV_CONFIRM]
    .every(v => v !== undefined);

  // 1. All absent — skip exit 0
  if (!hasAny) {
    console.log('[*] Skipping M38 real combined opt-in validation: explicit opt-in env vars not found.');
    process.exit(0);
  }

  // 2. Partial — fail before setup/network
  if (hasAny && !hasAll) {
    console.error('[-] ERROR: Partial M38 real run env vars provided. Failing closed.');
    process.exit(1);
  }

  // 3. Wrong flag value
  if (ENV_ENABLED !== '1') {
    console.error('[-] ERROR: FIXGUARD_V2_REAL_ACTIVE_RECON_RUN must be exactly "1". Failing closed.');
    process.exit(1);
  }

  // 4. Wrong confirmation
  if (ENV_CONFIRM !== EXPECTED_CONFIRM) {
    console.error(`[-] ERROR: Confirmation mismatch. Expected "${EXPECTED_CONFIRM}". Failing closed.`);
    process.exit(1);
  }

  // 5. Validate requested probes
  const requestedProbes = (ENV_PROBES ?? '').split(',').map(p => p.trim()).filter(Boolean);
  for (const p of requestedProbes) {
    if (!SUPPORTED_PROBES.has(p)) {
      console.error(`[-] ERROR: Unsupported probe kind "${p}". Failing closed.`);
      process.exit(1);
    }
  }
  if (requestedProbes.length === 0) {
    console.error('[-] ERROR: No probe kinds specified. Failing closed.');
    process.exit(1);
  }

  // 6. Validate URLs: must have correct paths
  if (requestedProbes.includes('http.robots.inspect')) {
    try {
      const u = new URL(ENV_ROBOTS_URL!);
      if (u.pathname !== '/robots.txt' || u.search !== '' || u.hash !== '') {
        console.error('[-] ERROR: FIXGUARD_V2_REAL_ACTIVE_RECON_ROBOTS_URL must be exactly /robots.txt with no query or fragment. Failing closed.');
        process.exit(1);
      }
    } catch {
      console.error('[-] ERROR: FIXGUARD_V2_REAL_ACTIVE_RECON_ROBOTS_URL is not a valid URL. Failing closed.');
      process.exit(1);
    }
  }

  if (requestedProbes.includes('http.security_txt.inspect')) {
    try {
      const u = new URL(ENV_SECURITY_URL!);
      if (u.pathname !== '/.well-known/security.txt' || u.search !== '' || u.hash !== '') {
        console.error('[-] ERROR: FIXGUARD_V2_REAL_ACTIVE_RECON_SECURITY_TXT_URL must be exactly /.well-known/security.txt. Failing closed.');
        process.exit(1);
      }
    } catch {
      console.error('[-] ERROR: FIXGUARD_V2_REAL_ACTIVE_RECON_SECURITY_TXT_URL is not a valid URL. Failing closed.');
      process.exit(1);
    }
  }

  return {
    requestedProbes,
    robotsUrl: ENV_ROBOTS_URL!,
    securityTxtUrl: ENV_SECURITY_URL!,
    origin: ENV_ORIGIN!,
  };
}

async function runRealM38Validation() {
  console.log('--- V2 Opt-in Real Active Recon Document Probe Runner Validation ---');

  const { requestedProbes, robotsUrl, securityTxtUrl, origin } = checkEnv();

  console.log(`[*] Authorization confirmed for real combined run.`);
  console.log(`[*] Requested probes: ${requestedProbes.join(', ')}`);
  console.log(`[*] Allowed origin: [configured]`);

  const verifiedAuthorizationDecision: AuthorizedScope = {
    allowedOrigins: [origin],
    allowSameHostPaths: true,
    allowSubdomains: false,
  };

  // Explicitly inject real adapters — runner does not instantiate them
  const adapters: ActiveReconDocumentProbeAdapters = {};
  if (requestedProbes.includes('http.robots.inspect')) {
    adapters.robots = new RealActiveReconHttpProbeAdapter();
  }
  if (requestedProbes.includes('http.security_txt.inspect')) {
    adapters.securityTxt = new RealActiveReconSecurityTxtProbeAdapter();
  }

  const probes = [];
  if (requestedProbes.includes('http.robots.inspect')) {
    probes.push({ probeId: 'robots-1', kind: 'http.robots.inspect' as const, targetUrl: robotsUrl });
  }
  if (requestedProbes.includes('http.security_txt.inspect')) {
    probes.push({ probeId: 'security-txt-1', kind: 'http.security_txt.inspect' as const, targetUrl: securityTxtUrl });
  }

  console.log('[*] Executing real combined document probe run...');

  const result = await runActiveReconDocumentProbes(
    {
      contractVersion: 'active-recon-document-probe-run/v1',
      evaluatedAt: '2026-07-01T12:00:00.000Z',
      verifiedAuthorizationDecision: validDecision,
      probes,
    },
    adapters
  );

  // Classification flags
  assert.strictEqual(result.classification.finding, false, 'Must not be a finding');
  assert.strictEqual(result.classification.evidence, false, 'Must not be evidence');
  assert.strictEqual(result.classification.vulnerability, false, 'Must not be a vulnerability');
  assert.strictEqual(result.classification.riskClaim, false, 'Must not be a risk claim');

  // Result must not contain raw values
  const resultJson = JSON.stringify(result);
  assert.ok(!resultJson.includes('"body":'), 'Raw body must not leak');
  assert.ok(!resultJson.includes('"headers":'), 'Raw headers must not leak');
  assert.ok(!resultJson.includes('"request":'), 'Raw request must not leak');
  assert.ok(!resultJson.includes('"response":'), 'Raw response must not leak');

  // Probe results
  for (const probe of result.probes) {
    console.log(`[+] Probe ${probe.safeProbeIndex} (${probe.safeKind}): status=${probe.status}, policyDecision=${probe.policyDecision}, observations=${probe.observations.length}`);
    if (probe.error) {
      console.log(`    Error code: ${probe.error.code}`);
    }
    // No raw field values in observations
    for (const obs of probe.observations) {
      const obsJson = JSON.stringify(obs);
      assert.ok(!obsJson.includes('"body":'), `Obs must not have raw body in probe ${probe.safeProbeIndex}`);
      assert.ok(!obsJson.includes('"headers":'), `Obs must not have raw headers in probe ${probe.safeProbeIndex}`);
      assert.ok(!obsJson.includes('mailto:'), `Contact emails must not be in obs for probe ${probe.safeProbeIndex}`);
    }
  }

  console.log(`[+] Run completed: requested=${result.requestedProbeCount} completed=${result.completedProbeCount} blocked=${result.blockedProbeCount} failed=${result.failedProbeCount}`);
  console.log('[+] No raw bodies/headers/secrets survive serialization.');
  console.log('[+] No findings/evidence/vulnerability/risk claims created.');
  console.log('[+] Observations:');
  console.log(JSON.stringify(result.observations, null, 2));

  console.log('--- Opt-in Real Active Recon Document Probe Runner Validation Completed Successfully ---');
}

runRealM38Validation().catch(err => {
  console.error(err);
  process.exit(1);
});
