import assert from 'node:assert';

import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
const validDecision = (establishVerifiedAuthorizationDecision({ contractVersion: 'fixguard-verified-authorization-decision/v0', kind: 'establish_verified_authorization_decision_request', assessmentId: 'assess_1', scanId: 'scan_1', authorizationDecisionId: 'dec_1', authorizedActor: { actorId: 'sys', actorType: 'human' }, decision: 'authorized', decidedAt: '2026-07-01T12:00:00.000Z', scopeGrant: { contractVersion: 'fixguard-authorized-scope-policy/v0', kind: 'authorized_scope_policy', grantId: 'grant_1', scanId: 'scan_1', subject: { targetKind: 'origin', normalizedOrigin: 'https://example.com' }, permissionSet: { endpointDiscovery: true, activeValidation: false }, boundaries: { allowedOrigins: ['https://example.com'], allowedMethods: ['GET'], allowedPathPatterns: [{ pathTemplate: '/' }] }, constraints: { allowCredentialUse: false }, classification: { executesNetwork: false } } } as any, '2026-07-01T12:00:00.000Z') as any).decision;
import { runActiveReconOriginProbes } from '../recon/active/ActiveReconOriginRunService.js';
import { isInternalOrSsrfTarget } from '../recon/policy/PassiveEgressPolicy.js';
import { RealActiveReconHttpProbeAdapter } from '../recon/active/RealActiveReconHttpProbeAdapter.js';
import { RealActiveReconSecurityTxtProbeAdapter } from '../recon/active/RealActiveReconSecurityTxtProbeAdapter.js';
import type { ActiveReconDocumentProbeAdapters } from '../recon/active/ActiveReconDocumentProbeRunner.js';
import type { AuthorizedScope } from '../recon/policy/EgressPolicyContracts.js';
import type { ActiveReconOriginProbeSelection } from '../recon/active/ActiveReconOriginRunContracts.js';

console.log('--- V2 Opt-in Real Active Recon Origin Run Validation ---');

async function runRealOriginSmoke() {
  const ENV_ENABLED = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_ORIGIN_RUN;
  const ENV_ORIGIN = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_ORIGIN;
  const ENV_PROBES = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_ORIGIN_RUN_PROBES;
  const ENV_CONFIRM = process.env.FIXGUARD_V2_REAL_ACTIVE_RECON_CONFIRM_AUTHORIZED;

  const hasAny = ENV_ENABLED !== undefined || ENV_ORIGIN !== undefined || ENV_PROBES !== undefined || ENV_CONFIRM !== undefined;
  const hasAll = ENV_ENABLED !== undefined && ENV_ORIGIN !== undefined && ENV_PROBES !== undefined && ENV_CONFIRM !== undefined;

  if (!hasAny) {
    console.log('[*] Skipping M39 real egress validation: explicit opt-in env vars not found.');
    process.exit(0);
  }

  if (hasAny && !hasAll) {
    console.error('[-] Invalid M39 real origin run environment.');
    process.exit(1);
  }

  if (ENV_ENABLED !== '1') {
    console.error('[-] Invalid M39 real origin run environment.');
    process.exit(1);
  }

  if (ENV_CONFIRM !== 'I_CONFIRM_AUTHORIZED_ACTIVE_RECON_ORIGIN_RUN_TARGET') {
    console.error('[-] Authorization confirmation is required.');
    process.exit(1);
  }

  // Pre-validate Origin
  let parsedOrigin: URL;
  try {
    parsedOrigin = new URL(ENV_ORIGIN!);
    if (parsedOrigin.protocol !== 'http:' && parsedOrigin.protocol !== 'https:') throw new Error();
    if (parsedOrigin.pathname !== '' && parsedOrigin.pathname !== '/') throw new Error();
    if (parsedOrigin.search || parsedOrigin.hash) throw new Error();
    if (parsedOrigin.username || parsedOrigin.password) throw new Error();
    if (isInternalOrSsrfTarget(parsedOrigin.hostname)) throw new Error();
  } catch {
    console.error('[-] Invalid or unsafe origin.');
    process.exit(1);
  }

  const requestedProbesStr = ENV_PROBES!.split(',').map(p => p.trim()).filter(Boolean);
  const probes: ActiveReconOriginProbeSelection[] = [];

  for (const p of requestedProbesStr) {
    if (p === 'http.robots.inspect' || p === 'http.security_txt.inspect') {
      probes.push({ family: 'document', probe: p });
    } else {
      console.error('[-] Unsupported origin probe selection.');
      process.exit(1);
    }
  }

  const authorizedScope: AuthorizedScope = {
    allowedOrigins: [ENV_ORIGIN!], // Only testing the exact origin
    allowSameHostPaths: true,
    allowSubdomains: false,
  };

  const adapters: ActiveReconDocumentProbeAdapters = {};
  if (requestedProbesStr.includes('http.robots.inspect')) {
    adapters.robots = new RealActiveReconHttpProbeAdapter();
  }
  if (requestedProbesStr.includes('http.security_txt.inspect')) {
    adapters.securityTxt = new RealActiveReconSecurityTxtProbeAdapter();
  }

  console.log('[*] Executing real combined origin run...');

  const result = await runActiveReconOriginProbes(
    {
      contractVersion: 'active-recon-origin-run/v1',
      evaluatedAt: '2026-07-01T12:00:00.000Z',
      verifiedAuthorizationDecision: validDecision,
      origin: ENV_ORIGIN!,
      probes,
    },
    adapters
  );

  if (result.status === 'failed' || result.runErrors.length > 0) {
    console.error('[-] M39 real origin run failed.');
    process.exit(1);
  }

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

  // Print results
  for (const probe of result.probes) {
    console.log(`[+] Probe ${probe.safeProbeIndex} (${probe.safeKind}): status=${probe.status}, observations=${probe.observations.length}`);
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

  console.log('--- V2 Opt-in Real Active Recon Origin Run Completed ---');
}

runRealOriginSmoke().catch(err => {
  console.error(err);
  process.exit(1);
});
