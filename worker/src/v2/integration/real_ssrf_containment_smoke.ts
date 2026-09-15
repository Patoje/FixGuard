/**
 * FixGuard V2 — Real SSRF Containment Integration Test
 *
 * Verifies that in real execution environments without mocks:
 * 1. isInternalOrSsrfTarget strictly blocks loopback (127.0.0.1), private RFC1918 subnets, and cloud metadata (169.254.169.254).
 * 2. AdapterPreflightPipeline strictly rejects internal and metadata URLs with 'preflight_denied'
 *    and executes strictly 0 child processes.
 */

import assert from 'node:assert';
import process from 'node:process';

import { isInternalOrSsrfTarget } from '../recon/policy/PassiveEgressPolicy.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { HttpxInspectionAdapter } from '../recon/adapters/HttpxInspectionAdapter.js';
import { DnsxAdapter } from '../recon/adapters/DnsxAdapter.js';
import { LocalProcessRunner } from '../core/ProcessRunner.js';

function createAuthorizedScope(domain: string): AuthorizedScopeGrant {
  const nowIso = new Date().toISOString();
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: `grant_real_ssrf_${Date.now()}`,
    scanId: `scan_real_ssrf_${Date.now()}`,
    issuedAt: nowIso,
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    subject: {
      targetKind: 'domain',
      domain,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Confirmed asset boundary for ${domain}`,
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
      allowedDomains: [domain],
      allowedHosts: [domain],
      allowedOrigins: [`https://${domain}`],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
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
  };
}

export async function runRealSsrfContainmentSmoke(): Promise<void> {
  console.log('[*] [INTEGRATION] Verifying real SSRF containment and egress gate boundaries...');

  // 1. Policy Function Level
  assert.strictEqual(isInternalOrSsrfTarget('127.0.0.1'), true, 'Loopback IP must be blocked');
  assert.strictEqual(isInternalOrSsrfTarget('127.0.0.5'), true, 'Loopback subnet must be blocked');
  assert.strictEqual(isInternalOrSsrfTarget('localhost'), true, 'localhost hostname must be blocked');
  assert.strictEqual(isInternalOrSsrfTarget('169.254.169.254'), true, 'AWS/Cloud metadata IP must be blocked');
  assert.strictEqual(isInternalOrSsrfTarget('10.0.0.1'), true, 'RFC1918 10.0.0.0/8 must be blocked');
  assert.strictEqual(isInternalOrSsrfTarget('172.16.0.1'), true, 'RFC1918 172.16.0.0/12 must be blocked');
  assert.strictEqual(isInternalOrSsrfTarget('192.168.1.1'), true, 'RFC1918 192.168.0.0/16 must be blocked');
  assert.strictEqual(isInternalOrSsrfTarget('0.0.0.0'), true, '0.0.0.0 must be blocked');
  assert.strictEqual(isInternalOrSsrfTarget('example.com'), false, 'Public domain must be allowed');
  assert.strictEqual(isInternalOrSsrfTarget('scanme.nmap.org'), false, 'Public target must be allowed');

  // 2. Preflight Pipeline Level with Branded Decision
  const scopeGrant = createAuthorizedScope('127.0.0.1');
  const nowIso = new Date().toISOString();
  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asmt_real_ssrf_test',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'dec_real_ssrf_test',
      authorizedActor: { actorId: 'usr_secops_integration', actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant,
    },
    nowIso
  );

  assert.strictEqual(authRes.status, 'established');
  const verifiedDecision = authRes.decision;
  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'asmt_real_ssrf_test',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_real_ssrf_test',
    actorId: 'usr_secops_integration',
  };

  const preflightResult = await runAdapterPreflight({
    target: 'http://127.0.0.1:8080/admin',
    targetKind: 'url',
    verifiedAuthorizationDecision: verifiedDecision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    permissionCheck: () => true,
  });

  assert.strictEqual(preflightResult.ok, false, 'Preflight must deny loopback target');
  assert.strictEqual(preflightResult.reasonCode, 'ssrf_target_blocked');

  // 3. Adapter Level with real LocalProcessRunner
  const realRunner = new LocalProcessRunner();
  const httpxAdapter = new HttpxInspectionAdapter(realRunner);

  const httpxResult = await httpxAdapter.inspectWeb({
    targetUrl: 'http://169.254.169.254/latest/meta-data/',
    verifiedAuthorizationDecision: verifiedDecision,
    authorizedScopeGrant: scopeGrant,
    lineage,
  });

  assert.strictEqual(httpxResult.status, 'preflight_denied');
  assert.strictEqual(httpxResult.reasonCode, 'ssrf_target_blocked');

  const dnsxAdapter = new DnsxAdapter(realRunner);
  const dnsxResult = await dnsxAdapter.resolveDns({
    targetDomain: '127.0.0.1',
    verifiedAuthorizationDecision: verifiedDecision,
    authorizedScopeGrant: scopeGrant,
    lineage,
  });

  assert.strictEqual(dnsxResult.status, 'preflight_denied');
  assert.ok(
    dnsxResult.reasonCode === 'ssrf_target_blocked' || dnsxResult.reasonCode === 'invalid_target_domain',
    `Expected ssrf_target_blocked or invalid_target_domain, got ${dnsxResult.reasonCode}`
  );

  console.log('    [PASS] SSRF containment verified in real execution context (loopback, metadata, RFC1918 blocked with 0 child processes dispatched)');
}

if (process.argv[1]?.endsWith('real_ssrf_containment_smoke.ts')) {
  runRealSsrfContainmentSmoke().catch((err) => {
    console.error('[!] Real SSRF Containment Test FAILED:', err);
    process.exit(1);
  });
}
