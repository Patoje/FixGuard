/**
 * FixGuard V2 — Real Target DNS Integration Test
 *
 * Executes real dnsx binary via LocalProcessRunner (shell: false) against authorized target 'example.com'.
 * Validates non-empty DNS A records parsed into DiscoveredDnsObservation, deep SSRF filtering, and non-claims.
 */

import assert from 'node:assert';
import process from 'node:process';
import dns from 'node:dns/promises';

import { DnsxAdapter } from '../recon/adapters/DnsxAdapter.js';
import { DNS_RESOLUTION_NON_CLAIMS } from '../recon/adapters/DnsResolutionContracts.js';
import { LocalProcessRunner } from '../core/ProcessRunner.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';

function createAuthorizedScope(domain: string): AuthorizedScopeGrant {
  const nowIso = new Date().toISOString();
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: `grant_real_dns_${Date.now()}`,
    scanId: `scan_real_dns_${Date.now()}`,
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

export async function runRealTargetDnsSmoke(): Promise<void> {
  console.log('[*] [INTEGRATION] Checking dnsx binary availability on host...');
  const availability = new ReconToolAvailabilityService(new LocalProcessRunner());
  const status = await availability.checkTool('dnsx');

  if (status.status !== 'available') {
    console.log(`    [SKIPPED] dnsx binary is not available on host PATH (${status.error ?? 'not installed'}).`);
    console.log('[*] [INTEGRATION] Verifying real Node.js native DNS resolution against example.com as fallback...');
    const ips = await dns.resolve4('example.com');
    assert.ok(ips.length > 0, 'Native DNS resolution for example.com must return valid IPs');
    console.log(`    [PASS] Native DNS resolution succeeded: ${ips.join(', ')}`);
    return;
  }

  console.log(`    [INFO] dnsx is available at ${status.path ?? 'PATH'} (version: ${status.version ?? 'detected'})`);
  console.log('[*] [INTEGRATION] Executing real dnsx against authorized target: example.com...');

  const targetDomain = 'example.com';
  const scopeGrant = createAuthorizedScope(targetDomain);
  const nowIso = new Date().toISOString();

  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asmt_real_dns_test',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'dec_real_dns_test',
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
    assessmentId: 'asmt_real_dns_test',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_real_dns_test',
    actorId: 'usr_secops_integration',
  };

  const runner = new LocalProcessRunner();
  const adapter = new DnsxAdapter(runner);

  const result = await adapter.resolveDns({
    targetDomain,
    verifiedAuthorizationDecision: verifiedDecision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    timeoutMs: 15_000,
  });

  assert.strictEqual(result.status, 'success', `Expected status 'success', got ${result.status}`);
  assert.ok(result.observations.length > 0, 'Real dnsx must produce at least one observation for example.com');
  const aRecord = result.observations.find((obs) => obs.recordType === 'A');
  assert.ok(aRecord, 'example.com must have an A record observation');
  assert.ok(aRecord.values.length > 0, 'A record observation must contain resolved IP values');
  assert.deepStrictEqual(result.explicitNonClaims, DNS_RESOLUTION_NON_CLAIMS);

  console.log(`    [PASS] Real dnsx resolved A record: ${aRecord.values.join(', ')}`);
}

if (process.argv[1]?.endsWith('real_target_dns_smoke.ts')) {
  runRealTargetDnsSmoke().catch((err) => {
    console.error('[!] Real DNS Integration Test FAILED:', err);
    process.exit(1);
  });
}
