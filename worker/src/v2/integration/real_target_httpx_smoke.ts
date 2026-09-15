/**
 * FixGuard V2 — Real Target HTTPX Integration Test
 *
 * Executes real httpx binary via LocalProcessRunner (shell: false) against public authorized target 'scanme.nmap.org'.
 * Validates real process spawning, stdout JSON parsing, and non-claim preservation.
 */

import assert from 'node:assert';
import process from 'node:process';

import { HttpxInspectionAdapter } from '../recon/adapters/HttpxInspectionAdapter.js';
import { WEB_INSPECTION_NON_CLAIMS } from '../recon/adapters/WebInspectionContracts.js';
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
    grantId: `grant_real_httpx_${Date.now()}`,
    scanId: `scan_real_httpx_${Date.now()}`,
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
      allowedOrigins: [`https://${domain}`, `http://${domain}`],
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

export async function runRealTargetHttpxSmoke(): Promise<void> {
  console.log('[*] [INTEGRATION] Checking httpx binary availability on host...');
  const availability = new ReconToolAvailabilityService(new LocalProcessRunner());
  const status = await availability.checkTool('httpx');

  if (status.status !== 'available') {
    console.log(`    [SKIPPED] httpx binary is not available on host PATH (${status.error ?? 'not installed'}). Skipping real httpx test.`);
    return;
  }

  console.log(`    [INFO] httpx is available at ${status.path ?? 'PATH'} (version: ${status.version ?? 'detected'})`);
  console.log('[*] [INTEGRATION] Executing real httpx against authorized public target: http://scanme.nmap.org...');

  const targetDomain = 'scanme.nmap.org';
  const targetUrl = 'http://scanme.nmap.org';
  const scopeGrant = createAuthorizedScope(targetDomain);
  const nowIso = new Date().toISOString();

  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asmt_real_httpx_test',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'dec_real_httpx_test',
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
    assessmentId: 'asmt_real_httpx_test',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_real_httpx_test',
    actorId: 'usr_secops_integration',
  };

  const runner = new LocalProcessRunner();
  const adapter = new HttpxInspectionAdapter(runner);

  const result = await adapter.inspectWeb({
    targetUrl,
    verifiedAuthorizationDecision: verifiedDecision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    timeoutMs: 15_000,
  });

  assert.strictEqual(result.status, 'success', `Expected status 'success', got ${result.status}`);
  assert.ok(result.observations.length > 0, 'Real httpx must produce at least one observation for scanme.nmap.org');
  assert.strictEqual(result.observations[0].statusCode, 200, 'scanme.nmap.org must return HTTP 200');
  assert.deepStrictEqual(result.explicitNonClaims, WEB_INSPECTION_NON_CLAIMS);
  assert.strictEqual(result.lineage.assessmentId, lineage.assessmentId);

  console.log(`    [PASS] Real httpx parsed response successfully: status 200, title: "${result.observations[0].title ?? 'N/A'}", server: "${result.observations[0].webServer ?? 'N/A'}"`);
}

if (process.argv[1]?.endsWith('real_target_httpx_smoke.ts')) {
  runRealTargetHttpxSmoke().catch((err) => {
    console.error('[!] Real HTTPX Integration Test FAILED:', err);
    process.exit(1);
  });
}
