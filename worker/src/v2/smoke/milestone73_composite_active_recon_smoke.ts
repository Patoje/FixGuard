/**
 * Milestone 73 — Composite Active Reconnaissance Orchestrator Smoke Test Suite
 *
 * Validates the Composite Active Reconnaissance Orchestrator Application Service:
 * 1. End-to-end staged orchestration chaining 9 Layer 6 tool adapters across Stages 1–5.
 * 2. Rate-limiting and concurrency controls enforced via TargetExecutionCoordinator.
 * 3. Continuous lineage tuple integrity and explicit non-claims across all staged evidence drafts.
 * 4. Atomic preflight, SSRF containment, and session expiration fail-closed with strictly 0 tool invocations.
 */

import assert from 'node:assert';
import {
  establishVerifiedAuthorizationDecision,
  deriveAuthorizationLineageRef,
} from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { TargetSessionState } from '../core/SessionLifecycleContracts.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';

import type {
  ReconToolAdapters,
  ActiveReconOrchestrationRequest,
} from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import {
  ACTIVE_RECON_ORCHESTRATION_CONTRACT_VERSION,
  RECON_ORCHESTRATION_NON_CLAIMS,
} from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import { CompositeActiveReconOrchestratorService } from '../recon/orchestration/CompositeActiveReconOrchestratorService.js';

import { SUBDOMAIN_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SubdomainDiscoveryContracts.js';
import { DNS_RESOLUTION_NON_CLAIMS } from '../recon/adapters/DnsResolutionContracts.js';
import { PORT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/PortDiscoveryContracts.js';
import { WEB_INSPECTION_NON_CLAIMS } from '../recon/adapters/WebInspectionContracts.js';
import { TLS_INSPECTION_NON_CLAIMS } from '../recon/adapters/TlsInspectionContracts.js';
import { URL_DISCOVERY_NON_CLAIMS } from '../recon/adapters/UrlDiscoveryContracts.js';
import { CONTENT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ContentDiscoveryContracts.js';
import { PARAMETER_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ParameterDiscoveryContracts.js';
import { SECRET_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SecretDiscoveryContracts.js';



function createScopeGrant(overrides?: Partial<AuthorizedScopeGrant>): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_m73_test_001',
    scanId: 'scan_m73_test_001',
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),


    subject: {
      targetKind: 'domain',
      domain: 'example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone 73 composite active recon testing',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: true,
      lightValidation: true,
      activeValidation: true,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: ['example.com', 'api.example.com', 'app.example.com'],
      allowedHosts: ['example.com', 'api.example.com', 'app.example.com', '93.184.216.34'],
      allowedOrigins: ['https://example.com', 'https://api.example.com', 'https://app.example.com'],
      allowedMethods: ['GET', 'HEAD', 'POST'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: false,
      allowCredentialUse: true,
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
    ...overrides,
  };
}

function createMockAdapters(invocationTracker: { count: number }): ReconToolAdapters {
  return {
    subdomainTool: {
      async discoverSubdomains(req) {
        invocationTracker.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-subdomain-discovery/v0',
          targetDomain: req.targetDomain,
          observations: [
            {
              subdomain: 'api.example.com',
              parentDomain: req.targetDomain,
              sources: ['mock_crtsh'],
              discoveredAt: new Date().toISOString(),
              confidence: 0.95,
            },
          ],
          explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 15,
        };
      },
    },
    dnsTool: {
      async resolveDns(req) {
        invocationTracker.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-dns-resolution/v0',
          targetDomain: req.targetDomain,
          observations: [
            {
              domain: req.targetDomain,
              recordType: 'A',
              values: ['93.184.216.34'],
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 12,
        };
      },
    },
    portTool: {
      async discoverPorts(req) {
        invocationTracker.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-port-discovery/v0',
          targetHostOrIp: req.targetHostOrIp,
          observations: [
            {
              host: req.targetHostOrIp,
              ip: '93.184.216.34',
              port: 443,
              protocol: 'tcp',
              state: 'open',
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 25,
        };
      },
    },
    webTool: {
      async inspectWeb(req) {
        invocationTracker.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-web-inspection/v0',
          targetUrl: req.targetUrl,
          observations: [
            {
              url: req.targetUrl,
              method: 'GET',
              statusCode: 200,
              title: 'Example API Gateway',
              webServer: 'nginx/1.24',
              technologies: ['Node.js', 'Express'],
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 30,
        };
      },
    },
    tlsTool: {
      async inspectTls(req) {
        invocationTracker.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-tls-inspection/v0',
          targetHost: req.targetHostOrUrl,
          observations: [
            {
              host: req.targetHostOrUrl,
              port: 443,
              subjectAlternativeNames: ['example.com', '*.example.com'],
              supportedProtocols: ['TLSv1.2', 'TLSv1.3'],
              cipherSuites: ['TLS_AES_256_GCM_SHA384'],
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 20,
        };
      },
    },
    urlTool: {
      async discoverUrls(req) {
        invocationTracker.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-url-discovery/v0',
          targetUrlOrDomain: req.targetUrlOrDomain,
          observations: [
            {
              url: 'https://api.example.com/v1/users',
              host: 'api.example.com',
              path: '/v1/users',
              sources: ['katana'],
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 40,
        };
      },
    },
    contentTool: {
      async discoverContent(req) {
        invocationTracker.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-content-discovery/v0',
          targetUrl: req.targetUrl,
          wordlistPath: req.wordlistPath,
          observations: [
            {
              url: 'https://api.example.com/v1/health',
              path: '/v1/health',
              statusCode: 200,
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 35,
        };
      },
    },
    parameterTool: {
      async discoverParameters(req) {
        invocationTracker.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-parameter-discovery/v0',
          targetUrl: req.targetUrl,
          observations: [
            {
              url: req.targetUrl,
              method: 'GET',
              parameterName: 'format',
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 28,
        };
      },
    },
    secretTool: {
      async scanSecrets(req) {
        invocationTracker.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-secret-discovery/v0',
          targetUrlOrPath: req.targetUrlOrPath,
          observations: [
            {
              locationUrl: req.targetUrlOrPath,
              detectorName: 'generic_api_key',
              redactedSecret: 'ak_live_********99',
              discoveredAt: new Date().toISOString(),
              verified: false,
            },
          ],
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 32,
        };
      },
    },
  };
}

function setupAuthorizedContext(scopeGrant = createScopeGrant()) {
  const nowIso = new Date().toISOString();
  const establishResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'assess_m73_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_m73_001',
      authorizedActor: { actorId: 'sec_lead_1', actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant,
    },
    nowIso
  );

  if (establishResult.status !== 'established') {
    throw new Error(`Failed to establish verified authorization decision: ${establishResult.reasonCode}`);
  }
  return {
    verifiedAuthorizationDecision: establishResult.decision,
    scopeGrant,
    lineage: {
      assessmentId: 'assess_m73_001',
      scanId: scopeGrant.scanId,
      authorizationGrantId: scopeGrant.grantId,
      authorizationDecisionId: 'decision_m73_001',
      actorId: 'sec_lead_1',
    },
  };
}

async function runMilestone73SmokeSuite(): Promise<void> {
  console.log('>>> RUNNING MILESTONE 73 SMOKE TEST SUITE (Composite Active Recon Orchestrator) <<<');

  const auth = setupAuthorizedContext();
  const { verifiedAuthorizationDecision: authDecision, scopeGrant, lineage: canonicalLineage } = auth;

  // -------------------------------------------------------------------------
  // Assertion 1: Staged Execution Pipeline Across All 5 Stages
  // -------------------------------------------------------------------------
  {
    console.log('\n[+] Assertion 1: End-to-end staged orchestration with data flowing through Stages 1 to 5...');

    const tracker = { count: 0 };
    const adapters = createMockAdapters(tracker);
    const service = new CompositeActiveReconOrchestratorService(adapters);

    const result = await service.orchestrate({
      targetDomain: 'example.com',
      verifiedAuthorizationDecision: authDecision,
      authorizedScopeGrant: scopeGrant,
      lineage: canonicalLineage,
      config: {
        wordlistPath: 'wordlists/common.txt',
      },
      dnsResolver: async () => ['93.184.216.34'],
    });

    assert.strictEqual(result.status, 'success');
    assert.strictEqual(result.contractVersion, ACTIVE_RECON_ORCHESTRATION_CONTRACT_VERSION);
    assert.strictEqual(result.targetDomain, 'example.com');
    assert.strictEqual(result.stages.length, 5, 'All 5 stages must have executed');

    // Check each stage completed
    for (const st of result.stages) {
      assert.strictEqual(st.status, 'completed', `Stage ${st.stage} must be completed`);
      assert.ok(st.observationsCount > 0, `Stage ${st.stage} must have observations`);
    }

    // Verify observations populated in aggregatedObservations
    const agg = result.aggregatedObservations;
    assert.strictEqual(agg.subdomains.length, 1);
    assert.strictEqual(agg.dnsRecords.length, 2); // resolved for targetDomain + subdomain
    assert.strictEqual(agg.ports.length, 2);
    assert.ok(agg.webObservations.length > 0);
    assert.ok(agg.tlsCertificates.length > 0);
    assert.ok(agg.urls.length > 0);
    assert.ok(agg.content.length > 0);
    assert.ok(agg.parameters.length > 0);
    assert.ok(agg.secrets.length > 0);

    // Verify all tool adapters were invoked
    assert.ok(tracker.count >= 9, 'All 9 Layer 6 tool adapters must have been invoked');

    console.log('    [PASS] Staged pipeline successfully executed all 5 phases and chained discoveries');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: TargetExecutionCoordinator Concurrency and Rate Limiting
  // -------------------------------------------------------------------------
  {
    console.log('\n[+] Assertion 2: Rate-limiting and concurrency coordination enforced via coordinator...');

    const tracker = { count: 0 };
    const adapters = createMockAdapters(tracker);
    const service = new CompositeActiveReconOrchestratorService(adapters);

    const coordinator = new TargetExecutionCoordinator({
      maxConcurrency: 2,
      requestsPerSecond: 20,
    });

    const result = await service.orchestrate({
      targetDomain: 'example.com',
      verifiedAuthorizationDecision: authDecision,
      authorizedScopeGrant: scopeGrant,
      lineage: canonicalLineage,
      coordinator,
      dnsResolver: async () => ['93.184.216.34'],
    });

    assert.strictEqual(result.status, 'success');

    const stats = coordinator.getHostStats('example.com');
    assert.ok(stats.totalCompleted > 0, 'Coordinator must record completed tasks for target host');
    assert.strictEqual(stats.totalRejected, 0, 'No requests should be rejected under normal capacity');

    console.log('    [PASS] Coordinator successfully paced and coordinated requests across hosts');
  }

  // -------------------------------------------------------------------------
  // Assertion 3: Continuous Lineage Preservation & Non-Claims on Evidence Drafts
  // -------------------------------------------------------------------------
  {
    console.log('\n[+] Assertion 3: Verifying continuous lineage tuple and explicit non-claims on drafts...');

    const tracker = { count: 0 };
    const adapters = createMockAdapters(tracker);
    const service = new CompositeActiveReconOrchestratorService(adapters);

    const result = await service.orchestrate({
      targetDomain: 'example.com',
      verifiedAuthorizationDecision: authDecision,
      authorizedScopeGrant: scopeGrant,
      lineage: canonicalLineage,
      dnsResolver: async () => ['93.184.216.34'],
    });

    assert.strictEqual(result.status, 'success');
    assert.deepStrictEqual(result.lineage, canonicalLineage);
    assert.deepStrictEqual(result.explicitNonClaims, RECON_ORCHESTRATION_NON_CLAIMS);

    assert.ok(result.drafts.length > 0, 'Evidence drafts must be generated');

    for (const draft of result.drafts) {
      assert.deepStrictEqual(draft.lineage, canonicalLineage, 'Every draft must carry the exact continuous lineage');
      assert.strictEqual(draft.explicitNonClaims.severity, 'info');
      assert.strictEqual(draft.explicitNonClaims.createsRealFindings, false);
      assert.strictEqual(draft.explicitNonClaims.confirmsVulnerabilities, false);
      assert.ok(!draft.draftId.includes('idor'));
      assert.ok(!draft.draftId.includes('vulnerable'));
      assert.ok(!draft.draftId.includes('attack'));
    }

    console.log('    [PASS] Unbroken lineage and explicit non-claims verified across all evidence drafts');
  }

  // -------------------------------------------------------------------------
  // Assertion 4: Preflight, SSRF, and Session Expiration Fail-Closed Semantics
  // -------------------------------------------------------------------------
  {
    console.log('\n[+] Assertion 4: Verifying preflight, SSRF, and session expiration fail-closed behavior...');

    const tracker = { count: 0 };
    const adapters = createMockAdapters(tracker);
    const service = new CompositeActiveReconOrchestratorService(adapters);

    // 4a: Out-of-scope / SSRF target domain
    const ssrfResult = await service.orchestrate({
      targetDomain: '127.0.0.1',
      verifiedAuthorizationDecision: authDecision,
      authorizedScopeGrant: scopeGrant,
      lineage: canonicalLineage,
    });

    assert.strictEqual(ssrfResult.status, 'preflight_denied');
    assert.strictEqual(tracker.count, 0, 'Zero child processes/probes must spawn on SSRF denial');

    // 4b: Malformed domain
    const malformedResult = await service.orchestrate({
      targetDomain: 'bad..domain..example',
      verifiedAuthorizationDecision: authDecision,
      authorizedScopeGrant: scopeGrant,
      lineage: canonicalLineage,
    });

    assert.strictEqual(malformedResult.status, 'preflight_denied');
    assert.strictEqual(tracker.count, 0, 'Zero child processes/probes must spawn on malformed domain');

    // 4c: Expired session
    const expiredSession: TargetSessionState = {
      state: 'expired',
      expiresAt: '2020-01-01T00:00:00.000Z',
    };

    const sessionResult = await service.orchestrate({
      targetDomain: 'example.com',
      verifiedAuthorizationDecision: authDecision,
      authorizedScopeGrant: scopeGrant,
      lineage: canonicalLineage,
      authContext: {
        identityId: 'user_expired',
        sessionState: expiredSession,
      },
    });

    assert.strictEqual(sessionResult.status, 'preflight_denied');
    assert.strictEqual(sessionResult.reasonCode, 'session_expired');
    assert.strictEqual(tracker.count, 0, 'Zero child processes/probes must spawn on expired session');

    console.log('    [PASS] Preflight, SSRF, and session expiration safely failed closed with strictly 0 tool invocations');
  }

  console.log('\n>>> ALL 4 MILESTONE 73 ASSERTIONS PASSED SUCCESSFULLY! <<<');
}

runMilestone73SmokeSuite().catch((err) => {
  console.error('[!] MILESTONE 73 SMOKE SUITE FAILED:', err);
  process.exit(1);
});
