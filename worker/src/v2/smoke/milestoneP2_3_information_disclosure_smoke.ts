/**
 * FixGuard V2 — Milestone P2-3 Smoke Suite
 *
 * Verifies Information Disclosure Detection Engine:
 * 1. Detects stack traces and server banners, classifying as potential_weakness with InformationDisclosureMetadata.
 * 2. Sensitive credential patterns are strictly redacted in disclosed fragments.
 * 3. Generic error pages and hardened targets cleanly abstain (secure_target_abstained).
 * 4. Preflight & SSRF containment gates fail closed safely.
 * 5. Full Orchestrated Assessment Pipeline integration & human triage lifecycle.
 */

import assert from 'node:assert';
import {
  runInformationDisclosureDetection,
  sanitizeDisclosedExcerpt,
} from '../detection/InformationDisclosureDetectionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type { HttpProbeRequest, HttpProbeResponse, IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { ReconToolAdapters } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import { SUBDOMAIN_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SubdomainDiscoveryContracts.js';
import { DNS_RESOLUTION_NON_CLAIMS } from '../recon/adapters/DnsResolutionContracts.js';
import { PORT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/PortDiscoveryContracts.js';
import { WEB_INSPECTION_NON_CLAIMS } from '../recon/adapters/WebInspectionContracts.js';
import { TLS_INSPECTION_NON_CLAIMS } from '../recon/adapters/TlsInspectionContracts.js';
import { URL_DISCOVERY_NON_CLAIMS } from '../recon/adapters/UrlDiscoveryContracts.js';
import { CONTENT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ContentDiscoveryContracts.js';
import { PARAMETER_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ParameterDiscoveryContracts.js';
import { SECRET_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SecretDiscoveryContracts.js';

console.log('[milestoneP2_3_information_disclosure_smoke] Starting Milestone P2-3 smoke suite...');

function createScopeGrant(domain = 'leaky-app.example.com'): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_p2_3_001',
    scanId: 'scan_p2_3_001',
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'domain',
      domain,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized scope for ${domain} info disclosure testing`,
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
      allowedDomains: [domain, 'hardened-app.example.com'],
      allowedHosts: [domain, 'hardened-app.example.com', '93.184.216.34'],
      allowedOrigins: [`https://${domain}`, `http://${domain}`, 'https://hardened-app.example.com'],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
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
  };
}

function setupAuthorizedContext(domain = 'leaky-app.example.com') {
  const scopeGrant = createScopeGrant(domain);
  const nowIso = new Date().toISOString();
  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asmt_p2_3_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'dec_p2_3_001',
      authorizedActor: { actorId: 'usr_secops_auditor', actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant,
    },
    nowIso
  );

  if (authRes.status !== 'established') {
    throw new Error(`Failed to establish auth decision: ${authRes.reasonCode}`);
  }

  return {
    verifiedAuthorizationDecision: authRes.decision,
    scopeGrant,
    lineage: {
      assessmentId: 'asmt_p2_3_001',
      scanId: scopeGrant.scanId,
      authorizationGrantId: scopeGrant.grantId,
      authorizationDecisionId: 'dec_p2_3_001',
      actorId: 'usr_secops_auditor',
    },
  };
}

function createMockAdapters(): ReconToolAdapters {
  return {
    subdomainTool: {
      async discoverSubdomains(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-subdomain-discovery/v0',
          targetDomain: req.targetDomain,
          observations: [],
          explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    dnsTool: {
      async resolveDns(req) {
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
          durationMs: 5,
        };
      },
    },
    portTool: {
      async discoverPorts(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-port-discovery/v0',
          targetHostOrIp: req.targetHostOrIp,
          observations: [
            {
              host: req.targetHostOrIp,
              ip: req.targetHostOrIp,
              port: 443,
              protocol: 'tcp',
              state: 'open',
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    webTool: {
      async inspectWeb(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-web-inspection/v0',
          targetUrl: req.targetUrl,
          observations: [],
          explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    tlsTool: {
      async inspectTls(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-tls-inspection/v0',
          targetHost: req.targetHostOrUrl,
          observations: [],
          explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    urlTool: {
      async discoverUrls(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-url-discovery/v0',
          targetUrlOrDomain: req.targetUrlOrDomain,
          observations: [],
          explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    contentTool: {
      async discoverContent(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-content-discovery/v0',
          targetUrl: req.targetUrl,
          wordlistPath: req.wordlistPath,
          observations: [],
          explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    parameterTool: {
      async discoverParameters(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-parameter-discovery/v0',
          targetUrl: req.targetUrl,
          observations: [],
          explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    secretTool: {
      async scanSecrets(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-secret-discovery/v0',
          targetUrlOrPath: req.targetUrlOrPath,
          observations: [],
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
  };
}

const { verifiedAuthorizationDecision: verifiedDecision, scopeGrant } = setupAuthorizedContext();

async function runTests() {
  // ---------------------------------------------------------------------------
  // Assertion 1: Stack Trace Detection & Hardening Gap Status Invariant
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_3_information_disclosure_smoke] Assertion 1: Testing stack trace detection...');

  const javaStackTraceTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    if (req.url.includes('_fixguard_anomaly_404_')) {
      const traceBody = `
        <html>
          <h1>HTTP Status 500 – Internal Server Error</h1>
          <pre>
            java.lang.NullPointerException: Cannot invoke user session
            at org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:204)
            at org.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:97)
            at com.example.app.security.AuthFilter.doFilter(AuthFilter.java:88)
          </pre>
        </html>
      `;
      return {
        statusCode: 500,
        headers: { 'content-type': 'text/html' },
        bodyText: traceBody,
        responseTimeMs: 20,
      };
    }
    return {
      statusCode: 200,
      headers: { 'content-type': 'text/html' },
      bodyText: '<html>Home</html>',
      responseTimeMs: 10,
    };
  };

  const unreviewedResult = await runInformationDisclosureDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'information_disclosure_detection_request',
    detectionId: 'det_infodisc_001',
    assessmentId: 'asmt_p2_3_001',
    scanId: 'scan_p2_3_001',
    authorizationGrantId: 'grant_p2_3_001',
    authorizationDecisionId: 'dec_p2_3_001',
    actorId: 'usr_secops_auditor',
    endpointUrl: 'https://leaky-app.example.com/',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    transport: javaStackTraceTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  assert.strictEqual(
    unreviewedResult.status,
    'pending_human_review',
    'Unreviewed information disclosure must route to pending_human_review'
  );
  assert.ok(unreviewedResult.evidenceDraft, 'Evidence draft must be generated');
  assert.strictEqual(unreviewedResult.disclosures.length > 0, true, 'Disclosures must be detected');
  assert.strictEqual(unreviewedResult.disclosures[0].disclosureKind, 'stack_trace');

  // Approved review must produce status: 'potential_weakness' (never 'exploit_confirmed')
  const approvedResult = await runInformationDisclosureDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'information_disclosure_detection_request',
    detectionId: 'det_infodisc_002',
    assessmentId: 'asmt_p2_3_001',
    scanId: 'scan_p2_3_001',
    authorizationGrantId: 'grant_p2_3_001',
    authorizationDecisionId: 'dec_p2_3_001',
    actorId: 'usr_secops_auditor',
    endpointUrl: 'https://leaky-app.example.com/',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    transport: javaStackTraceTransport,
    dnsResolver: async () => ['93.184.216.34'],
    humanReviewDecision: {
      decision: 'approve_evidence',
      reviewerId: 'operator_secops_lead',
      reviewedAt: new Date().toISOString(),
    },
  });

  assert.strictEqual(
    approvedResult.status,
    'potential_weakness',
    'Approved information disclosure must strictly produce potential_weakness'
  );
  assert.ok(approvedResult.finding, 'Must produce finding on approval');
  assert.strictEqual(approvedResult.finding.metadata.kind, 'information_disclosure_metadata');
  assert.strictEqual(approvedResult.finding.severity, 'low');

  console.log('[milestoneP2_3_information_disclosure_smoke] Assertion 1 PASSED: Stack trace detected and metadata created.');

  // ---------------------------------------------------------------------------
  // Assertion 2: Server Banner Disclosure & Sensitive Credential Redaction
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_3_information_disclosure_smoke] Assertion 2: Testing banner disclosure & credential redaction...');

  const leakedExcerpt = 'Debug info: api_key="secret_token_abcdef123456" in /var/www/html/app.php on line 42 with Bearer eyJhbGciOi...';
  const sanitized = sanitizeDisclosedExcerpt(leakedExcerpt);
  assert(!sanitized.includes('secret_token_abcdef123456'), 'Plaintext API key must be redacted');
  assert(sanitized.includes('[REDACTED]'), 'Redaction placeholder must be inserted');

  const bannerTransport: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => ({
    statusCode: 200,
    headers: {
      server: 'Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1d',
      'x-powered-by': 'PHP/7.4.3',
    },
    bodyText: '<html>App running</html>',
    responseTimeMs: 10,
  });

  const bannerResult = await runInformationDisclosureDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'information_disclosure_detection_request',
    detectionId: 'det_infodisc_003',
    assessmentId: 'asmt_p2_3_001',
    scanId: 'scan_p2_3_001',
    authorizationGrantId: 'grant_p2_3_001',
    authorizationDecisionId: 'dec_p2_3_001',
    actorId: 'usr_secops_auditor',
    endpointUrl: 'https://leaky-app.example.com/',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    transport: bannerTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  assert.strictEqual(bannerResult.status, 'pending_human_review');
  const serverBannerDisc = bannerResult.disclosures.find((d) => d.disclosureKind === 'server_banner');
  assert.ok(serverBannerDisc, 'Must identify server_banner disclosure');
  assert(serverBannerDisc.disclosedFragment.includes('Apache/2.4.41'), 'Disclosed fragment must contain server version');

  console.log('[milestoneP2_3_information_disclosure_smoke] Assertion 2 PASSED: Server banners detected and credentials redacted.');

  // ---------------------------------------------------------------------------
  // Assertion 3: Clean Error Pages & Hardened Target Abstention
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_3_information_disclosure_smoke] Assertion 3: Testing hardened target abstention...');

  const hardenedTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    if (req.url.includes('_fixguard_anomaly_404_')) {
      return {
        statusCode: 404,
        headers: { server: 'cloudflare' },
        bodyText: '<html><h1>404 Not Found</h1><p>The requested resource was not found.</p></html>',
        responseTimeMs: 12,
      };
    }
    return {
      statusCode: 200,
      headers: { server: 'cloudflare' },
      bodyText: '<html><h1>Welcome</h1></html>',
      responseTimeMs: 12,
    };
  };

  const hardenedResult = await runInformationDisclosureDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'information_disclosure_detection_request',
    detectionId: 'det_infodisc_004',
    assessmentId: 'asmt_p2_3_001',
    scanId: 'scan_p2_3_001',
    authorizationGrantId: 'grant_p2_3_001',
    authorizationDecisionId: 'dec_p2_3_001',
    actorId: 'usr_secops_auditor',
    endpointUrl: 'https://hardened-app.example.com/',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    transport: hardenedTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  assert.strictEqual(
    hardenedResult.status,
    'secure_target_abstained',
    'Hardened error templates must trigger secure_target_abstained'
  );
  assert.strictEqual(hardenedResult.finding, undefined, 'No findings created for secure target');
  assert.strictEqual(hardenedResult.evidenceDraft, undefined, 'No drafts created for secure target');

  console.log('[milestoneP2_3_information_disclosure_smoke] Assertion 3 PASSED: Hardened target cleanly abstained.');

  // ---------------------------------------------------------------------------
  // Assertion 4: Preflight & SSRF Containment
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_3_information_disclosure_smoke] Assertion 4: Testing preflight & SSRF containment...');

  const ssrfResult = await runInformationDisclosureDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'information_disclosure_detection_request',
    detectionId: 'det_infodisc_005',
    assessmentId: 'asmt_p2_3_001',
    scanId: 'scan_p2_3_001',
    authorizationGrantId: 'grant_p2_3_001',
    authorizationDecisionId: 'dec_p2_3_001',
    actorId: 'usr_secops_auditor',
    endpointUrl: 'http://169.254.169.254/latest/meta-data/',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    transport: hardenedTransport,
    dnsResolver: async () => ['169.254.169.254'],
  });

  assert.strictEqual(
    ssrfResult.status,
    'preflight_denied',
    'Forbidden SSRF IP space must fail closed at preflight'
  );

  console.log('[milestoneP2_3_information_disclosure_smoke] Assertion 4 PASSED: SSRF target safely blocked at preflight.');

  // ---------------------------------------------------------------------------
  // Assertion 5: Orchestrated Assessment Pipeline Integration & Human Triage
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_3_information_disclosure_smoke] Assertion 5: Testing Orchestrated Assessment Pipeline & Triage...');

  const repository = new InMemoryOrchestratedAssessmentRepository();
  const mockAvailabilityService = new ReconToolAvailabilityService({
    async execute() {
      return { stdout: '1.0.0\n', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
    },
  });

  const orchestrator = new OrchestratedAssessmentApplicationService({
    repository,
    reconAdapters: createMockAdapters(),
    httpTransport: javaStackTraceTransport,
    dnsResolver: async () => ['93.184.216.34'],
    availabilityService: mockAvailabilityService,
  });

  const startRes = await orchestrator.startAssessment({
    targetDomain: 'leaky-app.example.com',
    actorId: 'human_operator_42',
  });

  assert.strictEqual(startRes.status, 'running');

  const record = await orchestrator.awaitAssessment(startRes.assessmentId);
  assert.ok(record, 'Assessment record must exist');
  assert.strictEqual(record.status, 'completed');
  assert.ok((record.pendingEvidenceDrafts ?? []).length > 0, 'Must have pending drafts');

  const infoDiscDraft = record.pendingEvidenceDrafts?.find(
    (d) => d.differentialContext?.detectionKind === 'information_disclosure'
  );
  assert.ok(infoDiscDraft, 'Must contain information_disclosure draft in pending drafts');
  assert.strictEqual(infoDiscDraft.differentialContext?.disclosureKind, 'stack_trace');

  // Triage: Human operator approves the draft
  const reviewRes = await orchestrator.reviewEvidenceDraft({
    assessmentId: startRes.assessmentId,
    draftId: infoDiscDraft.draftId,
    decision: 'approve_evidence',
    reviewerId: 'authorized_sec_lead',
    reviewedAt: new Date().toISOString(),
    notes: 'Verified leaked Java stack trace on anomalous 404 endpoint',
  });

  assert.strictEqual(reviewRes.decision, 'approve_evidence');
  assert.ok(reviewRes.findingCreated, 'Must have promoted finding');
  assert.strictEqual(reviewRes.findingCreated.metadata.kind, 'information_disclosure_metadata');
  assert.strictEqual(reviewRes.findingCreated.severity, 'low');

  // Verify updated summary
  const updatedSummary = await orchestrator.getSummary(startRes.assessmentId);
  const foundInSummary = updatedSummary.findings.find(
    (f) => f.metadata.kind === 'information_disclosure_metadata'
  );
  assert.ok(foundInSummary, 'Promoted Information Disclosure finding must be present in assessment findings');

  console.log('[milestoneP2_3_information_disclosure_smoke] Assertion 5 PASSED: Pipeline and human review triage lifecycle verified.');

  console.log('----------------------------------------------------------------');
  console.log('[milestoneP2_3_information_disclosure_smoke] ALL SMOKE TESTS PASSED (100%)');
  console.log('----------------------------------------------------------------');
}

runTests().catch((err) => {
  console.error('[milestoneP2_3_information_disclosure_smoke] FAILED:', err);
  process.exit(1);
});
