/**
 * FixGuard V2 — Milestone P2-1 Smoke Test Suite
 *
 * Verifies the Security Header Detection Engine:
 * 1. Target missing recommended security headers produces 'pending_human_review' with evidence draft.
 * 2. Crucial Invariant: Approved missing security headers strictly produce status: 'potential_weakness'
 *    (hardening gap discipline), NEVER 'exploit_confirmed'.
 * 3. Fully hardened target (all security headers present) produces 'secure_target_abstained' with 0 findings.
 * 4. Preflight and SSRF gates fail closed with 0 probes dispatched.
 * 5. Full end-to-end integration via OrchestratedAssessmentApplicationService and human triage promotion.
 */

import assert from 'node:assert';
import process from 'node:process';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { HttpProbeRequest, HttpProbeResponse, IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import { runSecurityHeaderDetection, DEFAULT_REQUIRED_SECURITY_HEADERS } from '../detection/SecurityHeaderDetectionService.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
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

function createScopeGrant(domain = 'headers.example.com'): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_p2_1_001',
    scanId: 'scan_p2_1_001',
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'domain',
      domain,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized scope for ${domain} security header testing`,
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
      allowedDomains: [domain],
      allowedHosts: [domain, '93.184.216.34'],
      allowedOrigins: [`https://${domain}`, `http://${domain}`],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
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

function setupAuthorizedContext(domain = 'headers.example.com') {
  const scopeGrant = createScopeGrant(domain);
  const nowIso = new Date().toISOString();
  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asmt_p2_1_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'dec_p2_1_001',
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
      assessmentId: 'asmt_p2_1_001',
      scanId: scopeGrant.scanId,
      authorizationGrantId: scopeGrant.grantId,
      authorizationDecisionId: 'dec_p2_1_001',
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

async function runSmokeTests(): Promise<void> {
  console.log('[milestoneP2_1_security_headers_smoke] Starting Milestone P2-1 smoke suite...');

  // ---------------------------------------------------------------------------
  // Assertion 1: Missing security headers produce pending_human_review with draft
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_1_security_headers_smoke] Assertion 1: Testing missing headers detection...');
  const auth1 = setupAuthorizedContext('vulnerable-headers.example.com');
  const coordinator = new TargetExecutionCoordinator({ maxConcurrency: 2, requestsPerSecond: 10 });

  // Transport missing CSP, HSTS, and X-Frame-Options
  const missingHeadersTransport: IdorHttpProbeTransport = async () => ({
    statusCode: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'referrer-policy': 'no-referrer',
      'permissions-policy': 'geolocation=()',
    },
    bodyText: '<html><body>Hello</body></html>',
    responseTimeMs: 10,
  });

  const unreviewedResult = await runSecurityHeaderDetection({
    contractVersion: 'fixguard-detection/v0',
    kind: 'security_header_detection_request',
    detectionId: 'det_p21_unrev_001',
    assessmentId: auth1.lineage.assessmentId,
    scanId: auth1.lineage.scanId,
    authorizationGrantId: auth1.lineage.authorizationGrantId,
    authorizationDecisionId: auth1.lineage.authorizationDecisionId,
    actorId: auth1.lineage.actorId,
    verifiedAuthorizationDecision: auth1.verifiedAuthorizationDecision,
    scopeGrant: auth1.scopeGrant,
    endpointUrl: 'https://vulnerable-headers.example.com/',
    coordinator,
    transport: missingHeadersTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  assert.strictEqual(unreviewedResult.status, 'pending_human_review', 'Status must be pending_human_review');
  assert.strictEqual(unreviewedResult.reasonCode, 'pending_human_review');
  assert.ok(unreviewedResult.evidenceDraft, 'Evidence draft must be present');
  assert.strictEqual(unreviewedResult.finding, undefined, 'No finding should be auto-created');
  assert(unreviewedResult.missingHeaders.includes('content-security-policy'), 'Must detect missing CSP');
  assert(unreviewedResult.missingHeaders.includes('strict-transport-security'), 'Must detect missing HSTS');
  assert(unreviewedResult.missingHeaders.includes('x-frame-options'), 'Must detect missing X-Frame-Options');
  assert.strictEqual(unreviewedResult.presentHeaders.length, 2, 'Must recognize 2 present headers');
  console.log('[milestoneP2_1_security_headers_smoke] Assertion 1 PASSED: Missing headers correctly detected.');

  // ---------------------------------------------------------------------------
  // Assertion 2: Crucial Invariant: Approved status is 'potential_weakness' (NEVER 'exploit_confirmed')
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_1_security_headers_smoke] Assertion 2: Verifying hardening gap invariant...');
  const approvedResult = await runSecurityHeaderDetection({
    contractVersion: 'fixguard-detection/v0',
    kind: 'security_header_detection_request',
    detectionId: 'det_p21_appr_001',
    assessmentId: auth1.lineage.assessmentId,
    scanId: auth1.lineage.scanId,
    authorizationGrantId: auth1.lineage.authorizationGrantId,
    authorizationDecisionId: auth1.lineage.authorizationDecisionId,
    actorId: auth1.lineage.actorId,
    verifiedAuthorizationDecision: auth1.verifiedAuthorizationDecision,
    scopeGrant: auth1.scopeGrant,
    endpointUrl: 'https://vulnerable-headers.example.com/',
    humanReviewDecision: {
      decision: 'approve_evidence',
      reviewerId: 'usr_secops_lead_auditor',
      reviewedAt: new Date().toISOString(),
    },
    coordinator,
    transport: missingHeadersTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  assert.strictEqual(approvedResult.status, 'potential_weakness', 'Missing headers MUST strictly produce potential_weakness');
  assert.notStrictEqual(approvedResult.status, 'exploit_confirmed', 'Missing headers must NEVER produce exploit_confirmed');
  assert.strictEqual(approvedResult.reasonCode, 'missing_security_headers_observed');
  assert.ok(approvedResult.finding, 'Canonical Finding must be created upon review approval');
  assert.strictEqual(approvedResult.finding.type, 'SECURITY_MISCONFIGURATION');
  assert.strictEqual(approvedResult.finding.metadata.kind, 'missing_security_headers_metadata');
  assert.strictEqual(approvedResult.finding.severity, 'low');
  console.log('[milestoneP2_1_security_headers_smoke] Assertion 2 PASSED: Hardening gap invariant strictly satisfied.');

  // ---------------------------------------------------------------------------
  // Assertion 3: Fully hardened target produces 'secure_target_abstained' with 0 findings
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_1_security_headers_smoke] Assertion 3: Testing fully hardened target abstention...');
  const hardenedTransport: IdorHttpProbeTransport = async () => ({
    statusCode: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': "default-src 'self'",
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'x-frame-options': 'DENY',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'permissions-policy': 'geolocation=(), camera=()',
    },
    bodyText: '<html><body>Hardened Page</body></html>',
    responseTimeMs: 8,
  });

  const hardenedResult = await runSecurityHeaderDetection({
    contractVersion: 'fixguard-detection/v0',
    kind: 'security_header_detection_request',
    detectionId: 'det_p21_hard_001',
    assessmentId: auth1.lineage.assessmentId,
    scanId: auth1.lineage.scanId,
    authorizationGrantId: auth1.lineage.authorizationGrantId,
    authorizationDecisionId: auth1.lineage.authorizationDecisionId,
    actorId: auth1.lineage.actorId,
    verifiedAuthorizationDecision: auth1.verifiedAuthorizationDecision,
    scopeGrant: auth1.scopeGrant,
    endpointUrl: 'https://vulnerable-headers.example.com/',
    coordinator,
    transport: hardenedTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  assert.strictEqual(hardenedResult.status, 'secure_target_abstained');
  assert.strictEqual(hardenedResult.reasonCode, 'all_security_headers_enforced');
  assert.strictEqual(hardenedResult.missingHeaders.length, 0);
  assert.strictEqual(hardenedResult.presentHeaders.length, DEFAULT_REQUIRED_SECURITY_HEADERS.length);
  assert.strictEqual(hardenedResult.finding, undefined, 'Zero findings on secure target');
  assert.strictEqual(hardenedResult.evidenceDraft, undefined, 'Zero evidence drafts on secure target');
  console.log('[milestoneP2_1_security_headers_smoke] Assertion 3 PASSED: Secure target cleanly abstained.');

  // ---------------------------------------------------------------------------
  // Assertion 4: SSRF & Preflight Failure Containment
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_1_security_headers_smoke] Assertion 4: Testing SSRF preflight containment...');
  const ssrfContext = setupAuthorizedContext('127.0.0.1');
  const ssrfResult = await runSecurityHeaderDetection({
    contractVersion: 'fixguard-detection/v0',
    kind: 'security_header_detection_request',
    detectionId: 'det_p21_ssrf_001',
    assessmentId: ssrfContext.lineage.assessmentId,
    scanId: ssrfContext.lineage.scanId,
    authorizationGrantId: ssrfContext.lineage.authorizationGrantId,
    authorizationDecisionId: ssrfContext.lineage.authorizationDecisionId,
    actorId: ssrfContext.lineage.actorId,
    verifiedAuthorizationDecision: ssrfContext.verifiedAuthorizationDecision,
    scopeGrant: ssrfContext.scopeGrant,
    endpointUrl: 'http://127.0.0.1/',
    coordinator,
    transport: hardenedTransport,
    dnsResolver: async () => ['127.0.0.1'],
  });

  assert.strictEqual(ssrfResult.status, 'preflight_denied');
  assert.strictEqual(ssrfResult.missingHeaders.length, 0);
  console.log('[milestoneP2_1_security_headers_smoke] Assertion 4 PASSED: SSRF target safely blocked at preflight.');

  // ---------------------------------------------------------------------------
  // Assertion 5: Orchestrated Assessment Pipeline End-to-End & Triage Promotion
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_1_security_headers_smoke] Assertion 5: Testing Orchestrated Assessment Pipeline integration...');
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const mockAvailabilityService = new ReconToolAvailabilityService({
    async execute() {
      return { stdout: '1.0.0\n', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
    },
  });

  const orchestratedService = new OrchestratedAssessmentApplicationService({
    repository,
    reconAdapters: createMockAdapters(),
    httpTransport: missingHeadersTransport,
    dnsResolver: async () => ['93.184.216.34'],
    availabilityService: mockAvailabilityService,
  });

  const launchResult = await orchestratedService.startAssessment({
    targetDomain: 'security-headers-target.com',
    actorId: 'usr_secops_lead',
  });

  assert.strictEqual(launchResult.status, 'running');
  const record = await orchestratedService.awaitAssessment(launchResult.assessmentId);
  assert(record, 'Record must exist');
  assert.strictEqual(record.status, 'completed');

  // Verify pending drafts contain missing_security_headers draft
  const drafts = record.pendingEvidenceDrafts ?? [];
  const shDraft = drafts.find((d) => d.differentialContext?.detectionKind === 'missing_security_headers');
  assert(shDraft, 'Pipeline must generate missing_security_headers pending evidence draft');
  assert(shDraft.differentialContext?.missingHeaders?.includes('content-security-policy'), 'Draft must track missing headers');

  // Triage review: Approve evidence draft
  const reviewResult = await orchestratedService.reviewEvidenceDraft({
    assessmentId: record.assessmentId,
    draftId: shDraft.draftId,
    decision: 'approve_evidence',
    reviewerId: 'usr_secops_lead_auditor',
    reviewedAt: new Date().toISOString(),
    notes: 'Confirmed missing CSP and HSTS in staging environment.',
  });

  assert.strictEqual(reviewResult.decision, 'approve_evidence');
  assert(reviewResult.findingCreated, 'Finding must be created');
  assert.strictEqual(reviewResult.findingCreated.metadata.kind, 'missing_security_headers_metadata');

  // Verify updated assessment record
  const updatedRecord = await repository.findById(record.assessmentId);
  assert(updatedRecord, 'Updated record must exist');
  assert(updatedRecord.findings.some((f) => f.id === reviewResult.findingCreated?.id), 'Finding must be in record findings');
  console.log('[milestoneP2_1_security_headers_smoke] Assertion 5 PASSED: Full pipeline & triage lifecycle verified.');

  console.log('----------------------------------------------------------------');
  console.log('[milestoneP2_1_security_headers_smoke] ALL SMOKE TESTS PASSED (100%)');
  console.log('----------------------------------------------------------------');
}

runSmokeTests().catch((err) => {
  console.error('[milestoneP2_1_security_headers_smoke] FATAL TEST FAILURE:', err);
  process.exit(1);
});
