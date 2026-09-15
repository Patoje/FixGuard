/**
 * FixGuard V2 — Milestone P2-2 Smoke Suite
 *
 * Verifies Open Redirect Detection Engine:
 * 1. Detects unvalidated canary redirection in Location header and builds OpenRedirectMetadata upon review.
 * 2. Cleanly abstains when target validates destinations against internal allowlist or relative path.
 * 3. Egress & preflight gates strictly block SSRF destinations and forbidden IP ranges.
 * 4. Returns pending_human_review when humanReviewDecision is absent.
 * 5. Full Orchestrated Assessment Pipeline integration & human triage lifecycle.
 */

import assert from 'node:assert';
import { runOpenRedirectDetection } from '../detection/OpenRedirectDetectionService.js';
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

console.log('[milestoneP2_2_open_redirect_smoke] Starting Milestone P2-2 smoke suite...');

function createScopeGrant(domain = 'vulnerable-redirect.example.com'): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_p2_2_001',
    scanId: 'scan_p2_2_001',
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'domain',
      domain,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized scope for ${domain} open redirect testing`,
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
      allowedDomains: [domain, 'secure-target.example.com'],
      allowedHosts: [domain, 'secure-target.example.com', '93.184.216.34'],
      allowedOrigins: [`https://${domain}`, `http://${domain}`, 'https://secure-target.example.com'],
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

function setupAuthorizedContext(domain = 'vulnerable-redirect.example.com') {
  const scopeGrant = createScopeGrant(domain);
  const nowIso = new Date().toISOString();
  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asmt_p2_2_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'dec_p2_2_001',
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
      assessmentId: 'asmt_p2_2_001',
      scanId: scopeGrant.scanId,
      authorizationGrantId: scopeGrant.grantId,
      authorizationDecisionId: 'dec_p2_2_001',
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
  // Assertion 1: Unvalidated Canary Redirection & Human Review Draft
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_2_open_redirect_smoke] Assertion 1: Testing unvalidated canary redirection...');

  const vulnerableTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    const url = new URL(req.url);
    const redirectParam = url.searchParams.get('redirect');
    if (redirectParam) {
      return {
        statusCode: 302,
        headers: {
          location: redirectParam,
          'content-type': 'text/html',
        },
        bodyText: '<html>Redirecting...</html>',
        responseTimeMs: 15,
      };
    }
    return {
      statusCode: 200,
      headers: { 'content-type': 'text/html' },
      bodyText: '<html>Home</html>',
      responseTimeMs: 15,
    };
  };

  const unreviewedResult = await runOpenRedirectDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'open_redirect_detection_request',
    detectionId: 'det_redir_001',
    assessmentId: 'asmt_p2_2_001',
    scanId: 'scan_p2_2_001',
    authorizationGrantId: 'grant_p2_2_001',
    authorizationDecisionId: 'dec_p2_2_001',
    actorId: 'usr_secops_auditor',
    endpointUrl: 'https://vulnerable-redirect.example.com/login',
    parameterName: 'redirect',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    transport: vulnerableTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  assert.strictEqual(
    unreviewedResult.status,
    'pending_human_review',
    'Unreviewed detection must route to pending_human_review'
  );
  assert.ok(unreviewedResult.evidenceDraft, 'Evidence draft must be present');
  assert.strictEqual(unreviewedResult.parameterName, 'redirect');
  assert.strictEqual(unreviewedResult.injectedCanary, 'https://canary.fixguard.internal/');
  assert.strictEqual(unreviewedResult.finalDestination, 'https://canary.fixguard.internal/');

  // Now verify promotion with approved human review decision
  const approvedResult = await runOpenRedirectDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'open_redirect_detection_request',
    detectionId: 'det_redir_002',
    assessmentId: 'asmt_p2_2_001',
    scanId: 'scan_p2_2_001',
    authorizationGrantId: 'grant_p2_2_001',
    authorizationDecisionId: 'dec_p2_2_001',
    actorId: 'usr_secops_auditor',
    endpointUrl: 'https://vulnerable-redirect.example.com/login',
    parameterName: 'redirect',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    transport: vulnerableTransport,
    dnsResolver: async () => ['93.184.216.34'],
    humanReviewDecision: {
      decision: 'approve_evidence',
      reviewerId: 'operator_sec_lead',
      reviewedAt: new Date().toISOString(),
    },
  });

  assert.strictEqual(
    approvedResult.status,
    'exploit_confirmed',
    'Approved review must yield exploit_confirmed status'
  );
  assert.ok(approvedResult.finding, 'Approved result must contain a formal Finding');
  assert.strictEqual(
    approvedResult.finding.metadata.kind,
    'open_redirect_metadata',
    'Finding must carry OpenRedirectMetadata'
  );
  assert.strictEqual(approvedResult.finding.type, 'INPUT_VALIDATION_FLAW');

  console.log('[milestoneP2_2_open_redirect_smoke] Assertion 1 PASSED: Unvalidated redirection detected and metadata built.');

  // ---------------------------------------------------------------------------
  // Assertion 2: Secure Target Abstention (Destination Allowlist / Relative Path)
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_2_open_redirect_smoke] Assertion 2: Testing secure target abstention...');

  const secureTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    // Sanitizes destination to relative path '/dashboard'
    return {
      statusCode: 302,
      headers: {
        location: '/dashboard',
        'content-type': 'text/html',
      },
      bodyText: '<html>Redirecting to dashboard</html>',
      responseTimeMs: 10,
    };
  };

  const secureResult = await runOpenRedirectDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'open_redirect_detection_request',
    detectionId: 'det_redir_003',
    assessmentId: 'asmt_p2_2_001',
    scanId: 'scan_p2_2_001',
    authorizationGrantId: 'grant_p2_2_001',
    authorizationDecisionId: 'dec_p2_2_001',
    actorId: 'usr_secops_auditor',
    endpointUrl: 'https://secure-target.example.com/login',
    parameterName: 'redirect',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    transport: secureTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  assert.strictEqual(
    secureResult.status,
    'secure_target_abstained',
    'Sanitized redirect destination must trigger secure_target_abstained'
  );
  assert.strictEqual(secureResult.finding, undefined, 'No finding created for secure target');
  assert.strictEqual(secureResult.evidenceDraft, undefined, 'No draft created for secure target');

  console.log('[milestoneP2_2_open_redirect_smoke] Assertion 2 PASSED: Secure target cleanly abstained.');

  // ---------------------------------------------------------------------------
  // Assertion 3: SSRF Egress Gate Containment
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_2_open_redirect_smoke] Assertion 3: Testing SSRF destination containment...');

  const ssrfRedirectTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    return {
      statusCode: 302,
      headers: {
        location: 'http://169.254.169.254/latest/meta-data/',
        'content-type': 'text/html',
      },
      bodyText: '<html>SSRF Redirect</html>',
      responseTimeMs: 10,
    };
  };

  const ssrfResult = await runOpenRedirectDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'open_redirect_detection_request',
    detectionId: 'det_redir_004',
    assessmentId: 'asmt_p2_2_001',
    scanId: 'scan_p2_2_001',
    authorizationGrantId: 'grant_p2_2_001',
    authorizationDecisionId: 'dec_p2_2_001',
    actorId: 'usr_secops_auditor',
    endpointUrl: 'https://vulnerable-redirect.example.com/auth',
    parameterName: 'next',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    transport: ssrfRedirectTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  assert.strictEqual(
    ssrfResult.status,
    'preflight_denied',
    'SSRF destination redirect must be blocked fail-closed'
  );
  assert.strictEqual(
    ssrfResult.reasonCode,
    'ssrf_destination_blocked',
    'Must specify ssrf_destination_blocked reason code'
  );

  console.log('[milestoneP2_2_open_redirect_smoke] Assertion 3 PASSED: SSRF destination safely blocked.');

  // ---------------------------------------------------------------------------
  // Assertion 4: Orchestrated Assessment Pipeline Integration & Human Review Triage
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_2_open_redirect_smoke] Assertion 4: Testing Orchestrated Assessment Pipeline & Triage...');

  const repository = new InMemoryOrchestratedAssessmentRepository();
  const mockAvailabilityService = new ReconToolAvailabilityService({
    async execute() {
      return { stdout: '1.0.0\n', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
    },
  });

  const orchestrator = new OrchestratedAssessmentApplicationService({
    repository,
    reconAdapters: createMockAdapters(),
    httpTransport: vulnerableTransport,
    dnsResolver: async () => ['93.184.216.34'],
    availabilityService: mockAvailabilityService,
  });

  const startRes = await orchestrator.startAssessment({
    targetDomain: 'vulnerable-redirect.example.com',
    actorId: 'human_operator_42',
  });

  assert.strictEqual(startRes.status, 'running');

  const record = await orchestrator.awaitAssessment(startRes.assessmentId);
  assert.ok(record, 'Assessment record must exist');
  assert.strictEqual(record.status, 'completed');
  assert.ok((record.pendingEvidenceDrafts ?? []).length > 0, 'Must have pending drafts');

  const openRedirectDraft = record.pendingEvidenceDrafts?.find(
    (d) => d.differentialContext?.detectionKind === 'open_redirect'
  );
  assert.ok(openRedirectDraft, 'Must contain open_redirect draft in pending drafts');

  // Triage: Human operator approves the draft
  const reviewRes = await orchestrator.reviewEvidenceDraft({
    assessmentId: startRes.assessmentId,
    draftId: openRedirectDraft.draftId,
    decision: 'approve_evidence',
    reviewerId: 'authorized_sec_lead',
    reviewedAt: new Date().toISOString(),
    notes: 'Verified canary redirection on redirect parameter',
  });

  assert.strictEqual(reviewRes.decision, 'approve_evidence');
  assert.ok(reviewRes.findingCreated, 'Must have promoted finding');
  assert.strictEqual(reviewRes.findingCreated.metadata.kind, 'open_redirect_metadata');

  // Verify updated summary
  const updatedSummary = await orchestrator.getSummary(startRes.assessmentId);
  const foundInSummary = updatedSummary.findings.find(
    (f) => f.metadata.kind === 'open_redirect_metadata'
  );
  assert.ok(foundInSummary, 'Promoted Open Redirect finding must be present in assessment findings');

  console.log('[milestoneP2_2_open_redirect_smoke] Assertion 4 PASSED: Pipeline and human review triage lifecycle verified.');

  console.log('----------------------------------------------------------------');
  console.log('[milestoneP2_2_open_redirect_smoke] ALL SMOKE TESTS PASSED (100%)');
  console.log('----------------------------------------------------------------');
}

runTests().catch((err) => {
  console.error('[milestoneP2_2_open_redirect_smoke] FAILED:', err);
  process.exit(1);
});
