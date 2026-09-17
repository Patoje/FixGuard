/**
 * Milestone P4-4 Smoke Test Suite
 * WordPress XML-RPC and User Enumeration Probes (Milestone P4-4)
 *
 * Verifies:
 * 1. Detects exposed XML-RPC and verifies system.multicall presence.
 * 2. Detects REST API user enumeration and captures sanitized user slugs.
 * 3. Cleanly abstains (secure_target_abstained) when surfaces return 401/403 or are disabled.
 * 4. Preflight and egress gates block SSRF / internal targets.
 * 5. Full HITL triage lifecycle promotes drafts to formal Findings.
 */

import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import { runWordPressSurfaceDetection } from '../detection/WordPressSurfaceDetectionService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { evaluateScopePolicy } from '../scope/AuthorizedScopePolicyService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type {
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from '../detection/DetectionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { Finding } from '../core/Evidence.js';

console.log('[milestoneP4_4_wordpress_surface_smoke] Starting Milestone P4-4 smoke suite...');

async function runTests(): Promise<void> {
  const lineage = {
    assessmentId: 'asm_test_p44_001',
    scanId: 'scn_test_p44_001',
    authorizationGrantId: 'grnt_test_p44_001',
    authorizationDecisionId: 'dec_test_p44_001',
    actorId: 'usr_secops_lead',
  };

  const decidedAt = new Date().toISOString();

  const scopeGrant: AuthorizedScopeGrant = {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: lineage.authorizationGrantId,
    scanId: lineage.scanId,
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'origin',
      normalizedOrigin: 'https://wp.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone P4-4 WordPress Surface smoke testing',
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
      allowedDomains: ['wp.example.com'],
      allowedHosts: ['wp.example.com'],
      allowedOrigins: ['https://wp.example.com'],
      allowedMethods: ['GET', 'HEAD', 'POST'],
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

  const authDecisionResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      authorizedActor: { actorId: lineage.actorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt,
      scopeGrant,
    },
    decidedAt
  );

  if (authDecisionResult.status !== 'established' || !authDecisionResult.decision) {
    const errorMsg = 'safeMessage' in authDecisionResult ? authDecisionResult.safeMessage : 'establishment failed';
    throw new Error(`Pre-test failure: authorization decision failed: ${errorMsg}`);
  }

  const verifiedDecision = authDecisionResult.decision;

  const scopeResult = evaluateScopePolicy({
    grant: verifiedDecision.scopeGrant,
    request: {
      contractVersion: 'fixguard-authorized-scope-policy/v0',
      kind: 'scope_action_request',
      requestId: 'req_scope_001',
      scanId: lineage.scanId,
      requestedAt: decidedAt,
      actionKind: 'endpoint_discovery',
      target: { targetKind: 'origin', normalizedOrigin: 'https://wp.example.com' },
      method: 'GET',
      pathTemplate: '/wp-json/wp/v2/users',
      intensity: 'low',
      usesCredentials: false,
      mayChangeServerState: false,
      usesOob: false,
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
    },
    decisionId: 'eval_scope_001',
    evaluatedAt: decidedAt,
  });

  if (scopeResult.decision !== 'allowed') {
    throw new Error(`Pre-test failure: scope policy evaluation denied: ${scopeResult.reasonCode}`);
  }

  const mockDnsResolver = async (host: string) => {
    if (host === 'wp.example.com') return ['93.184.216.34'];
    if (host === '127.0.0.1' || host === 'localhost') return ['127.0.0.1'];
    return ['93.184.216.34'];
  };

  const mockXmlRpcPayload = `<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value><string>system.listMethods</string></value>
            <value><string>system.multicall</string></value>
            <value><string>wp.getUsersBlogs</string></value>
            <value><string>wp.getPage</string></value>
            <value><string>wp.getPosts</string></value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>`;

  const mockUsersPayload = JSON.stringify([
    { id: 1, name: 'Site Administrator', slug: 'admin', link: 'https://wp.example.com/author/admin' },
    { id: 2, name: 'Editor Lead', slug: 'editor_john', link: 'https://wp.example.com/author/editor_john' },
    { id: 3, name: 'Contributor Jane', slug: 'jane_dev', link: 'https://wp.example.com/author/jane_dev' },
  ]);

  // --- Test 1: Detects Exposed XML-RPC & system.multicall Support ---
  console.log('--- Test 1: Detects exposed XML-RPC and system.multicall presence ---');
  {
    const mockXmlRpcTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.url === 'https://wp.example.com/xmlrpc.php' && req.method === 'POST') {
        return {
          statusCode: 200,
          headers: { 'content-type': 'text/xml' },
          bodyText: mockXmlRpcPayload,
          responseTimeMs: 30,
        };
      }
      return { statusCode: 404, headers: {}, bodyText: 'Not Found', responseTimeMs: 15 };
    };

    const result = await runWordPressSurfaceDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'wordpress_surface_detection_request',
      detectionId: 'det_wp_test_001',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      targetBaseUrl: 'https://wp.example.com',
      probeKind: 'xmlrpc_capabilities',
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      transport: mockXmlRpcTransport,
      dnsResolver: mockDnsResolver,
    });

    if (result.status !== 'pending_human_review') {
      throw new Error(`Test 1 Failed: Expected pending_human_review, got ${result.status}`);
    }

    if (!result.evidenceDraft) {
      throw new Error('Test 1 Failed: Missing evidenceDraft');
    }

    if (!result.multicallSupported) {
      throw new Error('Test 1 Failed: system.multicall was not detected');
    }

    if (!result.xmlRpcMethodsExposed?.includes('system.multicall')) {
      throw new Error('Test 1 Failed: system.multicall missing from xmlRpcMethodsExposed');
    }

    console.log('✓ Test 1 Passed: Exposed XML-RPC and system.multicall successfully detected');
  }

  // --- Test 2: Detects REST API User Enumeration ---
  console.log('--- Test 2: Detects REST API user enumeration and extracts user slugs ---');
  {
    const mockUsersTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.url === 'https://wp.example.com/wp-json/wp/v2/users' && req.method === 'GET') {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: mockUsersPayload,
          responseTimeMs: 25,
        };
      }
      return { statusCode: 404, headers: {}, bodyText: 'Not Found', responseTimeMs: 15 };
    };

    const result = await runWordPressSurfaceDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'wordpress_surface_detection_request',
      detectionId: 'det_wp_test_002',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      targetBaseUrl: 'https://wp.example.com',
      probeKind: 'rest_user_enumeration',
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      transport: mockUsersTransport,
      dnsResolver: mockDnsResolver,
    });

    if (result.status !== 'pending_human_review') {
      throw new Error(`Test 2 Failed: Expected pending_human_review, got ${result.status}`);
    }

    if (result.exposedUsersCount !== 3) {
      throw new Error(`Test 2 Failed: Expected 3 users, got ${result.exposedUsersCount}`);
    }

    if (!result.sampleUserSlugs?.includes('admin') || !result.sampleUserSlugs?.includes('editor_john')) {
      throw new Error(`Test 2 Failed: Slugs missing expected usernames: ${JSON.stringify(result.sampleUserSlugs)}`);
    }

    console.log('✓ Test 2 Passed: REST API user enumeration accurately detected');
  }

  // --- Test 3: Clean Abstention on Disabled / Hardened WordPress Surfaces ---
  console.log('--- Test 3: Cleanly abstains (secure_target_abstained) when surfaces return 401/403/404 ---');
  {
    const mockHardenedTransport: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => ({
      statusCode: 403,
      headers: { 'content-type': 'application/json' },
      bodyText: JSON.stringify({ code: 'rest_cannot_view', message: 'Sorry, you are not allowed to view users.' }),
      responseTimeMs: 15,
    });

    const result = await runWordPressSurfaceDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'wordpress_surface_detection_request',
      detectionId: 'det_wp_test_003',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      targetBaseUrl: 'https://wp.example.com',
      probeKind: 'all',
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      transport: mockHardenedTransport,
      dnsResolver: mockDnsResolver,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`Test 3 Failed: Expected secure_target_abstained, got ${result.status}`);
    }

    console.log('✓ Test 3 Passed: Hardened WordPress surfaces cleanly abstained');
  }

  // --- Test 4: Preflight SSRF Safety Gate Blocks Internal / Loopback Targets ---
  console.log('--- Test 4: Preflight and egress gates block SSRF targets ---');
  {
    const loopbackTransport: IdorHttpProbeTransport = async () => {
      throw new Error('Should never reach transport due to SSRF preflight block');
    };

    const ssrfResult = await runWordPressSurfaceDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'wordpress_surface_detection_request',
      detectionId: 'det_wp_test_004',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      targetBaseUrl: 'http://127.0.0.1',
      probeKind: 'xmlrpc_capabilities',
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      transport: loopbackTransport,
      dnsResolver: mockDnsResolver,
    });

    if (ssrfResult.status !== 'preflight_denied') {
      throw new Error(`Test 4 Failed: Expected preflight_denied for loopback target, got ${ssrfResult.status}`);
    }

    console.log('✓ Test 4 Passed: SSRF target safely blocked at preflight boundary');
  }

  // --- Test 5: Full HITL Triage Lifecycle Promotes Draft to Formal Finding ---
  console.log('--- Test 5: Full HITL triage lifecycle promotes draft to formal Finding ---');
  {
    const repo = new InMemoryOrchestratedAssessmentRepository();
    const toolService = new ReconToolAvailabilityService({
      async execute() {
        return { stdout: '1.0.0\n', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
      },
    });

    const mockWpTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.url.includes('/xmlrpc.php')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'text/xml' },
          bodyText: mockXmlRpcPayload,
          responseTimeMs: 25,
        };
      }
      if (req.url.includes('/wp-json/wp/v2/users')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: mockUsersPayload,
          responseTimeMs: 20,
        };
      }
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        bodyText: '<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2"></head><body>WordPress Blog</body></html>',
        responseTimeMs: 20,
      };
    };

    const service = new OrchestratedAssessmentApplicationService({
      repository: repo,
      availabilityService: toolService,
      httpTransport: mockWpTransport,
      dnsResolver: mockDnsResolver,
    });

    const startRes = await service.startAssessment({
      targetDomain: 'wp.example.com',
      actorId: 'usr_secops_lead',
    });

    if (startRes.status !== 'running') {
      throw new Error(`Test 5 Failed: Assessment did not start with running status: ${startRes.status}`);
    }

    let attempts = 0;
    let status = await service.getStatus(startRes.assessmentId);
    while (status.status === 'running' && attempts < 100) {
      await new Promise((r) => setTimeout(r, 100));
      status = await service.getStatus(startRes.assessmentId);
      attempts++;
    }

    const draftsResponse = await service.getEvidenceDrafts(startRes.assessmentId);
    const xmlDraft = draftsResponse.drafts.find(
      (d) => d.differentialContext?.detectionKind === 'wordpress_surface' && d.differentialContext?.wpProbeKind === 'xmlrpc_capabilities'
    );
    const usersDraft = draftsResponse.drafts.find(
      (d) => d.differentialContext?.detectionKind === 'wordpress_surface' && d.differentialContext?.wpProbeKind === 'rest_user_enumeration'
    );

    if (!xmlDraft) {
      throw new Error('Test 5 Failed: XML-RPC draft missing from pending drafts');
    }
    if (!usersDraft) {
      throw new Error('Test 5 Failed: REST users draft missing from pending drafts');
    }

    // Review & Approve XML-RPC draft
    const reviewXml = await service.reviewEvidenceDraft({
      assessmentId: startRes.assessmentId,
      draftId: xmlDraft.draftId,
      decision: 'approve_evidence',
      reviewerId: 'usr_auditor_01',
      reviewedAt: new Date().toISOString(),
      notes: 'Confirmed exposed XML-RPC with multicall amplification',
    });

    if (reviewXml.decision !== 'approve_evidence') {
      throw new Error(`Test 5 Failed: XML-RPC draft review approval failed`);
    }

    // Review & Approve Users draft
    const reviewUsers = await service.reviewEvidenceDraft({
      assessmentId: startRes.assessmentId,
      draftId: usersDraft.draftId,
      decision: 'approve_evidence',
      reviewerId: 'usr_auditor_01',
      reviewedAt: new Date().toISOString(),
      notes: 'Confirmed public user listing via REST API',
    });

    if (reviewUsers.decision !== 'approve_evidence') {
      throw new Error(`Test 5 Failed: Users draft review approval failed`);
    }

    const summary = await service.getSummary(startRes.assessmentId);
    const xmlFinding = summary.findings.find(
      (f: Finding) => f.metadata?.kind === 'wordpress_surface_metadata' && f.metadata.probeKind === 'xmlrpc_capabilities'
    );
    const usersFinding = summary.findings.find(
      (f: Finding) => f.metadata?.kind === 'wordpress_surface_metadata' && f.metadata.probeKind === 'rest_user_enumeration'
    );

    if (!xmlFinding) {
      throw new Error('Test 5 Failed: Promoted XML-RPC finding not found in summary');
    }
    if (!usersFinding) {
      throw new Error('Test 5 Failed: Promoted users finding not found in summary');
    }

    if (xmlFinding.severity !== 'medium' || xmlFinding.type !== 'SECURITY_MISCONFIGURATION') {
      throw new Error(`Test 5 Failed: XML-RPC finding type/severity mismatch: ${xmlFinding.type} / ${xmlFinding.severity}`);
    }

    if (usersFinding.severity !== 'medium' || usersFinding.type !== 'INFORMATION_DISCLOSURE') {
      throw new Error(`Test 5 Failed: Users finding type/severity mismatch: ${usersFinding.type} / ${usersFinding.severity}`);
    }

    console.log('✓ Test 5 Passed: HITL review approved and promoted WordPress surface drafts to formal Findings');
  }

  console.log('\n[milestoneP4_4_wordpress_surface_smoke] ALL 5 TESTS PASSED SUCCESSFULLY! (100% compliant)');
}

runTests().catch((err) => {
  console.error('[milestoneP4_4_wordpress_surface_smoke] FATAL SMOKE ERROR:', err);
  process.exit(1);
});
