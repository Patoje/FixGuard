/**
 * Milestone P4-3 Smoke Test Suite
 * Sourcemap Exposure Detection Engine (Milestone P4-3)
 *
 * Verifies:
 * 1. Detects accessible .map file from sourceMappingURL comment and builds SourcemapExposureMetadata.
 * 2. Detects accessible .map file from SourceMap HTTP response header.
 * 3. Cleanly abstains (secure_target_abstained) when .map request returns 404/403 or non-sourcemap payload.
 * 4. Preflight and egress gates block SSRF targets.
 * 5. Full HITL triage lifecycle promotes draft to formal Finding.
 */

import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import { runSourcemapExposureDetection, extractSourcemapUrlAndSignal } from '../detection/SourcemapExposureDetectionService.js';
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

console.log('[milestoneP4_3_sourcemap_exposure_smoke] Starting Milestone P4-3 smoke suite...');

async function runTests(): Promise<void> {
  const lineage = {
    assessmentId: 'asm_test_p43_001',
    scanId: 'scn_test_p43_001',
    authorizationGrantId: 'grnt_test_p43_001',
    authorizationDecisionId: 'dec_test_p43_001',
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
      normalizedOrigin: 'https://spa.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone P4-3 Sourcemap Exposure smoke testing',
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
      allowedDomains: ['spa.example.com'],
      allowedHosts: ['spa.example.com'],
      allowedOrigins: ['https://spa.example.com'],
      allowedMethods: ['GET', 'HEAD'],
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
      target: { targetKind: 'origin', normalizedOrigin: 'https://spa.example.com' },
      method: 'GET',
      pathTemplate: '/static/js/main.js.map',
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

  const mockValidSourcemapPayload = JSON.stringify({
    version: 3,
    file: 'main.js',
    sources: [
      'src/App.tsx',
      'src/components/AuthModal.tsx',
      'src/services/apiClient.ts',
      'src/config/internalEndpoints.ts',
    ],
    names: ['useState', 'useEffect', 'render'],
    mappings: 'AAAA,SAASA,GAAG,GAAG,CACb,OAAO,IAAI,CACb',
  });

  // Mock DNS Resolver allowing spa.example.com to public IP
  const mockDnsResolver = async (host: string) => {
    if (host === 'spa.example.com') return ['93.184.216.34'];
    if (host === '127.0.0.1' || host === 'localhost') return ['127.0.0.1'];
    return ['93.184.216.34'];
  };

  // --- Test 1: Extract Signal and Detect Exposed .map from //# sourceMappingURL comment ---
  console.log('--- Test 1: Detects exposed sourcemap from sourceMappingURL comment ---');
  {
    const jsBody = `
      function main() { console.log("FixGuard SPA Test"); }
      //# sourceMappingURL=main.js.map
    `;

    const extraction = extractSourcemapUrlAndSignal(
      'https://spa.example.com/static/js/main.js',
      undefined,
      jsBody
    );

    if (!extraction || extraction.signal !== 'sourcemapping_url_comment' || extraction.mapUrl !== 'https://spa.example.com/static/js/main.js.map') {
      throw new Error(`Test 1 Failed: Extraction did not resolve comment URL correctly: ${JSON.stringify(extraction)}`);
    }

    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.url === 'https://spa.example.com/static/js/main.js.map') {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: mockValidSourcemapPayload,
          responseTimeMs: 25,
        };
      }
      return { statusCode: 404, headers: {}, bodyText: 'Not Found', responseTimeMs: 15 };
    };

    const result = await runSourcemapExposureDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'sourcemap_exposure_detection_request',
      detectionId: 'det_smap_test_001',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      sourceJsUrl: 'https://spa.example.com/static/js/main.js',
      jsBodyText: jsBody,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      transport: mockTransport,
      dnsResolver: mockDnsResolver,
    });

    if (result.status !== 'pending_human_review') {
      throw new Error(`Test 1 Failed: Expected pending_human_review, received ${result.status} (${result.reasonCode})`);
    }

    if (!result.evidenceDraft) {
      throw new Error('Test 1 Failed: Missing evidenceDraft in result');
    }

    if (result.sampleSourcesCount !== 4) {
      throw new Error(`Test 1 Failed: Expected 4 sample sources, got ${result.sampleSourcesCount}`);
    }

    if (result.detectionSignal !== 'sourcemapping_url_comment') {
      throw new Error(`Test 1 Failed: Expected signal 'sourcemapping_url_comment', got ${result.detectionSignal}`);
    }

    console.log('✓ Test 1 Passed: Detected exposed sourcemap from sourceMappingURL comment');
  }

  // --- Test 2: Detect Exposed .map from SourceMap / X-SourceMap HTTP Response Header ---
  console.log('--- Test 2: Detects exposed sourcemap from SourceMap HTTP header ---');
  {
    const jsHeaders = {
      'content-type': 'application/javascript',
      sourcemap: '/bundles/app.chunk.js.map',
    };

    const extraction = extractSourcemapUrlAndSignal(
      'https://spa.example.com/assets/app.chunk.js',
      undefined,
      undefined,
      jsHeaders
    );

    if (!extraction || extraction.signal !== 'sourcemap_header' || extraction.mapUrl !== 'https://spa.example.com/bundles/app.chunk.js.map') {
      throw new Error(`Test 2 Failed: Extraction did not resolve SourceMap header correctly: ${JSON.stringify(extraction)}`);
    }

    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.url === 'https://spa.example.com/bundles/app.chunk.js.map') {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: mockValidSourcemapPayload,
          responseTimeMs: 30,
        };
      }
      return { statusCode: 404, headers: {}, bodyText: 'Not Found', responseTimeMs: 15 };
    };

    const result = await runSourcemapExposureDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'sourcemap_exposure_detection_request',
      detectionId: 'det_smap_test_002',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      sourceJsUrl: 'https://spa.example.com/assets/app.chunk.js',
      jsHeaders,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      transport: mockTransport,
      dnsResolver: mockDnsResolver,
    });

    if (result.status !== 'pending_human_review') {
      throw new Error(`Test 2 Failed: Expected pending_human_review, received ${result.status}`);
    }

    if (result.detectionSignal !== 'sourcemap_header') {
      throw new Error(`Test 2 Failed: Expected signal 'sourcemap_header', got ${result.detectionSignal}`);
    }

    console.log('✓ Test 2 Passed: Detected exposed sourcemap from SourceMap HTTP response header');
  }

  // --- Test 3: Clean Abstention on 404/403 or Invalid JSON ---
  console.log('--- Test 3: Cleanly abstains (secure_target_abstained) on 404/403 or non-sourcemap payloads ---');
  {
    // Case 3a: 404 Not Found
    const mock404Transport: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => ({
      statusCode: 404,
      headers: {},
      bodyText: '404 File Not Found',
      responseTimeMs: 15,
    });

    const res404 = await runSourcemapExposureDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'sourcemap_exposure_detection_request',
      detectionId: 'det_smap_test_003a',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      sourceJsUrl: 'https://spa.example.com/static/js/secure.js',
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      transport: mock404Transport,
      dnsResolver: mockDnsResolver,
    });

    if (res404.status !== 'secure_target_abstained') {
      throw new Error(`Test 3a Failed: Expected secure_target_abstained for 404, got ${res404.status}`);
    }

    // Case 3b: 200 OK returning HTML (Soft 404 SPA fallback)
    const mockHtmlTransport: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => ({
      statusCode: 200,
      headers: { 'content-type': 'text/html' },
      bodyText: '<!DOCTYPE html><html><body>SPA Root</body></html>',
      responseTimeMs: 20,
    });

    const resHtml = await runSourcemapExposureDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'sourcemap_exposure_detection_request',
      detectionId: 'det_smap_test_003b',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      sourceJsUrl: 'https://spa.example.com/static/js/soft404.js',
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      transport: mockHtmlTransport,
      dnsResolver: mockDnsResolver,
    });

    if (resHtml.status !== 'secure_target_abstained') {
      throw new Error(`Test 3b Failed: Expected secure_target_abstained for HTML soft-404, got ${resHtml.status}`);
    }

    console.log('✓ Test 3 Passed: Cleanly abstains on 404 and non-sourcemap payloads');
  }

  // --- Test 4: Preflight SSRF Safety Gate Blocks Internal / Loopback Targets ---
  console.log('--- Test 4: Preflight and egress gates block SSRF targets ---');
  {
    const loopbackTransport: IdorHttpProbeTransport = async () => {
      throw new Error('Should never reach transport due to SSRF preflight block');
    };

    const ssrfResult = await runSourcemapExposureDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'sourcemap_exposure_detection_request',
      detectionId: 'det_smap_test_004',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      sourceJsUrl: 'http://127.0.0.1/bundle.js',
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      transport: loopbackTransport,
      dnsResolver: mockDnsResolver,
    });

    if (ssrfResult.status !== 'preflight_denied') {
      throw new Error(`Test 4 Failed: Expected preflight_denied for loopback target, got ${ssrfResult.status}`);
    }

    console.log('✓ Test 4 Passed: SSRF target cleanly blocked at preflight boundary');
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

    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.url.endsWith('.map')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: mockValidSourcemapPayload,
          responseTimeMs: 25,
        };
      }
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        bodyText: '<!DOCTYPE html><html><head><script src="/bundle.js"></script></head><body>SPA App</body></html>',
        responseTimeMs: 20,
      };
    };

    const service = new OrchestratedAssessmentApplicationService({
      repository: repo,
      availabilityService: toolService,
      httpTransport: mockTransport,
      dnsResolver: mockDnsResolver,
    });

    const startRes = await service.startAssessment({
      targetDomain: 'spa.example.com',
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
    const smapDraft = draftsResponse.drafts.find(
      (d) => d.differentialContext?.detectionKind === 'sourcemap_exposure'
    );

    if (!smapDraft) {
      throw new Error('Test 5 Failed: No sourcemap_exposure draft found in pending drafts');
    }

    if (smapDraft.differentialContext?.sampleSourcesCount !== 4) {
      throw new Error(`Test 5 Failed: Expected 4 sample sources in draft context, got ${smapDraft.differentialContext?.sampleSourcesCount}`);
    }

    // Perform HITL Review -> Approve Evidence
    const reviewResult = await service.reviewEvidenceDraft({
      assessmentId: startRes.assessmentId,
      draftId: smapDraft.draftId,
      decision: 'approve_evidence',
      reviewerId: 'usr_auditor_01',
      reviewedAt: new Date().toISOString(),
      notes: 'Confirmed accessible production sourcemap leaking source code',
    });

    if (reviewResult.decision !== 'approve_evidence') {
      throw new Error(`Test 5 Failed: Review approval failed: ${JSON.stringify(reviewResult)}`);
    }

    const summary = await service.getSummary(startRes.assessmentId);
    const smapFinding = summary.findings.find((f: Finding) => f.type === 'INFORMATION_DISCLOSURE');

    if (!smapFinding) {
      throw new Error('Test 5 Failed: Finding not found in summary');
    }

    if (smapFinding.severity !== 'medium') {
      throw new Error(`Test 5 Failed: Unexpected finding severity: ${smapFinding.severity}`);
    }

    if (smapFinding.metadata?.kind !== 'sourcemap_exposure_metadata') {
      throw new Error(`Test 5 Failed: Unexpected finding metadata kind: ${smapFinding.metadata?.kind}`);
    }

    if (smapFinding.metadata?.sampleSourcesCount !== 4) {
      throw new Error(`Test 5 Failed: Finding sampleSourcesCount mismatch: ${smapFinding.metadata?.sampleSourcesCount}`);
    }

    console.log('✓ Test 5 Passed: HITL review approved and promoted sourcemap draft to formal Finding');
  }

  console.log('\n[milestoneP4_3_sourcemap_exposure_smoke] ALL 5 TESTS PASSED SUCCESSFULLY! (100% compliant)');
}

runTests().catch((err) => {
  console.error('[milestoneP4_3_sourcemap_exposure_smoke] FATAL SMOKE ERROR:', err);
  process.exit(1);
});
