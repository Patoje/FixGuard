/**
 * Milestone P4-10 Smoke Test Suite
 * CMS Plugin Vulnerability Surface (Milestone P4-10 — Phase 4 Finale)
 *
 * Verifies:
 * 1. Detects outdated plugin from readme.txt Stable tag against local JSON reference.
 * 2. Cleanly abstains (secure_target_abstained) when plugin is current.
 * 3. Cleanly abstains when readme.txt returns 404 or is inaccessible.
 * 4. Preflight and egress gates block internal/SSRF targets.
 * 5. Full HITL triage lifecycle promotes drafts to formal Findings.
 */

import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import { runCmsPluginVulnerabilityDetection } from '../detection/CmsPluginVulnerabilityDetectionService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type {
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from '../detection/DetectionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { Finding, CmsPluginVulnerabilityMetadata } from '../core/Evidence.js';

console.log('[milestoneP4_10_cms_plugin_surface_smoke] Starting Milestone P4-10 smoke suite...');

async function runTests(): Promise<void> {
  const lineage = {
    assessmentId: 'asm_test_p410_001',
    scanId: 'scn_test_p410_001',
    authorizationGrantId: 'grnt_test_p410_001',
    authorizationDecisionId: 'dec_test_p410_001',
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
      normalizedOrigin: 'https://app.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone P4-10 CMS Plugin smoke testing',
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
      allowedDomains: ['app.example.com'],
      allowedHosts: ['app.example.com'],
      allowedOrigins: ['https://app.example.com'],
      allowedMethods: ['GET', 'HEAD', 'POST'],
    },
    constraints: {
      allowLoginRequiredAreas: false,
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
    throw new Error('Failed to establish verified authorization decision for smoke test');
  }

  const authDecision = authDecisionResult.decision;

  // -------------------------------------------------------------------------
  // Test 1: Detects outdated plugin from readme.txt Stable tag against JSON ref
  // -------------------------------------------------------------------------
  console.log('--- Test 1: Detects outdated plugin from readme.txt Stable tag ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.url.includes('/woocommerce/readme.txt')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
          bodyText: `=== WooCommerce ===\nContributors: automattic\nTags: e-commerce, store\nRequires at least: 6.2\nTested up to: 6.4\nStable tag: 8.4.0\nLicense: GPLv3\n\n== Description ==\nAn eCommerce toolkit.`,
          responseTimeMs: 25,
        };
      }
      return {
        statusCode: 404,
        headers: { 'content-type': 'text/html' },
        bodyText: '404 Not Found',
        responseTimeMs: 20,
      };
    };

    const result = await runCmsPluginVulnerabilityDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'cms_plugin_vulnerability_detection_request',
      detectionId: 'det_test_p410_wc',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      targetBaseUrl: 'https://app.example.com',
      pluginSlug: 'woocommerce',
      cmsType: 'wordpress',
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      transport: mockTransport,
      humanReviewDecision: {
        reviewerId: 'usr_secops_lead',
        reviewedAt: new Date().toISOString(),
        decision: 'approve_evidence',
      },
    });

    if (result.status !== 'potential_weakness') {
      throw new Error(`Test 1 Failed: Expected status 'potential_weakness', got '${result.status}'`);
    }
    if (result.detectedVersion !== '8.4.0') {
      throw new Error(`Test 1 Failed: Expected detectedVersion '8.4.0', got '${result.detectedVersion}'`);
    }
    if (result.minimumSafeVersion !== '8.5.0') {
      throw new Error(`Test 1 Failed: Expected minimumSafeVersion '8.5.0', got '${result.minimumSafeVersion}'`);
    }
    if (result.isOutdated !== true) {
      throw new Error('Test 1 Failed: Expected isOutdated to be true');
    }
    if (!result.finding) {
      throw new Error('Test 1 Failed: Expected finding to be constructed');
    }
    const meta = result.finding.metadata as CmsPluginVulnerabilityMetadata;
    if (meta.kind !== 'cms_plugin_vulnerability_metadata' || meta.category !== 'SECURITY_MISCONFIGURATION') {
      throw new Error(`Test 1 Failed: Invalid metadata: ${JSON.stringify(meta)}`);
    }
    if (meta.pluginSlug !== 'woocommerce' || meta.detectedVersion !== '8.4.0') {
      throw new Error(`Test 1 Failed: Invalid plugin details in metadata: ${JSON.stringify(meta)}`);
    }

    console.log('✓ Test 1 Passed: Outdated plugin detected accurately');
  }

  // -------------------------------------------------------------------------
  // Test 2: Cleanly abstains when plugin is current / up-to-date
  // -------------------------------------------------------------------------
  console.log('--- Test 2: Cleanly abstains when plugin is current / up-to-date ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.url.includes('/elementor/readme.txt')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'text/plain' },
          bodyText: `=== Elementor Website Builder ===\nStable tag: 3.18.2\nLicense: GPLv3`,
          responseTimeMs: 20,
        };
      }
      return {
        statusCode: 404,
        headers: { 'content-type': 'text/html' },
        bodyText: '404 Not Found',
        responseTimeMs: 20,
      };
    };

    const result = await runCmsPluginVulnerabilityDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'cms_plugin_vulnerability_detection_request',
      detectionId: 'det_test_p410_current',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      targetBaseUrl: 'https://app.example.com',
      pluginSlug: 'elementor',
      cmsType: 'wordpress',
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      transport: mockTransport,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`Test 2 Failed: Expected status 'secure_target_abstained', got '${result.status}'`);
    }
    if (result.reasonCode !== 'plugin_version_up_to_date') {
      throw new Error(`Test 2 Failed: Expected reasonCode 'plugin_version_up_to_date', got '${result.reasonCode}'`);
    }
    if (result.isOutdated !== false) {
      throw new Error('Test 2 Failed: Expected isOutdated to be false');
    }

    console.log('✓ Test 2 Passed: Up-to-date plugin cleanly abstained');
  }

  // -------------------------------------------------------------------------
  // Test 3: Cleanly abstains when readme.txt returns 404
  // -------------------------------------------------------------------------
  console.log('--- Test 3: Cleanly abstains when readme.txt returns 404 ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => {
      return {
        statusCode: 404,
        headers: { 'content-type': 'text/html' },
        bodyText: '<html><body>404 Not Found</body></html>',
        responseTimeMs: 20,
      };
    };

    const result = await runCmsPluginVulnerabilityDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'cms_plugin_vulnerability_detection_request',
      detectionId: 'det_test_p410_404',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      targetBaseUrl: 'https://app.example.com',
      pluginSlug: 'contact-form-7',
      cmsType: 'wordpress',
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      transport: mockTransport,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`Test 3 Failed: Expected status 'secure_target_abstained', got '${result.status}'`);
    }
    if (result.reasonCode !== 'readme_not_exposed') {
      throw new Error(`Test 3 Failed: Expected reasonCode 'readme_not_exposed', got '${result.reasonCode}'`);
    }

    console.log('✓ Test 3 Passed: 404 / unexposed readme cleanly abstained');
  }

  // -------------------------------------------------------------------------
  // Test 4: Preflight and egress gates block internal/SSRF targets
  // -------------------------------------------------------------------------
  console.log('--- Test 4: Preflight and egress gates block internal/SSRF targets ---');
  {
    const internalScopeGrant: AuthorizedScopeGrant = {
      ...scopeGrant,
      subject: {
        targetKind: 'origin',
        normalizedOrigin: 'http://169.254.169.254',
      },
      boundaries: {
        allowedDomains: ['169.254.169.254'],
        allowedHosts: ['169.254.169.254'],
        allowedOrigins: ['http://169.254.169.254'],
        allowedMethods: ['GET'],
      },
    };

    const internalAuthDecisionResult = establishVerifiedAuthorizationDecision(
      {
        contractVersion: 'fixguard-verified-authorization-decision/v0',
        kind: 'establish_verified_authorization_decision_request',
        assessmentId: lineage.assessmentId,
        scanId: lineage.scanId,
        authorizationDecisionId: lineage.authorizationDecisionId,
        authorizedActor: { actorId: lineage.actorId, actorType: 'human' },
        decision: 'authorized',
        decidedAt,
        scopeGrant: internalScopeGrant,
      },
      decidedAt
    );

    if (internalAuthDecisionResult.status !== 'established' || !internalAuthDecisionResult.decision) {
      throw new Error('Failed to establish internal auth decision');
    }

    const result = await runCmsPluginVulnerabilityDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'cms_plugin_vulnerability_detection_request',
      detectionId: 'det_test_p410_ssrf',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      targetBaseUrl: 'http://169.254.169.254',
      pluginSlug: 'woocommerce',
      cmsType: 'wordpress',
      verifiedAuthorizationDecision: internalAuthDecisionResult.decision,
      scopeGrant: internalScopeGrant,
    });

    if (result.status !== 'preflight_denied') {
      throw new Error(`Test 4 Failed: Expected status 'preflight_denied', got '${result.status}'`);
    }

    console.log('✓ Test 4 Passed: SSRF target safely blocked at preflight boundary');
  }

  // -------------------------------------------------------------------------
  // Test 5: Full HITL triage lifecycle promotes drafts to formal Findings
  // -------------------------------------------------------------------------
  console.log('--- Test 5: Full HITL triage lifecycle promotes drafts to formal Findings ---');
  {
    const repository = new InMemoryOrchestratedAssessmentRepository();
    const availabilityService = new ReconToolAvailabilityService({
      async execute() {
        return { stdout: '1.0.0\n', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
      },
    });

    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.url.includes('/woocommerce/readme.txt')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'text/plain' },
          bodyText: `=== WooCommerce ===\nStable tag: 8.3.0\nLicense: GPLv3`,
          responseTimeMs: 20,
        };
      }
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        bodyText: `<html><body>App active on ${req.url}</body></html>`,
        responseTimeMs: 20,
      };
    };

    const mockDnsResolver = async (_host: string): Promise<string[]> => ['93.184.216.34'];

    const appService = new OrchestratedAssessmentApplicationService({
      repository,
      availabilityService,
      httpTransport: mockTransport,
      dnsResolver: mockDnsResolver,
    });

    const startRes = await appService.startAssessment({
      targetDomain: 'app.example.com',
      actorId: 'usr_secops_lead',
    });

    if (startRes.status !== 'running') {
      throw new Error(`Test 5 Failed: Assessment did not start with running status: ${startRes.status}`);
    }

    let attempts = 0;
    let status = await appService.getStatus(startRes.assessmentId);
    while (status.status === 'running' && attempts < 100) {
      await new Promise((r) => setTimeout(r, 100));
      status = await appService.getStatus(startRes.assessmentId);
      attempts++;
    }

    const draftsResponse = await appService.getEvidenceDrafts(startRes.assessmentId);
    const cmsDraft = draftsResponse.drafts.find(
      (d) => d.differentialContext?.detectionKind === 'cms_plugin_vulnerability'
    );

    if (!cmsDraft) {
      throw new Error(`Test 5 Failed: Expected pending CMS Plugin draft, found: ${JSON.stringify(draftsResponse.drafts.map((d) => d.differentialContext?.detectionKind))}`);
    }

    if (cmsDraft.differentialContext?.pluginSlug !== 'woocommerce' || cmsDraft.differentialContext?.detectedVersion !== '8.3.0') {
      throw new Error(`Test 5 Failed: Unexpected draft details: ${JSON.stringify(cmsDraft.differentialContext)}`);
    }

    // Perform HITL review promotion
    const reviewResult = await appService.reviewEvidenceDraft({
      assessmentId: startRes.assessmentId,
      draftId: cmsDraft.draftId,
      decision: 'approve_evidence',
      reviewerId: 'usr_secops_lead',
      reviewedAt: new Date().toISOString(),
      notes: 'Confirmed outdated WooCommerce plugin in staging environment.',
    });

    if (reviewResult.decision !== 'approve_evidence' || !reviewResult.findingCreated) {
      throw new Error(`Test 5 Failed: Review promotion failed: ${JSON.stringify(reviewResult)}`);
    }

    const promotedFinding = reviewResult.findingCreated;
    if (promotedFinding.type !== 'SECURITY_MISCONFIGURATION') {
      throw new Error(`Test 5 Failed: Expected finding type 'SECURITY_MISCONFIGURATION', got '${promotedFinding.type}'`);
    }

    const findingMeta = promotedFinding.metadata as CmsPluginVulnerabilityMetadata;
    if (findingMeta.kind !== 'cms_plugin_vulnerability_metadata' || findingMeta.pluginSlug !== 'woocommerce') {
      throw new Error(`Test 5 Failed: Invalid promoted finding metadata: ${JSON.stringify(findingMeta)}`);
    }

    const summary = await appService.getSummary(startRes.assessmentId);
    const summaryFinding = summary.findings.find((f: Finding) => f.metadata?.kind === 'cms_plugin_vulnerability_metadata');
    if (!summaryFinding) {
      throw new Error('Test 5 Failed: Promoted CMS Plugin finding not found in assessment summary');
    }

    console.log('✓ Test 5 Passed: HITL review approved and promoted CMS Plugin draft to formal Finding');
  }

  console.log('\n[milestoneP4_10_cms_plugin_surface_smoke] ALL 5 TESTS PASSED SUCCESSFULLY! (100% compliant)');
}

runTests().catch((err) => {
  console.error('[milestoneP4_10_cms_plugin_surface_smoke] FATAL ERROR:', err);
  process.exit(1);
});
