/**
 * Milestone P5-5 Smoke Test Suite — Frontend Manifest & Environment Exposure Engine
 *
 * Verifies:
 * 1. Detects exposed /.env file with redacted secret values and critical severity.
 * 2. Detects exposed /.git/config file with content signature validation.
 * 3. Cleanly discards HTML soft-404 SPA fallback responses.
 * 4. Preflight and egress gates block internal/SSRF targets.
 * 5. Full HITL triage lifecycle promotes drafts to formal Findings.
 */

import {
  runManifestExposureDetection,
  validateContentSignature,
} from '../detection/ManifestExposureDetectionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { IdorHttpProbeTransport, HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

async function runSmokeTests() {
  console.log('=== Milestone P5-5: Frontend Manifest and Environment Exposure Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const assessmentId = 'asm_smoke_p5_5_001';
  const scanId = 'scn_smoke_p5_5_001';
  const grantId = 'grn_smoke_p5_5_001';
  const decisionId = 'dec_smoke_p5_5_001';
  const actorId = 'act_smoke_p5_5_operator';

  const scopeGrant: AuthorizedScopeGrant = {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId,
    scanId,
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'origin',
      normalizedOrigin: 'https://app.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone P5-5 Manifest Exposure smoke test',
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

  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId,
      scanId,
      authorizationDecisionId: decisionId,
      authorizedActor: { actorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant,
    },
    nowIso
  );

  if (authRes.status !== 'established' || !authRes.decision) {
    throw new Error(`Failed to establish verified authorization: ${authRes.reasonCode}`);
  }

  const verifiedDecision = authRes.decision;

  // -------------------------------------------------------------------------
  // TEST 1: Detects exposed /.env file with redacted secret values & critical severity
  // -------------------------------------------------------------------------
  console.log('[TEST 1] Testing exposed /.env detection and credential redaction...');
  {
    const mockEnvTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.url.endsWith('/.env')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
          bodyText: 'DATABASE_URL=postgres://user:super_secret_password_123@db:5432/main\nAPI_KEY=sk_live_99887766554433221100\nNODE_ENV=production\n',
          responseTimeMs: 25,
        };
      }
      return { statusCode: 404, headers: {}, bodyText: 'Not Found', responseTimeMs: 10 };
    };

    const result = await runManifestExposureDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'manifest_exposure_detection_request',
      detectionId: 'det_manif_test_001',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      targetBaseUrl: 'https://app.example.com',
      exposedFilePath: '/.env',
      transport: mockEnvTransport,
    });

    if (result.status !== 'pending_human_review') {
      throw new Error(`[TEST 1] Expected pending_human_review, got ${result.status} (${result.reasonCode})`);
    }
    if (!result.evidenceDraft) {
      throw new Error('[TEST 1] Expected evidenceDraft in unattended run');
    }
    if (result.exposureSeverity !== 'critical') {
      throw new Error(`[TEST 1] Expected critical exposureSeverity, got ${result.exposureSeverity}`);
    }
    if (result.sanitizedSnippet.includes('super_secret_password_123') || result.sanitizedSnippet.includes('sk_live_')) {
      throw new Error('[TEST 1] Secret values MUST NOT be leaked in sanitizedSnippet!');
    }
    if (!result.sanitizedSnippet.includes('[REDACTED]')) {
      throw new Error('[TEST 1] Expected [REDACTED] placeholder in sanitized snippet');
    }
    console.log(`[TEST 1] PASS: Flagged exposed .env draft: ${result.evidenceDraft.draftId}, snippet: "${result.sanitizedSnippet}"`);
  }

  // -------------------------------------------------------------------------
  // TEST 2: Detects exposed /.git/config file with content signature validation
  // -------------------------------------------------------------------------
  console.log('[TEST 2] Testing exposed /.git/config signature validation...');
  {
    const mockGitTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.url.endsWith('/.git/config')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'text/plain' },
          bodyText: '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = git@github.com:org/internal.git\n',
          responseTimeMs: 20,
        };
      }
      return { statusCode: 404, headers: {}, bodyText: 'Not Found', responseTimeMs: 10 };
    };

    const result = await runManifestExposureDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'manifest_exposure_detection_request',
      detectionId: 'det_manif_test_002',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      targetBaseUrl: 'https://app.example.com',
      exposedFilePath: '/.git/config',
      transport: mockGitTransport,
    });

    if (result.status !== 'pending_human_review') {
      throw new Error(`[TEST 2] Expected pending_human_review, got ${result.status}`);
    }
    if (result.fileKind !== 'git_config') {
      throw new Error(`[TEST 2] Expected fileKind git_config, got ${result.fileKind}`);
    }
    console.log(`[TEST 2] PASS: Detected .git/config draft: ${result.evidenceDraft?.draftId}`);
  }

  // -------------------------------------------------------------------------
  // TEST 3: Cleanly discards HTML soft-404 SPA fallback responses
  // -------------------------------------------------------------------------
  console.log('[TEST 3] Verifying soft-404 HTML SPA fallback prevention...');
  {
    const mockSpaTransport: IdorHttpProbeTransport = async (_req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      // Returns 200 OK with HTML document (SPA catch-all router)
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html; charset=utf-8' },
        bodyText: '<!DOCTYPE html><html><head><title>App</title></head><body><div id="root"></div></body></html>',
        responseTimeMs: 15,
      };
    };

    const result = await runManifestExposureDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'manifest_exposure_detection_request',
      detectionId: 'det_manif_test_003',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      targetBaseUrl: 'https://app.example.com',
      exposedFilePath: '/.env',
      transport: mockSpaTransport,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`[TEST 3] Expected secure_target_abstained on HTML catch-all, got ${result.status}`);
    }
    if (result.reasonCode !== 'content_signature_mismatch_or_soft_404_html') {
      throw new Error(`[TEST 3] Expected soft-404 reason code, got ${result.reasonCode}`);
    }

    // Direct function verification
    const sigCheck = validateContentSignature('/.env', '<!DOCTYPE html><html><body>Error</body></html>', 'text/html');
    if (sigCheck.isValid !== false) {
      throw new Error('[TEST 3] validateContentSignature should return isValid: false for HTML');
    }
    console.log('[TEST 3] PASS: Soft-404 HTML fallback cleanly discarded.');
  }

  // -------------------------------------------------------------------------
  // TEST 4: Preflight & Egress Gates Block Internal / SSRF Targets
  // -------------------------------------------------------------------------
  console.log('[TEST 4] Verifying preflight SSRF protection against loopback/metadata...');
  {
    const ssrfScopeGrant: AuthorizedScopeGrant = {
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

    const ssrfAuth = establishVerifiedAuthorizationDecision(
      {
        contractVersion: 'fixguard-verified-authorization-decision/v0',
        kind: 'establish_verified_authorization_decision_request',
        assessmentId,
        scanId,
        authorizationDecisionId: 'dec_ssrf_004',
        authorizedActor: { actorId, actorType: 'human' },
        decision: 'authorized',
        decidedAt: nowIso,
        scopeGrant: ssrfScopeGrant,
      },
      nowIso
    );

    if (ssrfAuth.status !== 'established' || !ssrfAuth.decision) {
      throw new Error('Failed to establish SSRF auth decision fixture');
    }

    const result = await runManifestExposureDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'manifest_exposure_detection_request',
      detectionId: 'det_manif_ssrf_001',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: 'dec_ssrf_004',
      actorId,
      verifiedAuthorizationDecision: ssrfAuth.decision,
      scopeGrant: ssrfScopeGrant,
      targetBaseUrl: 'http://169.254.169.254',
      exposedFilePath: '/.env',
    });

    if (result.status !== 'preflight_denied') {
      throw new Error(`[TEST 4] Expected preflight_denied for loopback, got ${result.status}`);
    }
    console.log('[TEST 4] PASS: Preflight successfully blocked loopback SSRF probe.');
  }

  // -------------------------------------------------------------------------
  // TEST 5: Full HITL Review Lifecycle & Promotion to Formal Finding
  // -------------------------------------------------------------------------
  console.log('[TEST 5] Testing HITL review lifecycle promoting draft to formal Finding...');
  {
    const repo = new InMemoryOrchestratedAssessmentRepository();
    const appService = new OrchestratedAssessmentApplicationService({ repository: repo });

    const initialRecord = {
      contractVersion: 'fixguard-orchestrated-assessment/v0' as const,
      assessmentId,
      scanId,
      targetDomain: 'app.example.com',
      status: 'completed' as const,
      lineage: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId,
      },
      stages: [],
      timing: { startedAt: nowIso, completedAt: nowIso, durationMs: 150 },
      errorCount: 0,
      warningCount: 0,
      findings: [],
      pendingEvidenceDrafts: [
        {
          draftKind: 'non_persisted_comparison_evidence_draft' as const,
          draftId: 'dft_manif_rev_001',
          suggestedEvidenceType: 'http_difference' as const,
          suggestedStrength: 'strong' as const,
          sourceComparisonId: 'cmp_manif_001',
          sourceSnapshotIds: {
            baselineSnapshotId: 'snp_exp_001',
            validationSnapshotId: 'snp_val_001',
          },
          requiresHumanReview: true as const,
          notPersisted: true as const,
          notARealFinding: true as const,
          notConfirmedEvidence: true as const,
          notForExternalDelivery: true as const,
          notM45EvidenceRecord: true as const,
          safeRationale: 'Sensitive file /.env publicly accessible with valid KEY=VALUE parameters.',
          differentialContext: {
            endpointUrl: 'https://app.example.com/.env',
            detectionKind: 'manifest_exposure' as const,
            exposedFilePath: '/.env',
            fileKind: 'env_file' as const,
            exposureSeverity: 'critical' as const,
            sanitizedSnippet: 'DB_PASSWORD=[REDACTED]; SECRET_KEY=[REDACTED]',
            validationStatusCode: 200,
          },
        },
      ],
      recommendations: [],
    };

    await repo.save(initialRecord);

    const reviewRes = await appService.reviewEvidenceDraft({
      assessmentId,
      draftId: 'dft_manif_rev_001',
      decision: 'approve_evidence',
      reviewerId: 'act_operator_human_01',
      reviewedAt: nowIso,
      notes: 'Confirmed critical .env exposure.',
    });

    if (reviewRes.decision !== 'approve_evidence' || !reviewRes.findingCreated) {
      throw new Error(`[TEST 5] Expected review decision 'approve_evidence' with findingCreated, got ${reviewRes.decision}`);
    }

    const updated = await repo.findById(assessmentId);
    if (!updated || updated.findings.length === 0) {
      throw new Error('[TEST 5] Expected formal finding created in repository');
    }

    const createdFinding = updated.findings[0];
    if (
      createdFinding.metadata.kind !== 'manifest_exposure_metadata' ||
      createdFinding.metadata.category !== 'INFORMATION_DISCLOSURE' ||
      createdFinding.metadata.exposureSeverity !== 'critical' ||
      createdFinding.metadata.exposedFilePath !== '/.env'
    ) {
      throw new Error('[TEST 5] Metadata mismatch in promoted finding');
    }
    console.log(`[TEST 5] PASS: Promoted finding verified: ${createdFinding.id} (${createdFinding.title})`);
  }

  console.log('\n[ALL TESTS PASSED] Milestone P5-5 Manifest and Environment Exposure Engine certified!');
}

runSmokeTests().catch((err) => {
  console.error('[SMOKE FAILED]', err);
  process.exit(1);
});
