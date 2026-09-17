/**
 * Milestone P5-4 Smoke Test Suite — Dependency Confusion Detection Engine
 *
 * Verifies:
 * 1. Detects unclaimed private package (404 on public registry) and constructs DependencyConfusionMetadata.
 * 2. Cleanly abstains (secure_target_abstained) when package is claimed/published (200 OK on registry).
 * 3. Preflight and egress gates block internal/SSRF targets.
 * 4. Full HITL triage lifecycle promotes drafts to formal Findings.
 * 5. Manifest parsing helper extractPackageCandidatesFromManifest extracts scoped/internal dependencies.
 */

import {
  runDependencyConfusionDetection,
  extractPackageCandidatesFromManifest,
} from '../detection/DependencyConfusionDetectionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { IdorHttpProbeTransport, HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

async function runSmokeTests() {
  console.log('=== Milestone P5-4: Dependency Confusion Detection Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const assessmentId = 'asm_smoke_p5_4_001';
  const scanId = 'scn_smoke_p5_4_001';
  const grantId = 'grn_smoke_p5_4_001';
  const decisionId = 'dec_smoke_p5_4_001';
  const actorId = 'act_smoke_p5_4_operator';

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
      authorizationText: 'Authorized for Milestone P5-4 Dependency Confusion smoke test',
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
  // TEST 1: Detects unclaimed private package (404 on registry)
  // -------------------------------------------------------------------------
  console.log('[TEST 1] Testing unclaimed scoped package detection (HTTP 404 on registry)...');
  {
    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      const decodedUrl = decodeURIComponent(req.url);
      // Unclaimed package returns 404
      if (decodedUrl.includes('@internal-corp/auth-core')) {
        return {
          statusCode: 404,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({ error: 'Not found' }),
          responseTimeMs: 30,
        };
      }
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ name: 'public-package' }),
        responseTimeMs: 25,
      };
    };

    const result = await runDependencyConfusionDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'dependency_confusion_detection_request',
      detectionId: 'det_depconf_test_001',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      sourceManifestUrl: 'https://app.example.com/package.json',
      packageName: '@internal-corp/auth-core',
      detectedVersion: '^1.0.0',
      transport: mockTransport,
    });

    if (result.status !== 'pending_human_review') {
      throw new Error(`[TEST 1] Expected pending_human_review, got ${result.status} (${result.reasonCode})`);
    }
    if (!result.evidenceDraft) {
      throw new Error('[TEST 1] Expected evidenceDraft in unattended run');
    }
    if (result.isUnclaimedPublicly !== true) {
      throw new Error('[TEST 1] Expected isUnclaimedPublicly to be true');
    }
    if (result.registryStatusCode !== 404) {
      throw new Error(`[TEST 1] Expected registryStatusCode 404, got ${result.registryStatusCode}`);
    }
    console.log(`[TEST 1] PASS: Flagged unclaimed package draft: ${result.evidenceDraft.draftId}`);
  }

  // -------------------------------------------------------------------------
  // TEST 2: Cleanly abstains when package is claimed / registered publicly (200 OK)
  // -------------------------------------------------------------------------
  console.log('[TEST 2] Verifying abstention on claimed package (HTTP 200 on registry)...');
  {
    const mockClaimedTransport: IdorHttpProbeTransport = async (_req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ name: 'react', versions: { '18.0.0': {} } }),
        responseTimeMs: 20,
      };
    };

    const result = await runDependencyConfusionDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'dependency_confusion_detection_request',
      detectionId: 'det_depconf_test_002',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      sourceManifestUrl: 'https://app.example.com/package.json',
      packageName: 'react',
      detectedVersion: '^18.0.0',
      transport: mockClaimedTransport,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`[TEST 2] Expected secure_target_abstained, got ${result.status}`);
    }
    if (result.isUnclaimedPublicly !== false) {
      throw new Error('[TEST 2] Expected isUnclaimedPublicly to be false');
    }
    console.log('[TEST 2] PASS: Cleanly abstained on claimed package.');
  }

  // -------------------------------------------------------------------------
  // TEST 3: Preflight & Egress Gates Block Internal / SSRF Manifest Targets
  // -------------------------------------------------------------------------
  console.log('[TEST 3] Verifying preflight SSRF protection against loopback/metadata...');
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
        authorizationDecisionId: 'dec_ssrf_003',
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

    const result = await runDependencyConfusionDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'dependency_confusion_detection_request',
      detectionId: 'det_depconf_ssrf_001',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: 'dec_ssrf_003',
      actorId,
      verifiedAuthorizationDecision: ssrfAuth.decision,
      scopeGrant: ssrfScopeGrant,
      sourceManifestUrl: 'http://169.254.169.254/latest/meta-data/package.json',
      packageName: '@internal/cloud-config',
    });

    if (result.status !== 'preflight_denied') {
      throw new Error(`[TEST 3] Expected preflight_denied for loopback, got ${result.status}`);
    }
    console.log('[TEST 3] PASS: Preflight successfully blocked loopback SSRF probe.');
  }

  // -------------------------------------------------------------------------
  // TEST 4: Full HITL Review Lifecycle & Promotion to Formal Finding
  // -------------------------------------------------------------------------
  console.log('[TEST 4] Testing HITL review lifecycle promoting draft to formal Finding...');
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
          draftId: 'dft_depconf_rev_001',
          suggestedEvidenceType: 'http_difference' as const,
          suggestedStrength: 'strong' as const,
          sourceComparisonId: 'cmp_depconf_001',
          sourceSnapshotIds: {
            baselineSnapshotId: 'snp_manif_001',
            validationSnapshotId: 'snp_reg_001',
          },
          requiresHumanReview: true as const,
          notPersisted: true as const,
          notARealFinding: true as const,
          notConfirmedEvidence: true as const,
          notForExternalDelivery: true as const,
          notM45EvidenceRecord: true as const,
          safeRationale: 'Package @company/sec-auth is unclaimed on public npm registry (HTTP 404).',
          differentialContext: {
            endpointUrl: 'https://app.example.com/package.json',
            detectionKind: 'dependency_confusion' as const,
            packageName: '@company/sec-auth',
            detectedVersion: '^2.1.0',
            sourceManifestUrl: 'https://app.example.com/package.json',
            publicRegistryUrl: 'https://registry.npmjs.org/@company%2Fsec-auth',
            registryStatusCode: 404,
            isUnclaimedPublicly: true,
            validationStatusCode: 404,
          },
        },
      ],
      recommendations: [],
    };

    await repo.save(initialRecord);

    const reviewRes = await appService.reviewEvidenceDraft({
      assessmentId,
      draftId: 'dft_depconf_rev_001',
      decision: 'approve_evidence',
      reviewerId: 'act_operator_human_01',
      reviewedAt: nowIso,
      notes: 'Confirmed unclaimed internal package namespace.',
    });

    if (reviewRes.decision !== 'approve_evidence' || !reviewRes.findingCreated) {
      throw new Error(`[TEST 4] Expected review decision 'approve_evidence' with findingCreated, got ${reviewRes.decision}`);
    }

    const updated = await repo.findById(assessmentId);
    if (!updated || updated.findings.length === 0) {
      throw new Error('[TEST 4] Expected formal finding created in repository');
    }

    const createdFinding = updated.findings[0];
    if (
      createdFinding.metadata.kind !== 'dependency_confusion_metadata' ||
      createdFinding.metadata.category !== 'SUPPLY_CHAIN_RISK' ||
      createdFinding.metadata.isUnclaimedPublicly !== true ||
      createdFinding.metadata.packageName !== '@company/sec-auth'
    ) {
      throw new Error('[TEST 4] Metadata mismatch in promoted finding');
    }
    console.log(`[TEST 4] PASS: Promoted finding verified: ${createdFinding.id} (${createdFinding.title})`);
  }

  // -------------------------------------------------------------------------
  // TEST 5: Manifest parsing helper extracts scoped/internal candidates
  // -------------------------------------------------------------------------
  console.log('[TEST 5] Testing extractPackageCandidatesFromManifest...');
  {
    const manifestJson = JSON.stringify({
      name: 'my-corp-frontend',
      dependencies: {
        react: '^18.2.0',
        '@mycorp/shared-ui': '^1.0.0',
        'internal-auth-helper': 'file:../internal-auth',
      },
      devDependencies: {
        typescript: '^5.0.0',
        '@mycorp/test-utils': '^0.5.0',
      },
    });

    const candidates = extractPackageCandidatesFromManifest(manifestJson);
    const names = candidates.map((c) => c.packageName);

    if (!names.includes('@mycorp/shared-ui')) {
      throw new Error('[TEST 5] Missing @mycorp/shared-ui in extracted candidates');
    }
    if (!names.includes('internal-auth-helper')) {
      throw new Error('[TEST 5] Missing internal-auth-helper in extracted candidates');
    }
    if (!names.includes('@mycorp/test-utils')) {
      throw new Error('[TEST 5] Missing @mycorp/test-utils in extracted candidates');
    }
    if (names.includes('react') || names.includes('typescript')) {
      throw new Error('[TEST 5] Non-internal packages should be filtered out');
    }
    console.log('[TEST 5] PASS: Correctly extracted scoped & internal dependencies:', names);
  }

  console.log('\n[ALL TESTS PASSED] Milestone P5-4 Dependency Confusion Detection Engine certified!');
}

runSmokeTests().catch((err) => {
  console.error('[SMOKE FAILED]', err);
  process.exit(1);
});
