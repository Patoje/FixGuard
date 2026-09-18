/**
 * Milestone P5-6 Smoke Test Suite — Application Parameter Integrity Engine
 *
 * Verifies:
 * 1. Detects boundary violation when parameter processing leaks resource content.
 * 2. Cleanly abstains (secure_target_abstained) when target correctly isolates boundaries.
 * 3. Preflight and egress gates block internal/SSRF targets.
 * 4. Full HITL triage lifecycle promotes drafts to formal Findings.
 * 5. Structural leak detection & parameter candidate filtering helpers.
 */

import {
  runParameterIntegrityDetection,
  detectStructuralLeak,
  isResourceParameterCandidate,
} from '../detection/ParameterIntegrityDetectionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { IdorHttpProbeTransport, HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

async function runSmokeTests() {
  console.log('=== Milestone P5-6: Application Parameter Integrity Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const assessmentId = 'asm_smoke_p5_6_001';
  const scanId = 'scn_smoke_p5_6_001';
  const grantId = 'grn_smoke_p5_6_001';
  const decisionId = 'dec_smoke_p5_6_001';
  const actorId = 'act_smoke_p5_6_operator';

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
      authorizationText: 'Authorized for Milestone P5-6 Parameter Integrity smoke test',
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
  // TEST 1: Detects boundary violation when parameter leaks structural file content
  // -------------------------------------------------------------------------
  console.log('[TEST 1] Testing parameter boundary violation detection (Unix passwd leak)...');
  {
    const mockLeakTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      const decodedUrl = decodeURIComponent(req.url);
      if (decodedUrl.includes('file=') && decodedUrl.includes('etc/passwd')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'text/plain' },
          bodyText: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n',
          responseTimeMs: 25,
        };
      }
      return { statusCode: 404, headers: {}, bodyText: 'Not Found', responseTimeMs: 10 };
    };

    const result = await runParameterIntegrityDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'parameter_integrity_detection_request',
      detectionId: 'det_pinteg_test_001',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      endpointUrl: 'https://app.example.com/view',
      parameterName: 'file',
      probePattern: '../../../../etc/passwd',
      transport: mockLeakTransport,
    });

    if (result.status !== 'pending_human_review') {
      throw new Error(`[TEST 1] Expected pending_human_review, got ${result.status} (${result.reasonCode})`);
    }
    if (!result.evidenceDraft) {
      throw new Error('[TEST 1] Expected evidenceDraft in unattended run');
    }
    if (result.boundaryEnforced !== false) {
      throw new Error('[TEST 1] Expected boundaryEnforced to be false');
    }
    if (!result.sanitizedExcerpt || !result.sanitizedExcerpt.includes('root:x:0:0:')) {
      throw new Error(`[TEST 1] Expected sanitizedExcerpt with root signature, got ${result.sanitizedExcerpt}`);
    }
    console.log(`[TEST 1] PASS: Flagged parameter violation draft: ${result.evidenceDraft.draftId}, excerpt: "${result.sanitizedExcerpt}"`);
  }

  // -------------------------------------------------------------------------
  // TEST 2: Cleanly abstains when target isolates boundaries (400/403/404 or clean response)
  // -------------------------------------------------------------------------
  console.log('[TEST 2] Verifying abstention on secure boundary rejection (HTTP 400)...');
  {
    const mockSecureTransport: IdorHttpProbeTransport = async (_req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      return {
        statusCode: 400,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ error: 'Invalid file parameter: Directory traversal rejected' }),
        responseTimeMs: 15,
      };
    };

    const result = await runParameterIntegrityDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'parameter_integrity_detection_request',
      detectionId: 'det_pinteg_test_002',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
      verifiedAuthorizationDecision: verifiedDecision,
      scopeGrant,
      endpointUrl: 'https://app.example.com/view',
      parameterName: 'file',
      probePattern: '../../../../etc/passwd',
      transport: mockSecureTransport,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`[TEST 2] Expected secure_target_abstained, got ${result.status}`);
    }
    if (result.boundaryEnforced !== true) {
      throw new Error('[TEST 2] Expected boundaryEnforced: true');
    }
    console.log('[TEST 2] PASS: Cleanly abstained on secure target.');
  }

  // -------------------------------------------------------------------------
  // TEST 3: Preflight & Egress Gates Block Internal / SSRF Targets
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
        authorizationDecisionId: 'dec_ssrf_005',
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

    const result = await runParameterIntegrityDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'parameter_integrity_detection_request',
      detectionId: 'det_pinteg_ssrf_001',
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: 'dec_ssrf_005',
      actorId,
      verifiedAuthorizationDecision: ssrfAuth.decision,
      scopeGrant: ssrfScopeGrant,
      endpointUrl: 'http://169.254.169.254/fetch',
      parameterName: 'doc',
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
          draftId: 'dft_pinteg_rev_001',
          suggestedEvidenceType: 'http_difference' as const,
          suggestedStrength: 'strong' as const,
          sourceComparisonId: 'cmp_pinteg_001',
          sourceSnapshotIds: {
            baselineSnapshotId: 'snp_base_001',
            validationSnapshotId: 'snp_val_001',
          },
          requiresHumanReview: true as const,
          notPersisted: true as const,
          notARealFinding: true as const,
          notConfirmedEvidence: true as const,
          notForExternalDelivery: true as const,
          notM45EvidenceRecord: true as const,
          safeRationale: 'Parameter file on https://app.example.com/view leaked system file signatures.',
          differentialContext: {
            endpointUrl: 'https://app.example.com/view',
            detectionKind: 'parameter_integrity' as const,
            parameterName: 'file',
            injectedProbePattern: '../../../../etc/passwd',
            boundaryEnforced: false,
            sanitizedExcerpt: 'root:x:0:0:root:/root:/bin/bash',
            validationStatusCode: 200,
          },
        },
      ],
      recommendations: [],
    };

    await repo.save(initialRecord);

    const reviewRes = await appService.reviewEvidenceDraft({
      assessmentId,
      draftId: 'dft_pinteg_rev_001',
      decision: 'approve_evidence',
      reviewerId: 'act_operator_human_01',
      reviewedAt: nowIso,
      notes: 'Confirmed directory traversal parameter boundary violation.',
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
      createdFinding.metadata.kind !== 'parameter_integrity_metadata' ||
      createdFinding.metadata.category !== 'INFORMATION_DISCLOSURE' ||
      createdFinding.metadata.parameterName !== 'file' ||
      createdFinding.metadata.boundaryEnforced !== false
    ) {
      throw new Error('[TEST 4] Metadata mismatch in promoted finding');
    }
    console.log(`[TEST 4] PASS: Promoted finding verified: ${createdFinding.id} (${createdFinding.title})`);
  }

  // -------------------------------------------------------------------------
  // TEST 5: Structural Leak Detection & Parameter Candidate Matching Helpers
  // -------------------------------------------------------------------------
  console.log('[TEST 5] Testing detectStructuralLeak and isResourceParameterCandidate...');
  {
    // Test Windows INI
    const winLeak = detectStructuralLeak('[boot loader]\ntimeout=30\ndefault=multi(0)');
    if (!winLeak.leaked || winLeak.signatureKind !== 'windows_ini') {
      throw new Error('[TEST 5] Failed to detect Windows INI leak');
    }

    // Test Java web.xml
    const javaLeak = detectStructuralLeak('<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"><servlet>');
    if (!javaLeak.leaked || javaLeak.signatureKind !== 'java_webxml') {
      throw new Error('[TEST 5] Failed to detect Java web.xml leak');
    }

    // Test parameter matching
    if (!isResourceParameterCandidate('file') || !isResourceParameterCandidate('template_path') || !isResourceParameterCandidate('load_doc')) {
      throw new Error('[TEST 5] Failed resource parameter candidate matching');
    }
    if (isResourceParameterCandidate('search_query') || isResourceParameterCandidate('id')) {
      throw new Error('[TEST 5] False positive on non-resource parameters');
    }
    console.log('[TEST 5] PASS: Structural leak detector and candidate matcher verified.');
  }

  console.log('\n[ALL TESTS PASSED] Milestone P5-6 Application Parameter Integrity Engine certified!');
}

runSmokeTests().catch((err) => {
  console.error('[SMOKE FAILED]', err);
  process.exit(1);
});
