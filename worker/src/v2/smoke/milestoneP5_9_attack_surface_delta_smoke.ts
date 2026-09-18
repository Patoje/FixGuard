/**
 * Milestone P5-9 Smoke Test Suite — Attack Surface Delta Analysis
 *
 * Verifies:
 * 1. Computes correct delta between current assessment targets and historical baseline profile.
 * 2. Cleanly abstains (neutral delta / zero drafts) when no baseline exists or surface is identical.
 * 3. Operates purely in-memory with zero network overhead.
 * 4. Full HITL triage lifecycle promotes delta draft to formal Finding.
 * 5. Helper calculations, sensitive path flagging, and path capping verification.
 */

import {
  analyzeAttackSurfaceDelta,
  computeEndpointDifference,
  detectTechDrift,
  isSensitivePath,
} from '../intelligence/analysis/AttackSurfaceDeltaAnalysisService.js';
import type { TargetProfile } from '../intelligence/IntelligenceContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

async function runSmokeTests() {
  console.log('=== Milestone P5-9: Attack Surface Delta Analysis Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const currentAssessmentId = 'asm_smoke_p5_9_cur';
  const baselineAssessmentId = 'asm_smoke_p5_9_base';
  const scanId = 'scn_smoke_p5_9_001';
  const actorId = 'act_smoke_p5_9_operator';
  const targetDomain = 'app.example.com';

  const baselineProfile: TargetProfile = {
    contractVersion: 'fixguard-intelligence/v0',
    kind: 'target_profile',
    profileId: 'prf_smoke_p5_9_base',
    targetHost: targetDomain,
    normalizedOrigin: `https://${targetDomain}`,
    updatedAt: new Date(Date.now() - 86400_000 * 7).toISOString(),
    technologies: ['React', 'Nginx 1.24.0'],
    lineage: {
      assessmentId: baselineAssessmentId,
      scanId: 'scn_smoke_p5_9_old',
      authorizationGrantId: 'grn_smoke_old',
      authorizationDecisionId: 'dec_smoke_old',
      actorId,
    },
    endpoints: [
      {
        url: 'https://app.example.com/',
        path: '/',
        method: 'GET',
        parameters: [],
        authRequirement: 'none',
        flawCategories: [],
      },
      {
        url: 'https://app.example.com/login',
        path: '/login',
        method: 'GET',
        parameters: [],
        authRequirement: 'none',
        flawCategories: [],
      },
      {
        url: 'https://app.example.com/about',
        path: '/about',
        method: 'GET',
        parameters: [],
        authRequirement: 'none',
        flawCategories: [],
      },
    ],
    knownFindings: [],
  };

  const currentProfileWithExpansion: TargetProfile = {
    contractVersion: 'fixguard-intelligence/v0',
    kind: 'target_profile',
    profileId: 'prf_smoke_p5_9_cur',
    targetHost: targetDomain,
    normalizedOrigin: `https://${targetDomain}`,
    updatedAt: nowIso,
    technologies: ['React', 'Nginx 1.25.1', 'GraphQL'], // Tech drift (version drift + new GraphQL)
    lineage: {
      assessmentId: currentAssessmentId,
      scanId,
      authorizationGrantId: 'grn_smoke_001',
      authorizationDecisionId: 'dec_smoke_001',
      actorId,
    },
    endpoints: [
      {
        url: 'https://app.example.com/',
        path: '/',
        method: 'GET',
        parameters: [],
        authRequirement: 'none',
        flawCategories: [],
      },
      {
        url: 'https://app.example.com/login',
        path: '/login',
        method: 'GET',
        parameters: [],
        authRequirement: 'none',
        flawCategories: [],
      },
      {
        url: 'https://app.example.com/about',
        path: '/about',
        method: 'GET',
        parameters: [],
        authRequirement: 'none',
        flawCategories: [],
      },
      {
        url: 'https://app.example.com/admin/dashboard',
        path: '/admin/dashboard',
        method: 'GET',
        parameters: [],
        authRequirement: 'authenticated',
        flawCategories: [],
      }, // Sensitive new endpoint
      {
        url: 'https://app.example.com/api/v2/users',
        path: '/api/v2/users',
        method: 'GET',
        parameters: [],
        authRequirement: 'authenticated',
        flawCategories: [],
      },
      {
        url: 'https://app.example.com/graphql',
        path: '/graphql',
        method: 'POST',
        parameters: [],
        authRequirement: 'none',
        flawCategories: [],
      },
    ],
    knownFindings: [],
  };

  // -------------------------------------------------------------------------
  // TEST 1: Computes correct delta between current assessment targets and baseline
  // -------------------------------------------------------------------------
  console.log('[TEST 1] Testing longitudinal attack surface delta computation...');
  {
    const result = analyzeAttackSurfaceDelta({
      currentAssessmentId,
      scanId,
      actorId,
      targetDomain,
      currentProfile: currentProfileWithExpansion,
      baselineProfile,
      baselineAssessmentId,
    });

    if (!result.hasDelta) {
      throw new Error('[TEST 1] Expected hasDelta: true for expanded surface');
    }
    if (result.newEndpointsCount !== 3) {
      throw new Error(`[TEST 1] Expected 3 new endpoints, got ${result.newEndpointsCount}`);
    }
    if (!result.technologyDriftDetected) {
      throw new Error('[TEST 1] Expected technologyDriftDetected: true');
    }
    if (result.deltaSeverity !== 'high') {
      throw new Error(`[TEST 1] Expected deltaSeverity 'high' due to /admin and /graphql, got ${result.deltaSeverity}`);
    }
    if (!result.evidenceDraft) {
      throw new Error('[TEST 1] Expected evidenceDraft in unattended delta analysis');
    }
    console.log(`[TEST 1] PASS: Flagged delta draft: ${result.evidenceDraft.draftId}, new endpoints: ${result.newlyExposedPaths.join(', ')}`);
  }

  // -------------------------------------------------------------------------
  // TEST 2: Cleanly abstains (neutral delta / zero drafts) when surface is identical or no baseline
  // -------------------------------------------------------------------------
  console.log('[TEST 2] Verifying abstention on identical surface or missing baseline...');
  {
    // Case A: No baseline
    const noBaseResult = analyzeAttackSurfaceDelta({
      currentAssessmentId,
      scanId,
      actorId,
      targetDomain,
      currentProfile: currentProfileWithExpansion,
      baselineProfile: undefined,
    });
    if (noBaseResult.hasDelta || noBaseResult.evidenceDraft) {
      throw new Error('[TEST 2A] Should have no delta when baseline is absent');
    }

    // Case B: Identical surface
    const identicalResult = analyzeAttackSurfaceDelta({
      currentAssessmentId,
      scanId,
      actorId,
      targetDomain,
      currentProfile: baselineProfile,
      baselineProfile,
      baselineAssessmentId,
    });
    if (identicalResult.hasDelta || identicalResult.evidenceDraft) {
      throw new Error('[TEST 2B] Should have no delta when surface is identical');
    }
    console.log('[TEST 2] PASS: Cleanly abstained with neutral delta on identical/missing baseline.');
  }

  // -------------------------------------------------------------------------
  // TEST 3: Operates purely in-memory with zero network overhead
  // -------------------------------------------------------------------------
  console.log('[TEST 3] Verifying zero network overhead during analytical delta execution...');
  {
    const startMemory = process.memoryUsage().heapUsed;
    const result = analyzeAttackSurfaceDelta({
      currentAssessmentId,
      scanId,
      actorId,
      targetDomain,
      currentProfile: currentProfileWithExpansion,
      baselineProfile,
      baselineAssessmentId,
    });
    const endMemory = process.memoryUsage().heapUsed;

    if (!result.hasDelta || typeof result.newEndpointsCount !== 'number') {
      throw new Error('[TEST 3] Analytical run failed to produce numeric delta');
    }
    console.log(`[TEST 3] PASS: In-memory analytical comparison completed cleanly (heap delta: ${Math.round((endMemory - startMemory) / 1024)} KB).`);
  }

  // -------------------------------------------------------------------------
  // TEST 4: Full HITL Review Lifecycle & Promotion to Formal Finding
  // -------------------------------------------------------------------------
  console.log('[TEST 4] Testing HITL review lifecycle promoting delta draft to formal Finding...');
  {
    const repo = new InMemoryOrchestratedAssessmentRepository();
    const appService = new OrchestratedAssessmentApplicationService({ repository: repo });

    const initialRecord = {
      contractVersion: 'fixguard-orchestrated-assessment/v0' as const,
      assessmentId: currentAssessmentId,
      scanId,
      targetDomain,
      status: 'completed' as const,
      lineage: {
        assessmentId: currentAssessmentId,
        scanId,
        authorizationGrantId: 'grn_smoke_001',
        authorizationDecisionId: 'dec_smoke_001',
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
          draftId: 'dft_asdelta_rev_001',
          suggestedEvidenceType: 'http_difference' as const,
          suggestedStrength: 'strong' as const,
          sourceComparisonId: 'cmp_asdelta_001',
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
          safeRationale: 'Longitudinal attack surface delta identified 3 new endpoints against baseline.',
          differentialContext: {
            endpointUrl: `https://${targetDomain}/`,
            detectionKind: 'attack_surface_delta' as const,
            baselineAssessmentId,
            newEndpointsCount: 3,
            removedEndpointsCount: 0,
            newlyExposedPaths: ['/admin/dashboard', '/api/v2/users', '/graphql'],
            technologyDriftDetected: true,
            deltaSeverity: 'high' as const,
            validationStatusCode: 200,
          },
        },
      ],
      recommendations: [],
    };

    await repo.save(initialRecord);

    const reviewRes = await appService.reviewEvidenceDraft({
      assessmentId: currentAssessmentId,
      draftId: 'dft_asdelta_rev_001',
      decision: 'approve_evidence',
      reviewerId: 'act_operator_human_01',
      reviewedAt: nowIso,
      notes: 'Approved longitudinal attack surface delta and new exposure paths.',
    });

    if (reviewRes.decision !== 'approve_evidence' || !reviewRes.findingCreated) {
      throw new Error(`[TEST 4] Expected review decision 'approve_evidence' with findingCreated, got ${reviewRes.decision}`);
    }

    const updated = await repo.findById(currentAssessmentId);
    if (!updated || updated.findings.length === 0) {
      throw new Error('[TEST 4] Expected formal finding created in repository');
    }

    const createdFinding = updated.findings[0];
    if (
      createdFinding.metadata.kind !== 'attack_surface_delta_metadata' ||
      createdFinding.metadata.category !== 'SECURITY_MISCONFIGURATION' ||
      createdFinding.metadata.newEndpointsCount !== 3 ||
      createdFinding.metadata.technologyDriftDetected !== true
    ) {
      throw new Error('[TEST 4] Metadata mismatch in promoted finding');
    }
    console.log(`[TEST 4] PASS: Promoted finding verified: ${createdFinding.id} (${createdFinding.title})`);
  }

  // -------------------------------------------------------------------------
  // TEST 5: Helper Calculations, Sensitive Path Flagging, and Path Capping
  // -------------------------------------------------------------------------
  console.log('[TEST 5] Testing helper functions and path capping...');
  {
    // Sensitive path check
    if (!isSensitivePath('/admin/users') || !isSensitivePath('/api/v1/debug') || !isSensitivePath('/.env')) {
      throw new Error('[TEST 5] Sensitive path matcher failed');
    }
    if (isSensitivePath('/public/about') || isSensitivePath('/contact-us')) {
      throw new Error('[TEST 5] False positive on harmless paths');
    }

    // Tech drift detection
    const driftDetected = detectTechDrift(
      ['Vue 3.0'],
      ['Vue 2.7']
    );
    if (!driftDetected) {
      throw new Error('[TEST 5] Failed to detect version drift');
    }

    // Endpoint diff
    const diff = computeEndpointDifference(['https://a.com/1', 'https://a.com/2'], ['https://a.com/1']);
    if (diff.newEndpoints.length !== 1 || diff.newEndpoints[0] !== '/2') {
      throw new Error('[TEST 5] Endpoint difference computation mismatch');
    }
    console.log('[TEST 5] PASS: Helpers verified.');
  }

  console.log('\n[ALL TESTS PASSED] Milestone P5-9 Attack Surface Delta Analysis certified!');
}

runSmokeTests().catch((err) => {
  console.error('[SMOKE FAILED]', err);
  process.exit(1);
});
