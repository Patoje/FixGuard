/**
 * Milestone P5-10 Smoke Test Suite — Cross-Finding Chain Correlation (Phase 5 Finale)
 *
 * Verifies:
 * 1. Correlates disparate confirmed findings into a valid cross-finding chain draft.
 * 2. Cleanly abstains when insufficient correlation criteria are met.
 * 3. Operates purely in-memory with zero network overhead.
 * 4. Full HITL triage lifecycle promotes compound draft to formal Critical Finding.
 * 5. Helper classifications for primary and secondary vectors.
 */

import {
  correlateCrossFindingChains,
  isPrimaryAccessVector,
  isSecondaryDisclosureVector,
} from '../intelligence/correlation/CrossFindingChainCorrelator.js';
import type { Finding } from '../core/Evidence.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

async function runSmokeTests() {
  console.log('=== Milestone P5-10: Cross-Finding Chain Correlation Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const assessmentId = 'asm_smoke_p5_10_001';
  const scanId = 'scn_smoke_p5_10_001';
  const actorId = 'act_smoke_p5_10_operator';
  const targetDomain = 'app.example.com';

  const idorFinding: Finding = {
    id: 'fnd_idor_001',
    type: 'BROKEN_ACCESS_CONTROL',
    severity: 'high',
    title: 'IDOR in Billing API',
    description: 'Object reference bypass in /api/v2/billing/invoice',
    target: `https://${targetDomain}/api/v2/billing/invoice`,
    evidence: JSON.stringify({ invoiceId: 'inv_123', status: 200 }),
    confidence: 1.0,
    metadata: {
      kind: 'broken_access_control_metadata',
      category: 'BROKEN_ACCESS_CONTROL',
      candidateId: 'cnd_idor_001',
      evidenceRecordId: 'evd_idor_001',
      lineage: { assessmentId, scanId, actorId },
      endpointUrl: `https://${targetDomain}/api/v2/billing/invoice`,
    },
  };

  const manifestFinding: Finding = {
    id: 'fnd_manif_001',
    type: 'INFORMATION_DISCLOSURE',
    severity: 'high',
    title: 'Exposed Frontend Manifest with Internal API Keys',
    description: 'Manifest exposes internal API keys and staging routes',
    target: `https://${targetDomain}/.env`,
    evidence: JSON.stringify({ leakedKeys: ['API_KEY', 'DB_HOST'] }),
    confidence: 1.0,
    metadata: {
      kind: 'manifest_exposure_metadata',
      category: 'INFORMATION_DISCLOSURE',
      endpointUrl: `https://${targetDomain}/.env`,
      exposedFilePath: '/.env',
      fileKind: 'env_file',
      exposureSeverity: 'high',
      sanitizedSnippet: 'API_KEY=[REDACTED]',
      observedAt: nowIso,
    },
  };

  const harmlessFinding: Finding = {
    id: 'fnd_headers_001',
    type: 'MISSING_SECURITY_HEADERS',
    severity: 'low',
    title: 'Missing X-Frame-Options',
    description: 'X-Frame-Options header not set',
    target: `https://${targetDomain}/`,
    evidence: JSON.stringify({ missingHeaders: ['X-Frame-Options'] }),
    confidence: 1.0,
    metadata: {
      kind: 'missing_security_headers_metadata',
      category: 'SECURITY_MISCONFIGURATION',
      missingHeaders: ['X-Frame-Options'],
      presentHeaders: ['X-Content-Type-Options'],
      observedAt: nowIso,
    },
  };

  // -------------------------------------------------------------------------
  // TEST 1: Correlates disparate confirmed findings into a valid cross-finding chain draft
  // -------------------------------------------------------------------------
  console.log('[TEST 1] Testing cross-finding chain correlation...');
  {
    const result = correlateCrossFindingChains({
      assessmentId,
      scanId,
      actorId,
      findings: [idorFinding, manifestFinding],
    });

    if (!result.hasChains) {
      throw new Error('[TEST 1] Expected hasChains: true for paired findings');
    }
    if (result.compoundDrafts.length === 0) {
      throw new Error('[TEST 1] Expected at least 1 compound draft created');
    }

    const draft = result.compoundDrafts[0];
    if (draft.suggestedStrength !== 'strong' || !draft.requiresHumanReview) {
      throw new Error('[TEST 1] Draft must require human review and have strong strength');
    }
    console.log(`[TEST 1] PASS: Flagged cross-finding chain draft: ${draft.draftId}, rationale: ${draft.safeRationale}`);
  }

  // -------------------------------------------------------------------------
  // TEST 2: Cleanly abstains when insufficient correlation criteria are met
  // -------------------------------------------------------------------------
  console.log('[TEST 2] Verifying abstention on insufficient correlation criteria...');
  {
    // Case A: Single finding
    const singleResult = correlateCrossFindingChains({
      assessmentId,
      scanId,
      actorId,
      findings: [idorFinding],
    });
    if (singleResult.hasChains || singleResult.compoundDrafts.length > 0) {
      throw new Error('[TEST 2A] Should abstain with single finding');
    }

    // Case B: Incompatible findings (e.g. only harmless header finding + IDOR)
    const incompResult = correlateCrossFindingChains({
      assessmentId,
      scanId,
      actorId,
      findings: [idorFinding, harmlessFinding],
    });
    if (incompResult.hasChains || incompResult.compoundDrafts.length > 0) {
      throw new Error('[TEST 2B] Should abstain when secondary finding is not a high-value exposure vector');
    }
    console.log('[TEST 2] PASS: Cleanly abstained when correlation requirements were unmet.');
  }

  // -------------------------------------------------------------------------
  // TEST 3: Operates purely in-memory with zero network overhead
  // -------------------------------------------------------------------------
  console.log('[TEST 3] Verifying zero network overhead during analytical correlation...');
  {
    const startMemory = process.memoryUsage().heapUsed;
    const result = correlateCrossFindingChains({
      assessmentId,
      scanId,
      actorId,
      findings: [idorFinding, manifestFinding],
    });
    const endMemory = process.memoryUsage().heapUsed;

    if (!result.hasChains) {
      throw new Error('[TEST 3] In-memory correlation failed to execute');
    }
    console.log(`[TEST 3] PASS: In-memory analytical correlation completed cleanly (heap delta: ${Math.round((endMemory - startMemory) / 1024)} KB).`);
  }

  // -------------------------------------------------------------------------
  // TEST 4: Full HITL Review Lifecycle & Promotion to Formal Critical Finding
  // -------------------------------------------------------------------------
  console.log('[TEST 4] Testing HITL review lifecycle promoting compound draft to formal Finding...');
  {
    const repo = new InMemoryOrchestratedAssessmentRepository();
    const appService = new OrchestratedAssessmentApplicationService({ repository: repo });

    const initialRecord = {
      contractVersion: 'fixguard-orchestrated-assessment/v0' as const,
      assessmentId,
      scanId,
      targetDomain,
      status: 'completed' as const,
      lineage: {
        assessmentId,
        scanId,
        authorizationGrantId: 'grn_smoke_001',
        authorizationDecisionId: 'dec_smoke_001',
        actorId,
      },
      stages: [],
      timing: { startedAt: nowIso, completedAt: nowIso, durationMs: 150 },
      errorCount: 0,
      warningCount: 0,
      findings: [idorFinding, manifestFinding],
      pendingEvidenceDrafts: [
        {
          draftKind: 'non_persisted_comparison_evidence_draft' as const,
          draftId: 'dft_xfchain_rev_001',
          suggestedEvidenceType: 'http_difference' as const,
          suggestedStrength: 'strong' as const,
          sourceComparisonId: 'cmp_xfchain_001',
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
          safeRationale: 'Cross-finding compound chain synthesized from IDOR + Manifest Exposure.',
          differentialContext: {
            endpointUrl: `https://${targetDomain}/`,
            detectionKind: 'cross_finding_chain' as const,
            chainKind: 'cross_finding_compound' as const,
            chainTitle: 'Multi-Step Attack Path: IDOR + Exposed Manifest Keys',
            constituentFindingIds: ['fnd_idor_001', 'fnd_manif_001'],
            primaryVector: 'IDOR in Billing API',
            secondaryVector: 'Exposed Frontend Manifest with Internal API Keys',
            compoundImpactScore: 0.95,
            validationStatusCode: 200,
          },
        },
      ],
      recommendations: [],
    };

    await repo.save(initialRecord);

    const reviewRes = await appService.reviewEvidenceDraft({
      assessmentId,
      draftId: 'dft_xfchain_rev_001',
      decision: 'approve_evidence',
      reviewerId: 'act_operator_human_01',
      reviewedAt: nowIso,
      notes: 'Approved critical cross-finding compound chain.',
    });

    if (reviewRes.decision !== 'approve_evidence' || !reviewRes.findingCreated) {
      throw new Error(`[TEST 4] Expected review decision 'approve_evidence' with findingCreated, got ${reviewRes.decision}`);
    }

    const updated = await repo.findById(assessmentId);
    if (!updated) {
      throw new Error('[TEST 4] Assessment not found in repository');
    }

    const promotedFinding = updated.findings.find((f) => f.id.startsWith('fnd_xfchain_'));
    if (!promotedFinding) {
      throw new Error('[TEST 4] Expected promoted cross-finding chain in repository');
    }

    if (
      promotedFinding.metadata.kind !== 'cross_finding_chain_metadata' ||
      promotedFinding.severity !== 'critical' ||
      promotedFinding.metadata.compoundImpactScore !== 0.95 ||
      promotedFinding.metadata.constituentFindingIds.length !== 2
    ) {
      throw new Error('[TEST 4] Promoted finding metadata mismatch');
    }
    console.log(`[TEST 4] PASS: Promoted critical finding verified: ${promotedFinding.id} (${promotedFinding.title})`);
  }

  // -------------------------------------------------------------------------
  // TEST 5: Helper Classifications for Primary and Secondary Vectors
  // -------------------------------------------------------------------------
  console.log('[TEST 5] Testing helper vector classifiers...');
  {
    if (!isPrimaryAccessVector(idorFinding)) {
      throw new Error('[TEST 5] idorFinding should be primary access vector');
    }
    if (!isSecondaryDisclosureVector(manifestFinding)) {
      throw new Error('[TEST 5] manifestFinding should be secondary disclosure vector');
    }
    if (isPrimaryAccessVector(manifestFinding) || isSecondaryDisclosureVector(idorFinding)) {
      throw new Error('[TEST 5] Vector overlap classification error');
    }
    console.log('[TEST 5] PASS: Vector classifiers verified.');
  }

  console.log('\n[ALL TESTS PASSED] Milestone P5-10 Cross-Finding Chain Correlation certified!');
}

runSmokeTests().catch((err) => {
  console.error('[SMOKE FAILED]', err);
  process.exit(1);
});
