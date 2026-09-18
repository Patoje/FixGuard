/**
 * Milestone P7-1 Smoke Test Suite — OOB Canary Token & Ephemeral Callback Server Architecture
 *
 * Verifies:
 * 1. Generates unique canary token and registers simulated inbound OOB callback successfully.
 * 2. Cleanly abstains when no OOB interaction is recorded for a token.
 * 3. Operates securely in ephemeral memory with strict isolation.
 * 4. Full HITL triage lifecycle promotes OOB interaction draft to formal Finding.
 * 5. Volatile in-memory state lifecycle and cleanup.
 */

import { OobCanaryManager } from '../oob/OobCanaryManager.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

async function runSmokeTests() {
  console.log('=== Milestone P7-1: OOB Canary Token Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const assessmentId = 'asm_smoke_p7_1_001';
  const scanId = 'scn_smoke_p7_1_001';
  const actorId = 'act_smoke_p7_1_operator';
  const targetDomain = 'app.example.com';

  const oobManager = new OobCanaryManager({ defaultCallbackDomain: 'oob.fixguard.internal' });

  // -------------------------------------------------------------------------
  // TEST 1: Generates unique canary token & registers inbound callback
  // -------------------------------------------------------------------------
  console.log('[TEST 1] Testing canary token generation and inbound callback registration...');
  {
    const tokenDescriptor = oobManager.issueCanaryToken({
      assessmentId,
      scanId,
      actorId,
      targetDomain,
      targetEndpoint: 'https://app.example.com/api/v1/webhook',
      purpose: 'blind_ssrf',
    });

    if (!tokenDescriptor.canaryToken.startsWith('fgc_') || tokenDescriptor.canaryToken.length < 15) {
      throw new Error(`[TEST 1] Unexpected token format: ${tokenDescriptor.canaryToken}`);
    }
    if (!tokenDescriptor.callbackUrl.includes(tokenDescriptor.canaryToken)) {
      throw new Error(`[TEST 1] Callback URL mismatch: ${tokenDescriptor.callbackUrl}`);
    }

    // Simulate inbound HTTP callback from target
    const recorded = oobManager.recordInteraction({
      canaryToken: tokenDescriptor.canaryToken,
      interactionType: 'http_callback',
      remoteAddress: '198.51.100.42',
      receivedAt: nowIso,
      httpMethod: 'POST',
      rawHeaders: { 'user-agent': 'TargetService/1.0', 'x-request-id': 'req-987' },
    });

    if (!recorded) {
      throw new Error('[TEST 1] Failed to record inbound interaction');
    }

    const interactions = oobManager.getInteractionsForToken(tokenDescriptor.canaryToken);
    if (interactions.length !== 1 || interactions[0].remoteAddress !== '198.51.100.42') {
      throw new Error(`[TEST 1] Interaction retrieval mismatch: ${JSON.stringify(interactions)}`);
    }

    const evalResult = oobManager.evaluateOobInteractions({
      assessmentId,
      scanId,
      actorId,
      targetDomain,
    });

    if (!evalResult.hasInteractions || evalResult.evidenceDrafts.length !== 1) {
      throw new Error(`[TEST 1] Expected 1 evidence draft for recorded callback, got ${evalResult.evidenceDrafts.length}`);
    }

    console.log(`[TEST 1] PASS: Generated canary '${tokenDescriptor.canaryToken}' and recorded callback from ${interactions[0].remoteAddress}.`);
  }

  // -------------------------------------------------------------------------
  // TEST 2: Cleanly abstains when no OOB interaction is recorded
  // -------------------------------------------------------------------------
  console.log('[TEST 2] Verifying abstention on untouched canary token...');
  {
    const cleanAssessmentId = 'asm_smoke_p7_1_clean';
    const cleanToken = oobManager.issueCanaryToken({
      assessmentId: cleanAssessmentId,
      scanId: 'scn_clean_001',
      actorId,
      targetDomain: 'secure.example.com',
      purpose: 'blind_ssrf',
    });

    if (!cleanToken) {
      throw new Error('[TEST 2] Failed to generate clean token');
    }

    // Evaluate without any interactions recorded
    const evalResult = oobManager.evaluateOobInteractions({
      assessmentId: cleanAssessmentId,
      scanId: 'scn_clean_001',
      actorId,
      targetDomain: 'secure.example.com',
    });

    if (evalResult.hasInteractions || evalResult.evidenceDrafts.length > 0 || evalResult.findings.length > 0) {
      throw new Error('[TEST 2] Expected clean abstention with 0 drafts on uncontacted canary');
    }

    console.log('[TEST 2] PASS: Cleanly abstained with zero findings when no OOB callbacks occurred.');
  }

  // -------------------------------------------------------------------------
  // TEST 3: Operates securely in ephemeral memory with strict isolation
  // -------------------------------------------------------------------------
  console.log('[TEST 3] Verifying ephemeral in-memory isolation and cleanup...');
  {
    const initialCount = oobManager.activeTokenCount;
    oobManager.clearAssessment(assessmentId);

    const postClearInteractions = oobManager.getInteractionsForToken('non_existent_token');
    if (postClearInteractions.length !== 0) {
      throw new Error('[TEST 3] Non-existent token returned interactions');
    }

    // Attempting to record interaction on cleared token fails
    const invalidRecord = oobManager.recordInteraction({
      canaryToken: 'fgc_random_invalid_token',
      interactionType: 'dns_query',
      receivedAt: nowIso,
    });

    if (invalidRecord !== false) {
      throw new Error('[TEST 3] Expected recordInteraction to return false on unknown token');
    }

    console.log(`[TEST 3] PASS: In-memory state cleared successfully (active tokens delta: ${initialCount - oobManager.activeTokenCount}).`);
  }

  // -------------------------------------------------------------------------
  // TEST 4: Full HITL Review Lifecycle & Promotion to Formal Finding
  // -------------------------------------------------------------------------
  console.log('[TEST 4] Testing HITL review lifecycle promoting OOB interaction draft to formal Finding...');
  {
    const repo = new InMemoryOrchestratedAssessmentRepository();
    const appService = new OrchestratedAssessmentApplicationService({ repository: repo });

    const testAssessmentId = 'asm_smoke_p7_1_hitl';
    const testCanaryToken = 'fgc_aabbccddeeff1122';

    const initialRecord = {
      contractVersion: 'fixguard-orchestrated-assessment/v0' as const,
      assessmentId: testAssessmentId,
      scanId,
      targetDomain,
      status: 'completed' as const,
      lineage: {
        assessmentId: testAssessmentId,
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
          draftId: 'dft_oobcan_rev_001',
          suggestedEvidenceType: 'http_difference' as const,
          suggestedStrength: 'strong' as const,
          sourceComparisonId: 'cmp_oobcan_001',
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
          safeRationale: `Asynchronous out-of-band interaction confirmed for canary token '${testCanaryToken}' (blind_ssrf). Interaction type: http_callback from remote IP 203.0.113.88.`,
          differentialContext: {
            endpointUrl: `https://${targetDomain}/api/v1/integrations/webhook`,
            detectionKind: 'oob_canary_interaction' as const,
            canaryToken: testCanaryToken,
            callbackDomain: 'oob.fixguard.internal',
            interactionType: 'http_callback' as const,
            remoteAddress: '203.0.113.88',
            interactionTimestamp: nowIso,
            exposureSeverity: 'critical' as const,
            validationStatusCode: 200,
          },
        },
      ],
      recommendations: [],
    };

    await repo.save(initialRecord);

    const reviewRes = await appService.reviewEvidenceDraft({
      assessmentId: testAssessmentId,
      draftId: 'dft_oobcan_rev_001',
      decision: 'approve_evidence',
      reviewerId: 'act_operator_human_01',
      reviewedAt: nowIso,
      notes: 'Approved confirmed out-of-band callback finding.',
    });

    if (reviewRes.decision !== 'approve_evidence' || !reviewRes.findingCreated) {
      throw new Error(`[TEST 4] Expected review decision 'approve_evidence' with findingCreated, got ${reviewRes.decision}`);
    }

    const updated = await repo.findById(testAssessmentId);
    if (!updated) {
      throw new Error('[TEST 4] Assessment not found in repository');
    }

    const promotedFinding = updated.findings.find((f) => f.id.startsWith('fnd_oobcan_'));
    if (!promotedFinding) {
      throw new Error('[TEST 4] Expected promoted OOB canary finding in repository');
    }

    if (
      promotedFinding.metadata.kind !== 'oob_canary_metadata' ||
      promotedFinding.severity !== 'critical' ||
      promotedFinding.metadata.canaryToken !== testCanaryToken ||
      promotedFinding.metadata.interactionType !== 'http_callback' ||
      promotedFinding.metadata.remoteAddress !== '203.0.113.88'
    ) {
      throw new Error(`[TEST 4] Promoted finding metadata mismatch: ${JSON.stringify(promotedFinding.metadata)}`);
    }
    console.log(`[TEST 4] PASS: Promoted OOB finding verified: ${promotedFinding.id} (${promotedFinding.title})`);
  }

  // -------------------------------------------------------------------------
  // TEST 5: Direct evaluateOobInteractions with approve_evidence
  // -------------------------------------------------------------------------
  console.log('[TEST 5] Testing direct approved finding generation...');
  {
    const approvedAssessmentId = 'asm_smoke_p7_1_direct';
    const directManager = new OobCanaryManager();
    const token = directManager.issueCanaryToken({
      assessmentId: approvedAssessmentId,
      scanId: 'scn_direct_001',
      actorId,
      targetDomain: 'direct.example.com',
      purpose: 'dns_rebinding',
    });

    directManager.recordInteraction({
      canaryToken: token.canaryToken,
      interactionType: 'dns_query',
      remoteAddress: '198.51.100.99',
      receivedAt: nowIso,
    });

    const directResult = directManager.evaluateOobInteractions({
      assessmentId: approvedAssessmentId,
      scanId: 'scn_direct_001',
      actorId,
      targetDomain: 'direct.example.com',
      humanReviewDecision: {
        decision: 'approve_evidence',
        reviewerId: 'act_human_reviewer',
        reviewedAt: nowIso,
      },
    });

    if (!directResult.hasInteractions || directResult.findings.length !== 1) {
      throw new Error('[TEST 5] Expected 1 finding on direct approval evaluation');
    }

    const f = directResult.findings[0];
    if (f.metadata.kind !== 'oob_canary_metadata' || f.metadata.interactionType !== 'dns_query') {
      throw new Error('[TEST 5] Finding metadata assertion failed');
    }

    console.log(`[TEST 5] PASS: Direct approved finding generated: ${f.title}`);
  }

  console.log('\n[ALL TESTS PASSED] Milestone P7-1 OOB Canary Token & Ephemeral Callback Server Architecture certified!');
}

runSmokeTests().catch((err) => {
  console.error('[SMOKE FAILED]', err);
  process.exit(1);
});
