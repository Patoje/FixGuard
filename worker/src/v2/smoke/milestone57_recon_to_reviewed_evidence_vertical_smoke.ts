import assert from 'node:assert';
import { runReconToReviewedEvidencePipeline } from '../application/ReconToReviewedEvidenceApplicationService.js';
import { InMemoryActiveReconOriginRunRepository } from '../recon/active/InMemoryActiveReconOriginRunRepository.js';
import { InMemoryReviewedEvidenceStoreRepository } from '../evidence-store/InMemoryReviewedEvidenceStoreRepository.js';
import { getReviewedEvidence } from '../evidence-store/ReviewedEvidenceReadModel.js';

console.log('--- V2 M57 Recon-to-Reviewed-Evidence Vertical Slice Smoke Test ---');

async function runTests() {
  const evaluatedAt = '2026-07-06T10:00:00.000Z';

  // -------------------------------------------------------------------------
  // 1. Happy Path: End-to-End Vertical Pipeline with Operator Approval
  // -------------------------------------------------------------------------
  {
    const reconRepo = new InMemoryActiveReconOriginRunRepository();
    const storeRepo = new InMemoryReviewedEvidenceStoreRepository();

    const result = await runReconToReviewedEvidencePipeline(
      {
        contractVersion: 'recon-to-reviewed-evidence/v1',
        assessmentId: 'assess_m57_1',
        scanId: 'scan_m57_1',
        operatorId: 'operator_pato',
        targetOrigin: 'https://example.com',
        evaluatedAt,
        reviewDecision: {
          decision: 'approve_evidence',
          reviewerId: 'operator_pato',
          reviewedAt: evaluatedAt,
        },
      },
      {
        reconRepository: reconRepo,
        evidenceStoreRepository: storeRepo,
      }
    );

    assert.strictEqual(result.status, 'completed', 'Expected pipeline status completed');
    assert.strictEqual(result.reasonCode, 'vertical_slice_completed_successfully');
    assert.strictEqual(result.promotionStatus, 'promoted');
    assert.ok(result.authorizationDecisionId, 'Authorization decision ID must be present');
    assert.ok(result.reconRunId, 'Recon run ID must be present');
    assert.ok(result.validationId, 'Validation ID must be present');
    assert.ok(result.storedRecordId, 'Stored record ID must be present');
    assert.ok(result.evidenceId, 'Evidence ID must be present');

    // Lineage verification
    assert.ok(result.lineage, 'Lineage must be present');
    assert.strictEqual(result.lineage.assessmentId, 'assess_m57_1');
    assert.strictEqual(result.lineage.scanId, 'scan_m57_1');
    assert.strictEqual(result.lineage.actorId, 'operator_pato');
    assert.strictEqual(result.lineage.authorizationDecisionId, result.authorizationDecisionId);

    // Classification boundaries
    assert.strictEqual(result.classification.createsRealFindings, false);
    assert.strictEqual(result.classification.confirmsVulnerabilities, false);
    assert.strictEqual(result.classification.makesRiskClaims, false);
    assert.strictEqual(result.classification.makesSeverityClaims, false);
    assert.strictEqual(result.classification.makesImpactClaims, false);
    assert.strictEqual(result.classification.executesNetwork, false);
    assert.strictEqual(result.classification.executesTools, false);
    assert.strictEqual(result.classification.createsPersistedEvidence, true);
    assert.strictEqual(result.classification.persistsData, true);

    // Verify Active Recon persistence in repo
    const persistedRecon = await reconRepo.getRun(result.reconRunId);
    assert.ok(persistedRecon, 'Recon record must be persisted in recon repository');
    assert.strictEqual(persistedRecon.subject.normalizedOrigin, 'https://example.com');
    assert.strictEqual(persistedRecon.status, 'completed');

    // Verify Reviewed Evidence persistence in store repo
    const getRes = await getReviewedEvidence(
      {
        contractVersion: 'fixguard-reviewed-evidence-store/v0',
        kind: 'get_reviewed_evidence_request',
        readId: 'read_m57_1',
        scanId: 'scan_m57_1',
        requestedAt: evaluatedAt,
        lookup: { by: 'storeRecordId', storeRecordId: result.storedRecordId },
        classification: {
          storesReviewedEvidenceRecord: false,
          storesInMemoryOnly: false,
          persistsToDatabase: false,
          createsFindingCandidate: false,
          createsSafeReportItem: false,
          confirmsVulnerabilities: false,
          makesRiskClaims: false,
          makesSeverityClaims: false,
          makesImpactClaims: false,
          executesNetwork: false,
          executesTools: false,
        },
      },
      evaluatedAt,
      storeRepo
    );

    assert.strictEqual(getRes.status, 'found');
    assert.strictEqual(getRes.record?.storeRecordId, result.storedRecordId);
    assert.strictEqual(getRes.record?.evidenceRecord.evidenceId, result.evidenceId);
    assert.strictEqual(getRes.record?.evidenceRecord.scanId, 'scan_m57_1');

    console.log('[+] 1. Happy path: full vertical pipeline from origin to reviewed evidence passed.');
  }

  // -------------------------------------------------------------------------
  // 2. Operator Rejection Flow: Reviewer Rejects Evidence Draft
  // -------------------------------------------------------------------------
  {
    const reconRepo = new InMemoryActiveReconOriginRunRepository();
    const storeRepo = new InMemoryReviewedEvidenceStoreRepository();

    const result = await runReconToReviewedEvidencePipeline(
      {
        contractVersion: 'recon-to-reviewed-evidence/v1',
        assessmentId: 'assess_m57_2',
        scanId: 'scan_m57_2',
        operatorId: 'operator_pato',
        targetOrigin: 'https://example.com',
        evaluatedAt,
        reviewDecision: {
          decision: 'reject',
          reviewerId: 'operator_pato',
          reviewedAt: evaluatedAt,
        },
      },
      {
        reconRepository: reconRepo,
        evidenceStoreRepository: storeRepo,
      }
    );

    assert.strictEqual(result.status, 'rejected');
    assert.strictEqual(result.reasonCode, 'rejected_by_human_review');
    assert.strictEqual(result.promotionStatus, 'rejected');
    assert.strictEqual(result.storedRecordId, undefined, 'Rejected evidence must not be stored');
    assert.strictEqual(result.evidenceId, undefined);
    assert.strictEqual(result.classification.createsPersistedEvidence, false);
    assert.strictEqual(result.classification.persistsData, false);

    // Recon should still have run and persisted
    assert.ok(result.reconRunId, 'Recon run ID should be present');
    const persistedRecon = await reconRepo.getRun(result.reconRunId);
    assert.ok(persistedRecon, 'Recon run was captured even if evidence was rejected');

    console.log('[+] 2. Rejection flow: Operator rejection halts promotion and prevents evidence storage.');
  }

  // -------------------------------------------------------------------------
  // 3. Needs More Review Flow
  // -------------------------------------------------------------------------
  {
    const storeRepo = new InMemoryReviewedEvidenceStoreRepository();

    const result = await runReconToReviewedEvidencePipeline(
      {
        contractVersion: 'recon-to-reviewed-evidence/v1',
        assessmentId: 'assess_m57_3',
        scanId: 'scan_m57_3',
        operatorId: 'operator_pato',
        targetOrigin: 'https://example.com',
        evaluatedAt,
        reviewDecision: {
          decision: 'needs_more_review',
          reviewerId: 'operator_pato',
          reviewedAt: evaluatedAt,
        },
      },
      {
        evidenceStoreRepository: storeRepo,
      }
    );

    assert.strictEqual(result.status, 'needs_more_review');
    assert.strictEqual(result.reasonCode, 'human_review_requested_more_review');
    assert.strictEqual(result.promotionStatus, 'needs_more_review');
    assert.strictEqual(result.storedRecordId, undefined);
    assert.strictEqual(result.classification.createsPersistedEvidence, false);

    console.log('[+] 3. Needs more review flow: Evidence draft held without storage.');
  }

  // -------------------------------------------------------------------------
  // 4. Invalid Command Parameter Handling (Fails Closed Safely)
  // -------------------------------------------------------------------------
  {
    const invalidResult = await runReconToReviewedEvidencePipeline({
      contractVersion: 'recon-to-reviewed-evidence/v1',
      assessmentId: 'assess_m57_4',
      scanId: 'scan_m57_4',
      operatorId: 'operator_pato',
      targetOrigin: 'https://example.com',
      evaluatedAt: 'invalid-date',
      reviewDecision: {
        decision: 'approve_evidence',
        reviewerId: 'operator_pato',
        reviewedAt: 'invalid-date',
      },
    });

    assert.strictEqual(invalidResult.status, 'failed');
    assert.strictEqual(invalidResult.reasonCode, 'invalid_command_parameters');
    assert.ok(invalidResult.error);

    console.log('[+] 4. Invalid command parameters safely reject with fail-closed status.');
  }

  console.log('\n--- V2 M57 Vertical Slice Smoke Test Passed Completely ---');
}

runTests().catch((err) => {
  console.error('M57 Smoke Failed:', err);
  process.exit(1);
});
