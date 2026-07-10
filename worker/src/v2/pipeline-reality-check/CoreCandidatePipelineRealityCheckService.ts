import type {
  RunCoreCandidatePipelineRealityCheckRequest,
  CoreCandidatePipelineRealityCheckFailedResult,
  CoreCandidatePipelineRealityCheckPassedResult,
  CoreCandidatePipelineRealityCheckResult,
  CoreCandidatePipelineRealityCheckFailureStage,
  CoreCandidatePipelineContinuityCheck,
  CoreCandidatePipelineRealityCheckReasonCode
} from "./CoreCandidatePipelineRealityCheckContracts.js";
import {
  saveReviewedEvidence
} from "../evidence-store/ReviewedEvidenceStoreService.js";
import { InMemoryReviewedEvidenceStoreRepository } from "../evidence-store/InMemoryReviewedEvidenceStoreRepository.js";
import { listReviewedEvidence } from "../evidence-store/ReviewedEvidenceReadModel.js";
import { selectReviewedEvidence } from "../evidence-selection/ReviewedEvidenceSelectionService.js";
import { createReviewedEvidenceFindingCandidateDraft } from "../finding-candidate-draft/ReviewedEvidenceFindingCandidateDraftService.js";
import { promoteReviewedEvidenceFindingCandidateDraft } from "../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionService.js";
import { summarizeReviewedEvidenceFormalFindingCandidate } from "../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionReadModel.js";
import type { SaveReviewedEvidenceRequest, ListReviewedEvidenceRequest } from "../evidence-store/ReviewedEvidenceStoreContracts.js";
import type { SelectReviewedEvidenceRequest } from "../evidence-selection/ReviewedEvidenceSelectionContracts.js";
import type { CreateReviewedEvidenceFindingCandidateDraftRequest } from "../finding-candidate-draft/ReviewedEvidenceFindingCandidateDraftContracts.js";
import type { PromoteReviewedEvidenceFindingCandidateDraftRequest, SummarizeReviewedEvidenceFormalFindingCandidateRequest } from "../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionContracts.js";

const UNSAFE_TERMS = [
  "authorization", "bearer", "cookie", "set-cookie", "password", "secret",
  "token", "api_key", "apikey", "access_token", "refresh_token",
  "raw_request", "raw response", "raw_body", "raw body", "raw_headers", "raw headers",
  "sqli", "idor", "bola", "auth bypass", "vulnerable", "exploit", "critical severity", "target is vulnerable"
];

function isSafeString(val: any): boolean {
  if (typeof val !== "string") return false;
  const lower = val.toLowerCase();
  return !UNSAFE_TERMS.some(term => lower.includes(term));
}

function isStrictIsoTimestamp(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

export async function runCoreCandidatePipelineRealityCheck(
  request: RunCoreCandidatePipelineRealityCheckRequest
): Promise<CoreCandidatePipelineRealityCheckResult> {
type MutableStages = CoreCandidatePipelineRealityCheckFailedResult["stages"];

  const failure = (
    stage: CoreCandidatePipelineRealityCheckFailureStage,
    code: CoreCandidatePipelineRealityCheckReasonCode,
    safeMessage: string,
    failedContinuityChecks: CoreCandidatePipelineContinuityCheck[] = [],
    stagesSoFar: Partial<MutableStages> = {}
  ): CoreCandidatePipelineRealityCheckResult => {
    return {
      contractVersion: "fixguard-core-candidate-pipeline-reality-check/v0",
      kind: "core_candidate_pipeline_reality_check_result",
      status: "failed",
      scanId: request?.scanId && typeof request.scanId === "string" && /^[A-Za-z0-9_-]+$/.test(request.scanId) && isSafeString(request.scanId) ? request.scanId : "SCAN_ID_REDACTED",
      evaluatedAt: isStrictIsoTimestamp(request?.evaluatedAt) ? request.evaluatedAt : "TIMESTAMP_REDACTED",
      failureStage: stage,
      failedContinuityChecks,
      stages: {
        reviewedEvidenceStored: { completed: false },
        reviewedEvidenceSelected: { completed: false },
        draftCreated: { completed: false },
        formalCandidatePromoted: { completed: false },
        formalCandidateSummarized: { completed: false },
        ...stagesSoFar
      },
      continuity: {
        sameScanId: !failedContinuityChecks.includes("same_scan_id"),
        refsPreserved: !failedContinuityChecks.includes("refs_preserved"),
        countsPreserved: !failedContinuityChecks.includes("counts_preserved"),
        indicatorIdsPreserved: !failedContinuityChecks.includes("indicator_ids_preserved"),
        timestampRangesPreserved: !failedContinuityChecks.includes("timestamp_ranges_preserved"),
        humanApprovalRequired: !failedContinuityChecks.includes("human_approval_required"),
        nonClaimsPreserved: !failedContinuityChecks.includes("nonclaims_preserved"),
      },
      explicitNonClaims: {
        noConfirmedFinding: true,
        noConfirmedVulnerability: true,
        noExploitabilityClaim: true,
        noSeverityRiskOrImpactClaim: true,
        noRemediationAdvice: true,
        noSafeReportItemCreated: true,
        noExternalReportCreated: true,
        noNetworkExecution: true,
        noToolExecution: true,
        noPersistence: true
      },
      classification: {
        createsNewDomainFeature: false,
        createsConfirmedFinding: false,
        createsSafeReportItem: false,
        createsExternalReport: false,
        confirmsVulnerabilities: false,
        makesExploitabilityClaims: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false,
        providesRemediationAdvice: false,
        persistsToDatabase: false,
        executesNetwork: false,
        executesTools: false
      },
      error: {
        code,
        safeMessage
      }
    };
  };

  try {
    if (!request || typeof request !== "object" || Array.isArray(request)) {
      return failure("input_fixture", "invalid_reality_check_input", "Invalid request");
    }
    const keys = Object.keys(request);
    const allowed = new Set(["contractVersion", "kind", "scanId", "evaluatedAt", "fixture", "classification", "debugMutation"]);
    if (keys.length < 6 || keys.length > 7) return failure("input_fixture", "invalid_reality_check_input", "Invalid request keys");
    for (const k of keys) if (!allowed.has(k)) return failure("input_fixture", "invalid_reality_check_input", "Invalid request keys");

    if (request.contractVersion !== "fixguard-core-candidate-pipeline-reality-check/v0") return failure("input_fixture", "invalid_reality_check_input", "Invalid contract version");
    if (request.kind !== "run_core_candidate_pipeline_reality_check_request") return failure("input_fixture", "invalid_reality_check_input", "Invalid kind");
    if (typeof request.scanId !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(request.scanId) || !isSafeString(request.scanId)) return failure("input_fixture", "invalid_reality_check_input", "Invalid scanId");
    if (!isStrictIsoTimestamp(request.evaluatedAt)) return failure("input_fixture", "invalid_reality_check_input", "Invalid evaluatedAt");
    
    if (!request.fixture || !Array.isArray(request.fixture.promotedEvidenceResults) || request.fixture.promotedEvidenceResults.length < 3) {
      return failure("input_fixture", "invalid_reality_check_input", "Invalid fixture length");
    }

    if (request.debugMutation !== undefined) {
      const allowedMutations = new Set([
        "mutate_scan_id_after_selection",
        "mutate_selected_count_after_selection",
        "mutate_candidate_refs_before_summary"
      ]);
      if (!allowedMutations.has(request.debugMutation)) {
        return failure("input_fixture", "invalid_reality_check_input", "Invalid debugMutation");
      }
    }

    const cl = request.classification;
    if (!cl || Object.values(cl).some(v => v !== false)) return failure("input_fixture", "invalid_reality_check_input", "Invalid classification");

    const scanId = request.scanId;
    const evaluatedAt = request.evaluatedAt;
    const repo = new InMemoryReviewedEvidenceStoreRepository();

    const stages: MutableStages = {
      reviewedEvidenceStored: { completed: false },
      reviewedEvidenceSelected: { completed: false },
      draftCreated: { completed: false },
      formalCandidatePromoted: { completed: false },
      formalCandidateSummarized: { completed: false }
    };

    // Stage 1: Store
    let promoIdx = 1;
    for (const item of request.fixture.promotedEvidenceResults) {
      const saveReq = {
        contractVersion: "fixguard-reviewed-evidence-store/v0",
        kind: "save_reviewed_evidence_request",
        saveId: `save_${promoIdx}`,
        scanId,
        requestedAt: evaluatedAt,
        promotionResult: item,
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
          executesTools: false
        }
      } satisfies SaveReviewedEvidenceRequest;
      
      const res = await saveReviewedEvidence(saveReq, evaluatedAt, repo);
      if (res.status !== "saved") {
        console.error("Save failure:", res);
        return failure("reviewed_evidence_store", "reviewed_evidence_store_failed", "Save failed", [], stages);
      }
      promoIdx++;
    }

    stages.reviewedEvidenceStored = { completed: true, count: request.fixture.promotedEvidenceResults.length };

    const listReq = {
      contractVersion: "fixguard-reviewed-evidence-store/v0",
      kind: "list_reviewed_evidence_request",
      listId: "list_1",
      scanId,
      requestedAt: evaluatedAt,
      options: { limit: 100 },
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
        executesTools: false
      }
    } satisfies ListReviewedEvidenceRequest;

    const listRes = await listReviewedEvidence(listReq, evaluatedAt, repo);
    if (listRes.status !== "listed") {
      console.error("List failure:", listRes);
      return failure("reviewed_evidence_store", "reviewed_evidence_store_failed", "List failed", [], stages);
    }
    if (listRes.summaries.length !== request.fixture.promotedEvidenceResults.length) return failure("reviewed_evidence_store", "reviewed_evidence_store_failed", "Count mismatch", ["counts_preserved"], stages);

    const expectedRefs = listRes.summaries.map(s => ({
      storeRecordId: s.storeRecordId,
      evidenceId: s.evidenceId,
      scanId: s.scanId,
      indicatorId: s.indicatorId
    }));

    const collectedAts = listRes.summaries.map(s => Date.parse(s.collectedAt));
    const savedAts = listRes.summaries.map(s => Date.parse(s.savedAt));
    const expectedCollectedAtRange = {
      earliest: new Date(Math.min(...collectedAts)).toISOString(),
      latest: new Date(Math.max(...collectedAts)).toISOString()
    };
    const expectedSavedAtRange = {
      earliest: new Date(Math.min(...savedAts)).toISOString(),
      latest: new Date(Math.max(...savedAts)).toISOString()
    };
    const expectedIndicatorIds = [...new Set(listRes.summaries.map(s => s.indicatorId))].sort();

    // Stage 2: Selection
    const selectReq = {
      contractVersion: "fixguard-reviewed-evidence-selection/v0",
      kind: "select_reviewed_evidence_request",
      selectionId: "sel_1",
      scanId,
      requestedAt: evaluatedAt,
      source: {
        mode: "explicit_store_record_ids",
        storeRecordIds: listRes.summaries.map(s => s.storeRecordId)
      },
      classification: {
        createsReviewedEvidenceSelectionSet: false,
        persistsSelectionSet: false,
        persistsToDatabase: false,
        createsFindingCandidate: false,
        createsFinding: false,
        createsSafeReportItem: false,
        confirmsVulnerabilities: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false,
        executesNetwork: false,
        executesTools: false
      }
    } satisfies SelectReviewedEvidenceRequest;
    const selectRes = await selectReviewedEvidence(selectReq, evaluatedAt, repo);
    if (selectRes.status !== "selected" || !selectRes.selectionSet) {
      console.error("Selection failure:", selectRes);
      return failure("reviewed_evidence_selection", "reviewed_evidence_selection_failed", "Selection failed", [], stages);
    }
    
    const selection = selectRes.selectionSet;
    if (request.debugMutation === "mutate_scan_id_after_selection") {
      selection.scanId = "mutated_scan_id";
    }
    if (request.debugMutation === "mutate_selected_count_after_selection") {
      selection.selectionStats.selectedCount = 999;
    }

    const sameScanIdSelect = selection.scanId === scanId;
    
    // Sort before comparing to ensure deterministic deep equal
    const sortedExpectedRefs = [...expectedRefs].sort((a, b) => a.storeRecordId.localeCompare(b.storeRecordId));
    const sortedSelectRefs = [...selection.selectedRefs].sort((a, b) => a.storeRecordId.localeCompare(b.storeRecordId));
    const refsPreservedSelect = JSON.stringify(sortedExpectedRefs) === JSON.stringify(sortedSelectRefs);
    
    const sortedSelectIndicatorIds = [...new Set(selection.selectedRefs.map(r => r.indicatorId))].sort();
    const indicatorIdsPreservedSelect = JSON.stringify(sortedSelectIndicatorIds) === JSON.stringify(expectedIndicatorIds);

    const countsPreservedSelect = selection.selectionStats.selectedCount === listRes.summaries.length &&
      selection.selectionStats.selectedCount === request.fixture.promotedEvidenceResults.length;

    if (!sameScanIdSelect || !refsPreservedSelect || !countsPreservedSelect || !indicatorIdsPreservedSelect) {
      const failedChecks: CoreCandidatePipelineContinuityCheck[] = [];
      if (!sameScanIdSelect) failedChecks.push("same_scan_id");
      if (!refsPreservedSelect) failedChecks.push("refs_preserved");
      if (!countsPreservedSelect) failedChecks.push("counts_preserved");
      if (!indicatorIdsPreservedSelect) failedChecks.push("indicator_ids_preserved");
      return failure("continuity_validation", "continuity_check_failed", "Selection continuity failed", failedChecks, stages);
    }

    stages.reviewedEvidenceSelected = { completed: true, selectionId: selection.selectionId, selectedCount: selection.selectionStats.selectedCount };

    // Stage 3: Draft
    const draftReq = {
      contractVersion: "fixguard-reviewed-evidence-finding-candidate-draft/v0",
      kind: "create_reviewed_evidence_finding_candidate_draft_request",
      draftId: "draft_1",
      scanId,
      requestedAt: evaluatedAt,
      selectionSet: selection,
      classification: {
        createsFindingCandidateDraft: false,
        createsFindingCandidate: false,
        createsConfirmedFinding: false,
        createsSafeReportItem: false,
        createsExternalReport: false,
        confirmsVulnerabilities: false,
        makesExploitabilityClaims: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false,
        providesRemediationAdvice: false,
        persistsDraft: false,
        persistsToDatabase: false,
        executesNetwork: false,
        executesTools: false
      }
    } satisfies CreateReviewedEvidenceFindingCandidateDraftRequest;
    const draftRes = await createReviewedEvidenceFindingCandidateDraft(draftReq, evaluatedAt);
    if (draftRes.status !== "draft_created" || !draftRes.draft) return failure("candidate_draft", "candidate_draft_failed", "Draft failed", [], stages);

    const draft = draftRes.draft;
    const sameScanIdDraft = draft.scanId === scanId;
    const countsPreservedDraft = draft.sourceSelection.selectedCount === selection.selectionStats.selectedCount;
    const sortedDraftIndicatorIds = [...new Set(draft.sourceSelection.selectedRefs.map(r => r.indicatorId))].sort();
    const indicatorIdsPreservedDraft = JSON.stringify(sortedDraftIndicatorIds) === JSON.stringify(expectedIndicatorIds) &&
      JSON.stringify([...draft.observedEvidenceSummary.indicatorIds].sort()) === JSON.stringify(expectedIndicatorIds);
    
    const sortedDraftRefs = [...draft.sourceSelection.selectedRefs].sort((a, b) => a.storeRecordId.localeCompare(b.storeRecordId));
    const refsPreservedDraft = JSON.stringify(sortedExpectedRefs) === JSON.stringify(sortedDraftRefs);

    const draftCollectedAtCovered = draft.observedEvidenceSummary.collectedAtRange.earliest <= expectedCollectedAtRange.earliest && draft.observedEvidenceSummary.collectedAtRange.latest >= expectedCollectedAtRange.latest;
    const draftSavedAtCovered = draft.observedEvidenceSummary.savedAtRange.earliest <= expectedSavedAtRange.earliest && draft.observedEvidenceSummary.savedAtRange.latest >= expectedSavedAtRange.latest;
    const timestampRangesPreservedDraft = draftCollectedAtCovered && draftSavedAtCovered;

    if (!sameScanIdDraft || !countsPreservedDraft || !indicatorIdsPreservedDraft || !refsPreservedDraft || !timestampRangesPreservedDraft) {
      const failedChecks: CoreCandidatePipelineContinuityCheck[] = [];
      if (!sameScanIdDraft) failedChecks.push("same_scan_id");
      if (!countsPreservedDraft) failedChecks.push("counts_preserved");
      if (!indicatorIdsPreservedDraft) failedChecks.push("indicator_ids_preserved");
      if (!refsPreservedDraft) failedChecks.push("refs_preserved");
      if (!timestampRangesPreservedDraft) failedChecks.push("timestamp_ranges_preserved");
      return failure("continuity_validation", "continuity_check_failed", "Draft continuity failed", failedChecks, stages);
    }

    stages.draftCreated = { completed: true, draftId: draft.draftId, selectedCount: draft.sourceSelection.selectedCount };

    // Triage required check
    const triageDecisionBase = {
      decisionId: "decision_123",
      reviewerId: "reviewer_1",
      reviewedAt: evaluatedAt,
      decision: "approve_finding_candidate_promotion" as const,
      attestations: {
        reviewedDraft: true as const,
        reviewedEvidenceRefs: true as const,
        understandsCandidateIsNotConfirmedFinding: true as const,
        understandsNoVulnerabilityConfirmed: true as const,
        understandsNoExploitabilityClaim: true as const,
        understandsNoSeverityRiskImpactAssigned: true as const,
        understandsNoRemediationAdvice: true as const,
        authorizedPromotionToFormalCandidate: true
      },
      explicitNonClaims: {
        noConfirmedFinding: true as const,
        noConfirmedVulnerability: true as const,
        noExploitabilityClaim: true as const,
        noSeverityRiskOrImpactClaim: true as const,
        noRemediationAdvice: true as const,
        noSafeReportItemCreated: true as const,
        noExternalReportCreated: true as const,
        noNetworkExecution: true as const,
        noToolExecution: true as const,
        noPersistence: true as const
      }
    };

    const validPromoReq = {
      contractVersion: "fixguard-reviewed-evidence-finding-candidate-promotion/v0",
      kind: "promote_reviewed_evidence_finding_candidate_draft_request",
      candidateId: "candidate_123",
      scanId,
      requestedAt: evaluatedAt,
      draft,
      triageDecision: triageDecisionBase,
      classification: {
        createsFormalFindingCandidate: false,
        createsConfirmedFinding: false,
        createsSafeReportItem: false,
        createsExternalReport: false,
        confirmsVulnerabilities: false,
        makesExploitabilityClaims: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false,
        providesRemediationAdvice: false,
        persistsCandidate: false,
        persistsToDatabase: false,
        executesNetwork: false,
        executesTools: false
      }
    } satisfies PromoteReviewedEvidenceFindingCandidateDraftRequest;

    
    // Stage 4: Promotion (with missing authorization check)
    const rejectTriageDecision = { ...triageDecisionBase, decision: "reject_finding_candidate_promotion" as const };
    const rejectPromoReq = { ...validPromoReq, triageDecision: rejectTriageDecision } satisfies PromoteReviewedEvidenceFindingCandidateDraftRequest;
    const rejectRes = await promoteReviewedEvidenceFindingCandidateDraft(rejectPromoReq, evaluatedAt);
    if (rejectRes.status === "candidate_created") return failure("human_triage_gate", "human_triage_gate_failed", "Promoted on reject", ["human_approval_required"], stages);

    const needsMoreEvidenceTriageDecision = { ...triageDecisionBase, decision: "needs_more_evidence" as const };
    const needsMoreEvidencePromoReq = { ...validPromoReq, triageDecision: needsMoreEvidenceTriageDecision } satisfies PromoteReviewedEvidenceFindingCandidateDraftRequest;
    const needsMoreEvidenceRes = await promoteReviewedEvidenceFindingCandidateDraft(needsMoreEvidencePromoReq, evaluatedAt);
    if (needsMoreEvidenceRes.status === "candidate_created") return failure("human_triage_gate", "human_triage_gate_failed", "Promoted on needs_more_evidence", ["human_approval_required"], stages);

    const unauthorizedApproveTriageDecision = { ...triageDecisionBase, attestations: { ...triageDecisionBase.attestations, authorizedPromotionToFormalCandidate: false } };
    const unauthorizedApprovePromoReq = { ...validPromoReq, triageDecision: unauthorizedApproveTriageDecision } satisfies PromoteReviewedEvidenceFindingCandidateDraftRequest;
    const unauthorizedApproveRes = await promoteReviewedEvidenceFindingCandidateDraft(unauthorizedApprovePromoReq, evaluatedAt);
    if (unauthorizedApproveRes.status === "candidate_created") return failure("human_triage_gate", "human_triage_gate_failed", "Promoted without authorized flag", ["human_approval_required"], stages);

    const promoRes = await promoteReviewedEvidenceFindingCandidateDraft(validPromoReq, evaluatedAt);
    if (promoRes.status !== "candidate_created" || !promoRes.candidate) return failure("formal_candidate_promotion", "formal_candidate_promotion_failed", "Promotion failed", [], stages);

    const candidate = promoRes.candidate;
    const sameScanIdCandidate = candidate.scanId === scanId;
    const countsPreservedCandidate = candidate.evidenceRefs.selectedCount === draft.sourceSelection.selectedCount;

    const sortedCandidateRefs = [...candidate.evidenceRefs.selectedRefs].sort((a, b) => a.storeRecordId.localeCompare(b.storeRecordId));
    const refsPreservedCandidate = JSON.stringify(sortedExpectedRefs) === JSON.stringify(sortedCandidateRefs);

    const candidateCollectedAtCovered = candidate.observedEvidenceSummary.collectedAtRange.earliest === draft.observedEvidenceSummary.collectedAtRange.earliest && candidate.observedEvidenceSummary.collectedAtRange.latest === draft.observedEvidenceSummary.collectedAtRange.latest;
    const candidateSavedAtCovered = candidate.observedEvidenceSummary.savedAtRange.earliest === draft.observedEvidenceSummary.savedAtRange.earliest && candidate.observedEvidenceSummary.savedAtRange.latest === draft.observedEvidenceSummary.savedAtRange.latest;
    const timestampRangesPreservedCandidate = candidateCollectedAtCovered && candidateSavedAtCovered;
    const nonClaimsPreservedCandidate = candidate.candidateState.confirmationState === "not_confirmed" && candidate.candidateState.reportState === "not_reported" && candidate.candidateState.persistenceState === "not_persisted" && candidate.candidateState.requiresFurtherHumanReview === true;
    const originalIdentityPreservedCandidate = candidate.sourceDraft.draftId === draft.draftId && candidate.sourceDraft.sourceSelectionId === selection.selectionId;

    const sortedCandidateIndicatorIds = [...new Set(candidate.evidenceRefs.selectedRefs.map(r => r.indicatorId))].sort();
    const indicatorIdsPreservedCandidate = JSON.stringify(sortedCandidateIndicatorIds) === JSON.stringify(expectedIndicatorIds) &&
      JSON.stringify([...candidate.observedEvidenceSummary.indicatorIds].sort()) === JSON.stringify(expectedIndicatorIds);

    const candidateEvidenceTypeSum = Object.values(candidate.observedEvidenceSummary.evidenceTypeCounts).reduce((a, b) => a + b, 0);
    const candidateStrengthSum = Object.values(candidate.observedEvidenceSummary.strengthCounts).reduce((a, b) => a + b, 0);
    const candidateCountsSumsCorrect = candidateEvidenceTypeSum === candidate.evidenceRefs.selectedCount && candidateStrengthSum === candidate.evidenceRefs.selectedCount;

    if (!sameScanIdCandidate || !countsPreservedCandidate || !refsPreservedCandidate || !timestampRangesPreservedCandidate || !nonClaimsPreservedCandidate || !originalIdentityPreservedCandidate || !indicatorIdsPreservedCandidate || !candidateCountsSumsCorrect) {
      const failedChecks: CoreCandidatePipelineContinuityCheck[] = [];
      if (!sameScanIdCandidate) failedChecks.push("same_scan_id");
      if (!countsPreservedCandidate || !candidateCountsSumsCorrect) failedChecks.push("counts_preserved");
      if (!refsPreservedCandidate) failedChecks.push("refs_preserved");
      if (!timestampRangesPreservedCandidate) failedChecks.push("timestamp_ranges_preserved");
      if (!nonClaimsPreservedCandidate) failedChecks.push("nonclaims_preserved");
      if (!indicatorIdsPreservedCandidate) failedChecks.push("indicator_ids_preserved");
      return failure("continuity_validation", "continuity_check_failed", "Candidate continuity failed", failedChecks, stages);
    }

    stages.formalCandidatePromoted = { completed: true, candidateId: candidate.candidateId, selectedCount: candidate.evidenceRefs.selectedCount, humanApprovedPromotion: true };

    if (request.debugMutation === "mutate_candidate_refs_before_summary") {
      candidate.evidenceRefs.selectedRefs.push({ storeRecordId: "injected", evidenceId: "injected", indicatorId: "injected", scanId: "injected" });
    }

    // Stage 5: Summary
    const sumReq = {
      contractVersion: "fixguard-reviewed-evidence-finding-candidate-promotion/v0",
      kind: "summarize_reviewed_evidence_formal_finding_candidate_request",
      summaryId: "summary_123",
      scanId,
      requestedAt: evaluatedAt,
      candidate,
      classification: {
        createsFormalFindingCandidate: false,
        createsConfirmedFinding: false,
        createsSafeReportItem: false,
        createsExternalReport: false,
        confirmsVulnerabilities: false,
        makesExploitabilityClaims: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false,
        providesRemediationAdvice: false,
        persistsCandidate: false,
        persistsToDatabase: false,
        executesNetwork: false,
        executesTools: false
      }
    } satisfies SummarizeReviewedEvidenceFormalFindingCandidateRequest;
    const sumRes = await summarizeReviewedEvidenceFormalFindingCandidate(sumReq, evaluatedAt);
    if (sumRes.status !== "summarized" || !sumRes.summary) {
      if (sumRes.status === "failed" && sumRes.reasonCode === "candidate_validation_failed") {
        return failure("continuity_validation", "continuity_check_failed", "Candidate validation failed at summary (refs injected)", ["refs_preserved"], stages);
      }
      return failure("formal_candidate_summary", "formal_candidate_summary_failed", "Summary failed", [], stages);
    }

    const summary = sumRes.summary;
    const sameScanIdSummary = summary.scanId === scanId;
    const countsPreservedSummary = summary.selectedCount === candidate.evidenceRefs.selectedCount;
    const nonClaimsPreservedSummary = summary.confirmationState === "not_confirmed" && summary.reportState === "not_reported" && summary.persistenceState === "not_persisted";
    const timestampRangesPreservedSummary = summary.createdAt === candidate.createdAt;
    const originalIdentityPreservedSummary = summary.sourceDraftId === draft.draftId && summary.sourceSelectionId === selection.selectionId;

    const summaryEvidenceTypeSum = Object.values(summary.evidenceTypeCounts).reduce((a, b) => a + b, 0);
    const summaryStrengthSum = Object.values(summary.strengthCounts).reduce((a, b) => a + b, 0);
    const summaryCountsSumsCorrect = summaryEvidenceTypeSum === summary.selectedCount && summaryStrengthSum === summary.selectedCount;

    // Deep equal maps
    const evidenceTypeCountsEqual = JSON.stringify(summary.evidenceTypeCounts) === JSON.stringify(candidate.observedEvidenceSummary.evidenceTypeCounts);
    const strengthCountsEqual = JSON.stringify(summary.strengthCounts) === JSON.stringify(candidate.observedEvidenceSummary.strengthCounts);
    
    if (!sameScanIdSummary || !countsPreservedSummary || !nonClaimsPreservedSummary || !timestampRangesPreservedSummary || !originalIdentityPreservedSummary || !summaryCountsSumsCorrect || !evidenceTypeCountsEqual || !strengthCountsEqual) {
      const failedChecks: CoreCandidatePipelineContinuityCheck[] = [];
      if (!sameScanIdSummary) failedChecks.push("same_scan_id");
      if (!countsPreservedSummary || !summaryCountsSumsCorrect || !evidenceTypeCountsEqual || !strengthCountsEqual) failedChecks.push("counts_preserved");
      if (!nonClaimsPreservedSummary) failedChecks.push("nonclaims_preserved");
      if (!timestampRangesPreservedSummary) failedChecks.push("timestamp_ranges_preserved");
      return failure("continuity_validation", "continuity_check_failed", "Summary continuity failed", failedChecks, stages);
    }

    stages.formalCandidateSummarized = { completed: true, summaryId: sumReq.summaryId, selectedCount: summary.selectedCount };

    return {
      contractVersion: "fixguard-core-candidate-pipeline-reality-check/v0",
      kind: "core_candidate_pipeline_reality_check_result",
      status: "passed",
      scanId,
      evaluatedAt,
      stages: stages as CoreCandidatePipelineRealityCheckPassedResult["stages"],
      continuity: {
        sameScanId: true,
        refsPreserved: true,
        countsPreserved: true,
        indicatorIdsPreserved: true,
        timestampRangesPreserved: true,
        humanApprovalRequired: true,
        nonClaimsPreserved: true
      },
      finalState: {
        lifecycleState: "formal_candidate_created",
        confirmationState: "not_confirmed",
        reportState: "not_reported",
        persistenceState: "not_persisted",
        requiresFurtherHumanReview: true
      },
      explicitNonClaims: {
        noConfirmedFinding: true,
        noConfirmedVulnerability: true,
        noExploitabilityClaim: true,
        noSeverityRiskOrImpactClaim: true,
        noRemediationAdvice: true,
        noSafeReportItemCreated: true,
        noExternalReportCreated: true,
        noNetworkExecution: true,
        noToolExecution: true,
        noPersistence: true
      },
      classification: {
        createsNewDomainFeature: false,
        createsConfirmedFinding: false,
        createsSafeReportItem: false,
        createsExternalReport: false,
        confirmsVulnerabilities: false,
        makesExploitabilityClaims: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false,
        providesRemediationAdvice: false,
        persistsToDatabase: false,
        executesNetwork: false,
        executesTools: false
      }
    };
  } catch (error) {
    console.error("Unexpected error in reality check:", error);
    return failure("unexpected_failure", "unexpected_reality_check_failure", "Unexpected failure caught");
  }
}
