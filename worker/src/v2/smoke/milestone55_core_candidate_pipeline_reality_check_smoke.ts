import { runCoreCandidatePipelineRealityCheck } from "../pipeline-reality-check/CoreCandidatePipelineRealityCheckService.js";
import type { HumanReviewedEvidencePromotionResult } from "../evidence-review/HumanReviewedEvidencePromotionContracts.js";

async function runSmokeTest() {
  console.log("--- V2 Core Candidate Pipeline Reality Check (M55) Smoke Test ---");

  const evaluatedAt = "2026-10-10T12:00:00.000Z";
  const scanId = "scan_001";
  
  const evidenceFixture = [
    {
      contractVersion: "fixguard-evidence-boundary/v0",
      kind: "evidence_record",
      evidenceId: "ev_1",
      scanId,
      indicatorId: "ind_1",
      evidenceType: "http_difference",
      strength: "strong",
      collectedAt: "2026-10-10T11:00:00.000Z",
      collectedBy: "manual_review",
      redaction: { isRedacted: true, redactionMethod: "redact_all" },
      classification: {
        createsRealFindings: false,
        createsPersistedEvidence: false,
        confirmsVulnerabilities: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false
      }
    },
    {
      contractVersion: "fixguard-evidence-boundary/v0",
      kind: "evidence_record",
      evidenceId: "ev_2",
      scanId,
      indicatorId: "ind_2",
      evidenceType: "http_difference",
      strength: "moderate",
      collectedAt: "2026-10-10T11:10:00.000Z",
      collectedBy: "manual_review",
      redaction: { isRedacted: true, redactionMethod: "redact_all" },
      classification: {
        createsRealFindings: false,
        createsPersistedEvidence: false,
        confirmsVulnerabilities: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false
      }
    },
    {
      contractVersion: "fixguard-evidence-boundary/v0",
      kind: "evidence_record",
      evidenceId: "ev_3",
      scanId,
      indicatorId: "ind_3",
      evidenceType: "manual_review_note",
      strength: "strong",
      collectedAt: "2026-10-10T11:20:00.000Z",
      collectedBy: "manual_review",
      redaction: { isRedacted: true, redactionMethod: "redact_all" },
      classification: {
        createsRealFindings: false,
        createsPersistedEvidence: false,
        confirmsVulnerabilities: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false
      }
    }
  ] as const;

  const promotedEvidenceResults = evidenceFixture.map((ev, idx) => ({
    contractVersion: "fixguard-human-reviewed-evidence-promotion/v0",
    kind: "human_reviewed_evidence_promotion_result",
    promotionId: `promo_${idx + 1}`,
    scanId,
    evaluatedAt,
    status: "promoted",
    reasonCode: "promoted_to_non_persisted_evidence_record",
    sourceValidationSummary: {
      validationId: `val_${idx + 1}`,
      status: "validated",
      reasonCode: "validation_passed",
      evidenceDraftPresent: true
    },
    reviewSummary: {
      decision: "approve_evidence",
      reviewerId: "reviewer_1",
      reviewedAt: evaluatedAt
    },
    nonPersistedEvidenceRecord: {
      contractVersion: "fixguard-evidence-boundary/v0",
      kind: "evidence_record",
      evidenceId: ev.evidenceId,
      scanId: ev.scanId,
      indicatorId: ev.indicatorId,
      evidenceType: ev.evidenceType,
      strength: ev.strength,
      collectedAt: ev.collectedAt,
      collectedBy: ev.collectedBy,
      redaction: ev.redaction,
      classification: ev.classification
    },
    explicitNonClaims: {
      noConfirmedVulnerability: true,
      noFindingCreated: true,
      noFindingCandidateCreated: true,
      noSafeReportItemCreated: true,
      noSeverityRiskOrImpactClaim: true,
      noExternalReportCreated: true,
      noNetworkExecution: true,
      noToolExecution: true,
      noPersistence: true
    },
    classification: {
      createsNonPersistedEvidenceRecord: true,
      createsPersistedEvidence: false,
      createsFindingCandidate: false,
      createsSafeReportItem: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false
    }
  })) satisfies HumanReviewedEvidencePromotionResult[];

  const reqBase = {
    contractVersion: "fixguard-core-candidate-pipeline-reality-check/v0",
    kind: "run_core_candidate_pipeline_reality_check_request",
    scanId,
    evaluatedAt,
    fixture: {
      promotedEvidenceResults
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

  const allowedFailureStages = new Set(["input_fixture", "reviewed_evidence_store", "reviewed_evidence_selection", "candidate_draft", "human_triage_gate", "formal_candidate_promotion", "formal_candidate_summary", "continuity_validation", "boundary_validation", "unexpected_failure"]);
  const allowedContinuityChecks = new Set(["same_scan_id", "refs_preserved", "counts_preserved", "indicator_ids_preserved", "timestamp_ranges_preserved", "human_approval_required", "nonclaims_preserved"]);
  const allowedReasonCodes = new Set(["core_candidate_pipeline_reality_check_passed", "invalid_reality_check_input", "reviewed_evidence_store_failed", "reviewed_evidence_selection_failed", "candidate_draft_failed", "human_triage_gate_failed", "formal_candidate_promotion_failed", "formal_candidate_summary_failed", "continuity_check_failed", "boundary_check_failed", "unexpected_reality_check_failure"]);

  function assertFailedResult(res: any, expectedStage?: string) {
    if (res.status !== "failed") { console.error("FAIL expected failed result"); process.exit(1); }
    if (!allowedFailureStages.has(res.failureStage)) { console.error("FAIL invalid failureStage", res.failureStage); process.exit(1); }
    if (expectedStage && res.failureStage !== expectedStage) { console.error("FAIL wrong failureStage", res.failureStage); process.exit(1); }
    if (res.failedContinuityChecks) {
      for (const c of res.failedContinuityChecks) {
        if (!allowedContinuityChecks.has(c)) { console.error("FAIL invalid continuity check", c); process.exit(1); }
      }
    }
    if (!allowedReasonCodes.has(res.error.code)) { console.error("FAIL invalid error code", res.error.code); process.exit(1); }
    if ("finalState" in res) { console.error("FAIL finalState present in failed result"); process.exit(1); }
    
    if (res.stages) {
      if (!res.stages.reviewedEvidenceSelected.completed && "selectionId" in res.stages.reviewedEvidenceSelected) { console.error("FAIL selectionId present"); process.exit(1); }
      if (!res.stages.draftCreated.completed && "draftId" in res.stages.draftCreated) { console.error("FAIL draftId present"); process.exit(1); }
      if (!res.stages.formalCandidatePromoted.completed && "candidateId" in res.stages.formalCandidatePromoted) { console.error("FAIL candidateId present"); process.exit(1); }
      if (!res.stages.formalCandidateSummarized.completed && "summaryId" in res.stages.formalCandidateSummarized) { console.error("FAIL summaryId present"); process.exit(1); }
    }
  }

  console.log("[*] Testing Invalid Reality Check Input...");
  const invalidReq = { ...reqBase, fixture: { promotedEvidenceResults: [] } } as unknown;
  const invalidRes = await runCoreCandidatePipelineRealityCheck(invalidReq as any);
  assertFailedResult(invalidRes, "input_fixture");

  console.log("[*] Testing Full Reality Check Happy Path...");
  const validRes = (await runCoreCandidatePipelineRealityCheck(reqBase as any)) as any;
  if (validRes.status !== "passed") {
    console.error("FAIL reality check did not pass", validRes);
    process.exit(1);
  }

  console.log("[+] Stages completed successfully");
  if (!validRes.stages.reviewedEvidenceStored.completed) { console.error("FAIL store"); process.exit(1); }
  if (!validRes.stages.reviewedEvidenceSelected.completed) { console.error("FAIL select"); process.exit(1); }
  if (!validRes.stages.draftCreated.completed) { console.error("FAIL draft"); process.exit(1); }
  if (!validRes.stages.formalCandidatePromoted.completed) { console.error("FAIL promotion"); process.exit(1); }
  if (!validRes.stages.formalCandidateSummarized.completed) { console.error("FAIL summary"); process.exit(1); }

  console.log("[+] Continuity booleans true");
  if (!validRes.continuity.sameScanId || !validRes.continuity.refsPreserved || !validRes.continuity.countsPreserved || !validRes.continuity.indicatorIdsPreserved || !validRes.continuity.timestampRangesPreserved || !validRes.continuity.humanApprovalRequired || !validRes.continuity.nonClaimsPreserved) {
    console.error("FAIL continuity booleans not true", validRes.continuity); process.exit(1);
  }

  console.log("[+] Final State validation");
  if (validRes.finalState.confirmationState !== "not_confirmed" || validRes.finalState.reportState !== "not_reported" || validRes.finalState.persistenceState !== "not_persisted" || !validRes.finalState.requiresFurtherHumanReview) {
    console.error("FAIL final state leaked claims"); process.exit(1);
  }

  console.log("[*] Field-aware No-Active-Claim Check...");
  const validResStr = JSON.stringify(validRes);
  const activeClaims = [
    '"confirmedFinding":',
    '"confirmedVulnerability":',
    '"vulnerabilityConfirmed":',
    '"exploitability":',
    '"severity":',
    '"risk":',
    '"impact":',
    '"remediation":',
    '"recommendation":',
    '"SafeReportItem":',
    '"ExternalReport":',
    '"FindingCandidateRecord":',
    '"candidateType":',
    '"severityGate":',
    '"rationale":'
  ];
  for (const claim of activeClaims) {
    if (validResStr.includes(claim)) {
      console.error(`FAIL leaked active claim: ${claim}`); process.exit(1);
    }
  }

  if (validResStr.includes("body") || validResStr.includes("targetUrl") || validResStr.includes("selectedSummaries") || validResStr.includes("draftTriage")) {
    console.error("FAIL leaked raw data or M45 payloads"); process.exit(1);
  }

  console.log("[*] Testing Unsafe Metadata Handling...");
  const unsafeReq = { ...reqBase, scanId: "secret_id" };
  const unsafeRes = await runCoreCandidatePipelineRealityCheck(unsafeReq as any);
  assertFailedResult(unsafeRes, "input_fixture");
  if (JSON.stringify(unsafeRes).includes("secret_id")) {
    console.error("FAIL raw echo");
    console.error(JSON.stringify(unsafeRes, null, 2));
    process.exit(1);
  }

  console.log("[*] Testing Debug Mutation: Mutated Scan ID after Selection...");
  const mutScanReq = { ...reqBase, debugMutation: "mutate_scan_id_after_selection" };
  const mutScanRes = await runCoreCandidatePipelineRealityCheck(mutScanReq as any);
  assertFailedResult(mutScanRes, "continuity_validation");
  if (!(mutScanRes as any).failedContinuityChecks.includes("same_scan_id")) {
    console.error("FAIL mutScanRes did not catch mutated scan ID");
    console.error(JSON.stringify(mutScanRes, null, 2));
    process.exit(1);
  }

  console.log("[*] Testing Debug Mutation: Mutated Count after Selection...");
  const mutCountReq = { ...reqBase, debugMutation: "mutate_selected_count_after_selection" };
  const mutCountRes = await runCoreCandidatePipelineRealityCheck(mutCountReq as any);
  assertFailedResult(mutCountRes, "continuity_validation");
  if (!(mutCountRes as any).failedContinuityChecks.includes("counts_preserved")) {
    console.error("FAIL mutCountRes did not catch mutated count"); process.exit(1);
  }

  console.log("[*] Testing Debug Mutation: Mutated Candidate Refs before Summary...");
  const mutRefsReq = { ...reqBase, debugMutation: "mutate_candidate_refs_before_summary" };
  const mutRefsRes = await runCoreCandidatePipelineRealityCheck(mutRefsReq as any);
  assertFailedResult(mutRefsRes, "continuity_validation");
  if (!(mutRefsRes as any).failedContinuityChecks.includes("refs_preserved")) {
    console.error("FAIL mutRefsRes did not catch mutated refs"); process.exit(1);
  }



  console.log("[*] Testing Invalid Debug Mutation...");
  const invalidMutationReq = { ...reqBase, debugMutation: "secret_invalid_mutation" } as unknown;
  const invalidMutationRes = await runCoreCandidatePipelineRealityCheck(invalidMutationReq as any);
  assertFailedResult(invalidMutationRes, "input_fixture");
  if (JSON.stringify(invalidMutationRes).includes("secret_invalid_mutation")) {
    console.error("FAIL invalidMutationRes leaked raw data"); process.exit(1);
  }

  console.log("--- M55 Core Candidate Pipeline Reality Check Smoke Completed Successfully ---");
}

runSmokeTest().catch(console.error);
