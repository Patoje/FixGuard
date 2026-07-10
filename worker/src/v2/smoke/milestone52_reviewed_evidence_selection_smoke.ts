import type {
  SelectReviewedEvidenceRequest,
  SummarizeReviewedEvidenceSelectionRequest
} from "../evidence-selection/ReviewedEvidenceSelectionContracts.js";
import {
  selectReviewedEvidence
} from "../evidence-selection/ReviewedEvidenceSelectionService.js";
import {
  summarizeReviewedEvidenceSelection
} from "../evidence-selection/ReviewedEvidenceSelectionReadModel.js";
import { getReviewedEvidence } from "../evidence-store/ReviewedEvidenceReadModel.js";
import { InMemoryReviewedEvidenceStoreRepository } from "../evidence-store/InMemoryReviewedEvidenceStoreRepository.js";
import { saveReviewedEvidence } from "../evidence-store/ReviewedEvidenceStoreService.js";

async function runSmoke() {
  console.log("--- M52 DB-Free Reviewed Evidence Selection Smoke Test ---");

  const evaluatedAt = "2026-07-02T10:00:00.000Z";
  const scanId = "scan_test_123";

  // Setup fake M51 store records
  const repo = new InMemoryReviewedEvidenceStoreRepository();
  const basePromo = {
    contractVersion: "fixguard-human-reviewed-evidence-promotion/v0" as const,
    kind: "human_reviewed_evidence_promotion_result" as const,
    scanId,
    evaluatedAt: "2026-07-01T10:00:00.000Z",
    status: "promoted" as const,
    reasonCode: "promoted_to_non_persisted_evidence_record" as const,
    explicitNonClaims: {
      noConfirmedVulnerability: true,
      noFindingCreated: true,
      noFindingCandidateCreated: true,
      noSafeReportItemCreated: true,
      noExternalReportCreated: true,
      noSeverityRiskOrImpactClaim: true,
      noNetworkExecution: true,
      noToolExecution: true,
      noPersistence: true
    } as const,
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
    } as const,
  };

  const recordsData = [
    { saveId: "save_1", evId: "ev_1", ind: "ind_1", type: "http_difference", strength: "weak", time: "2026-06-01T10:00:00.000Z", saveTime: "2026-06-01T10:00:00.000Z" },
    { saveId: "save_2", evId: "ev_2", ind: "ind_1", type: "authorization_difference", strength: "moderate", time: "2026-06-02T10:00:00.000Z", saveTime: "2026-06-02T10:00:00.000Z" },
    { saveId: "save_3", evId: "ev_3", ind: "ind_2", type: "manual_review_note", strength: "strong", time: "2026-06-03T10:00:00.000Z", saveTime: "2026-06-03T10:00:00.000Z" },
    { 
      saveId: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 
      evId:   "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 
      ind: "ind_long", type: "manual_review_note", strength: "strong", time: "2026-06-04T10:00:00.000Z", saveTime: "2026-06-04T10:00:00.000Z" 
    },
    { saveId: "save_old_match", evId: "ev_old", ind: "ind_match", type: "http_difference", strength: "weak", time: "2026-06-05T10:00:00.000Z", saveTime: "2026-06-05T10:00:00.000Z" },
    { saveId: "save_new_other", evId: "ev_new", ind: "ind_other", type: "http_difference", strength: "weak", time: "2026-06-06T10:00:00.000Z", saveTime: "2026-06-06T10:00:00.000Z" }
  ];

  for (const r of recordsData) {
    const promo = {
      ...basePromo,
      promotionId: "promo_1",
      nonPersistedEvidenceRecord: {
        contractVersion: "fixguard-evidence-boundary/v0" as const,
        kind: "evidence_record" as const,
        evidenceId: r.evId,
        scanId,
        indicatorId: r.ind,
        collectedAt: r.time,
        collectedBy: "manual_review",
        evidenceType: r.type,
        strength: r.strength,
        redaction: {
          isRedacted: true,
          redactionMethod: "manual_redaction"
        },
        classification: {
          createsRealFindings: false,
          createsPersistedEvidence: false,
          confirmsVulnerabilities: false,
          makesRiskClaims: false,
          makesSeverityClaims: false,
          makesImpactClaims: false
        }
      }
    } as any;
    const saveReq = {
      contractVersion: "fixguard-reviewed-evidence-store/v0" as const,
      kind: "save_reviewed_evidence_request" as const,
      saveId: r.saveId,
      scanId,
      requestedAt: evaluatedAt,
      promotionResult: promo,
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
      } as const
    };
    const res = await saveReviewedEvidence(saveReq, r.saveTime, repo);
    if (res.status !== "saved") {
      console.error("SETUP SAVE FAILED", r.saveId, res);
      process.exit(1);
    }
  }

  const baseSelectReq: Omit<SelectReviewedEvidenceRequest, "source"> = {
    contractVersion: "fixguard-reviewed-evidence-selection/v0",
    kind: "select_reviewed_evidence_request",
    selectionId: "sel_1",
    scanId,
    requestedAt: evaluatedAt,
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
  };

  const assertFail = (res: any, code: string) => {
    if (res.status !== "failed" || res.reasonCode !== code) {
      console.error(`FAIL: expected failed/${code}, got:`, res);
      process.exit(1);
    }
  };

  const assertBlocked = (res: any, code: string) => {
    if (res.status !== "blocked" || res.reasonCode !== code) {
      console.error(`FAIL: expected blocked/${code}, got:`, res);
      process.exit(1);
    }
  };

  console.log("[*] Testing 64-char valid internal ID length limit (Happy path)...");
  const longSelReq = {
    ...baseSelectReq,
    selectionId: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    source: { mode: "explicit_store_record_ids", storeRecordIds: ["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"] }
  };
  const selLong = await selectReviewedEvidence(longSelReq as any, evaluatedAt, repo);
  if (selLong.status !== "selected") {
    console.error("FAIL: Long IDs failed to select", selLong);
    process.exit(1);
  }

  console.log("[*] Testing raw echo sanitization in select...");
  const rawEchoReq = {
    ...baseSelectReq,
    selectionId: "secret_id",
    scanId: "secret_id_scan",
    source: { mode: "explicit_store_record_ids", storeRecordIds: ["secret_record"] }
  };
  const selRaw = await selectReviewedEvidence(rawEchoReq as any, "2026-07-02notvalid", repo);
  assertFail(selRaw, "invalid_selection_metadata");
  const selRawJson = JSON.stringify(selRaw);
  if (selRawJson.includes("secret_id") || selRawJson.includes("notvalid")) {
    console.error("FAIL: Raw echo found in select", selRawJson);
    process.exit(1);
  }

  console.log("[*] Testing exact classification validation (select)...");
  const badClassReqs = [
    { ...baseSelectReq, classification: { ...baseSelectReq.classification, extraKey: true } },
    { ...baseSelectReq, classification: { ...baseSelectReq.classification, executesNetwork: "false" } },
    { ...baseSelectReq, classification: { ...baseSelectReq.classification, createsReviewedEvidenceSelectionSet: true } },
  ];
  for (const b of badClassReqs) {
    const res = await selectReviewedEvidence(b as any, evaluatedAt, repo);
    assertFail(res, "invalid_selection_metadata");
  }

  // Generate a valid selection set
  const selCrit = await selectReviewedEvidence({
    ...baseSelectReq,
    source: { mode: "criteria_query", criteria: { strengths: ["strong", "moderate"] } }
  }, evaluatedAt, repo);

  if (selCrit.status !== "selected") {
    console.error("FAIL: criteria query", selCrit);
    process.exit(1);
  }

  const baseSumReq: SummarizeReviewedEvidenceSelectionRequest = {
    contractVersion: "fixguard-reviewed-evidence-selection/v0",
    kind: "summarize_reviewed_evidence_selection_request",
    summaryId: "sum_1",
    scanId,
    requestedAt: evaluatedAt,
    selectionSet: selCrit.selectionSet as any,
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
  };

  console.log("[*] Testing raw echo sanitization in summarize...");
  const sumRawReq = { ...baseSumReq, summaryId: "secret_sum", scanId: "secret_scan" };
  const sumRaw = await summarizeReviewedEvidenceSelection(sumRawReq as any, "invalid_date");
  assertFail(sumRaw, "invalid_selection_summary_metadata");
  const sumRawJson = JSON.stringify(sumRaw);
  if (sumRawJson.includes("secret_") || sumRawJson.includes("invalid_date")) {
    console.error("FAIL: Raw echo found in summarize", sumRawJson);
    process.exit(1);
  }

  console.log("[*] Testing scan mismatch behaviors...");
  const mismatchSumReq = { ...baseSumReq, scanId: "other_scan_id" };
  const mismatchSum = await summarizeReviewedEvidenceSelection(mismatchSumReq as any, evaluatedAt);
  assertFail(mismatchSum, "source_scan_mismatch"); // Contract specified failed / source_scan_mismatch for summary

  // For select, if we query M51 for "save_1" but pass scanId = "other_scan", M51 fails it internally.
  const mismatchSelReq = { ...baseSelectReq, scanId: "other_scan", source: { mode: "explicit_store_record_ids", storeRecordIds: ["save_1"] } };
  const mismatchSel = await selectReviewedEvidence(mismatchSelReq as any, evaluatedAt, repo);
  assertFail(mismatchSel, "source_reviewed_evidence_invalid");

  // The mismatch behavior for selectReviewedEvidence is covered implicitly because M51 blocks it.
  // We cannot mock M51's getReviewedEvidence boundary function here to force a bypass,
  // but we know selectReviewedEvidence checks `res.summary.scanId !== request.scanId` anyway.

  console.log("[*] Testing selection set exact refs/summaries keys validator...");
  const badSetReq1 = { ...baseSumReq, selectionSet: { ...baseSumReq.selectionSet, selectedRefs: [{ ...baseSumReq.selectionSet.selectedRefs[0], extraRaw: true }, ...baseSumReq.selectionSet.selectedRefs.slice(1)] } };
  const badSetReq2 = { ...baseSumReq, selectionSet: { ...baseSumReq.selectionSet, selectedSummaries: [{ ...baseSumReq.selectionSet.selectedSummaries[0], rawHeaders: ["xyz"] }, ...baseSumReq.selectionSet.selectedSummaries.slice(1)] } };
  const badSet1 = await summarizeReviewedEvidenceSelection(badSetReq1 as any, evaluatedAt);
  const badSet2 = await summarizeReviewedEvidenceSelection(badSetReq2 as any, evaluatedAt);
  assertFail(badSet1, "selection_set_validation_failed");
  assertFail(badSet2, "selection_set_validation_failed");

  console.log("[*] Testing request/source/options coverage...");
  const badSrcReqs = [
    { ...baseSelectReq, source: { mode: "criteria_query" } }, // missing criteria
    { ...baseSelectReq, source: { criteria: {} } }, // missing mode
    { ...baseSelectReq, source: { mode: "unknown_mode" } },
    { ...baseSelectReq, source: { mode: "explicit_store_record_ids", storeRecordIds: [] } },
    { ...baseSelectReq, source: { mode: "explicit_store_record_ids", storeRecordIds: Array(101).fill("id") } },
    { ...baseSelectReq, source: { mode: "explicit_store_record_ids", storeRecordIds: ["save_1"], options: "bad" } },
    { ...baseSelectReq, source: { mode: "explicit_store_record_ids", storeRecordIds: ["save_1"] }, options: { includeSummaries: false } }, // extra keys
    { ...baseSelectReq, source: { mode: "explicit_store_record_ids", storeRecordIds: ["save_1"] }, options: { limit: -1 } },
    { ...baseSelectReq, source: { mode: "explicit_store_record_ids", storeRecordIds: ["save_1"] }, options: { limit: "10" } },
  ];
  for (const r of badSrcReqs) {
    const res = await selectReviewedEvidence(r as any, evaluatedAt, repo);
    if (res.status !== "failed" && res.status !== "blocked") { // Could be missing or invalid
      console.error("FAIL: bad source req succeeded", res);
      process.exit(1);
    }
  }

  console.log("[*] Testing criteria_query applies limit after filtering...");
  const selFilterLimit = await selectReviewedEvidence({
    ...baseSelectReq,
    source: {
      mode: "criteria_query",
      criteria: { indicatorIds: ["ind_match"] }
    },
    options: { limit: 1 }
  }, evaluatedAt, repo);

  if (selFilterLimit.status !== "selected" || selFilterLimit.reasonCode !== "reviewed_evidence_selected") {
    console.error("FAIL: expected selected/reviewed_evidence_selected, got:", selFilterLimit);
    process.exit(1);
  }
  
  if (!selFilterLimit.selectionSet || selFilterLimit.selectionSet.selectedRefs.length !== 1) {
    console.error("FAIL: missing or invalid selectionSet refs", selFilterLimit);
    process.exit(1);
  }
  
  if (selFilterLimit.selectionSet.selectedRefs[0].storeRecordId !== "save_old_match") {
    console.error("FAIL: wrong record selected. Expected save_old_match, got:", selFilterLimit.selectionSet.selectedRefs[0].storeRecordId);
    process.exit(1);
  }
  
  if (selFilterLimit.selectionSet.selectedSummaries[0].indicatorId !== "ind_match") {
    console.error("FAIL: wrong summary indicatorId", selFilterLimit.selectionSet.selectedSummaries[0].indicatorId);
    process.exit(1);
  }

  const sStats = selFilterLimit.selectionSet.selectionStats;
  if (sStats.selectedCount !== 1 || sStats.duplicateInputCount !== 0 || sStats.rejectedInputCount !== sStats.candidateInputCount - 1) {
    console.error("FAIL: wrong stats", sStats);
    process.exit(1);
  }

  console.log("=== M52 DB-Free Reviewed Evidence Selection Smoke PASS ===");
}

runSmoke();
