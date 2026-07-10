import type {
  CreateReviewedEvidenceFindingCandidateDraftRequest,
  SummarizeReviewedEvidenceFindingCandidateDraftRequest,
} from "../finding-candidate-draft/ReviewedEvidenceFindingCandidateDraftContracts.js";
import {
  createReviewedEvidenceFindingCandidateDraft
} from "../finding-candidate-draft/ReviewedEvidenceFindingCandidateDraftService.js";
import {
  summarizeReviewedEvidenceFindingCandidateDraft
} from "../finding-candidate-draft/ReviewedEvidenceFindingCandidateDraftReadModel.js";
import {
  validateReviewedEvidenceFindingCandidateDraft
} from "../finding-candidate-draft/ReviewedEvidenceFindingCandidateDraftService.js";
import type {
  ReviewedEvidenceSelectionSet
} from "../evidence-selection/ReviewedEvidenceSelectionContracts.js";

async function runSmoke() {
  console.log("--- M53 DB-Free Reviewed Evidence Finding Candidate Draft Smoke Test ---");

  const evaluatedAt = "2026-07-03T10:00:00.000Z";
  const scanId = "scan_test_123";

  // Create a valid M52 selection set manually
  const validSelectionSet: ReviewedEvidenceSelectionSet = {
    contractVersion: "fixguard-reviewed-evidence-selection/v0",
    kind: "reviewed_evidence_selection_set",
    selectionId: "sel_1",
    scanId,
    createdAt: "2026-07-02T10:00:00.000Z",
    selectionMode: "criteria_query",
    selectedRefs: [
      { storeRecordId: "rec_1", evidenceId: "ev_1", scanId, indicatorId: "ind_1" },
      { storeRecordId: "rec_2", evidenceId: "ev_2", scanId, indicatorId: "ind_2" },
      { storeRecordId: "rec_3", evidenceId: "ev_3", scanId, indicatorId: "ind_1" }
    ],
    selectedSummaries: [
      {
        storeRecordId: "rec_1",
        evidenceId: "ev_1",
        scanId,
        indicatorId: "ind_1",
        collectedAt: "2026-06-01T10:00:00.000Z",
        savedAt: "2026-06-01T10:00:00.000Z",
        evidenceType: "http_difference",
        strength: "strong",
        sourceBoundary: "M50"
      },
      {
        storeRecordId: "rec_2",
        evidenceId: "ev_2",
        scanId,
        indicatorId: "ind_2",
        collectedAt: "2026-06-02T10:00:00.000Z",
        savedAt: "2026-06-02T10:00:00.000Z",
        evidenceType: "http_difference",
        strength: "weak",
        sourceBoundary: "M50"
      },
      {
        storeRecordId: "rec_3",
        evidenceId: "ev_3",
        scanId,
        indicatorId: "ind_1",
        collectedAt: "2026-06-03T10:00:00.000Z",
        savedAt: "2026-06-03T10:00:00.000Z",
        evidenceType: "manual_review_note",
        strength: "moderate",
        sourceBoundary: "M50"
      }
    ],
    selectionStats: {
      selectedCount: 3,
      candidateInputCount: 10,
      duplicateInputCount: 0,
      rejectedInputCount: 7
    },
    storage: {
      persisted: false,
      persistedToDatabase: false,
      externalized: false
    },
    explicitNonClaims: {
      noFindingCreated: true,
      noFindingCandidateCreated: true,
      noSafeReportItemCreated: true,
      noExternalReportCreated: true,
      noConfirmedVulnerability: true,
      noSeverityRiskOrImpactClaim: true,
      noNetworkExecution: true,
      noToolExecution: true,
      noPersistence: true
    },
    classification: {
      createsReviewedEvidenceSelectionSet: true,
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

  const baseReq: CreateReviewedEvidenceFindingCandidateDraftRequest = {
    contractVersion: "fixguard-reviewed-evidence-finding-candidate-draft/v0",
    kind: "create_reviewed_evidence_finding_candidate_draft_request",
    draftId: "draft_1",
    scanId,
    requestedAt: evaluatedAt,
    selectionSet: validSelectionSet,
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

  console.log("[*] Testing Happy Path: Create Draft...");
  const res = await createReviewedEvidenceFindingCandidateDraft(baseReq, evaluatedAt);
  if (res.status !== "draft_created") {
    console.error("FAIL: Happy path failed to create draft", res);
    process.exit(1);
  }

  const draft = res.draft!;
  
  console.log("[*] Verifying Draft constraints and summary counts...");
  if (draft.sourceSelection.selectedCount !== 3) { console.error("FAIL selectedCount", draft); process.exit(1); }
  if (draft.sourceSelection.selectedRefs.length !== 3) { console.error("FAIL selectedRefs length", draft); process.exit(1); }
  
  const etc = draft.observedEvidenceSummary.evidenceTypeCounts;
  if (etc.http_difference !== 2 || etc.manual_review_note !== 1 || Object.keys(etc).length !== 2) {
    console.error("FAIL evidenceTypeCounts", etc); process.exit(1);
  }
  
  const sc = draft.observedEvidenceSummary.strengthCounts;
  if (sc.strong !== 1 || sc.moderate !== 1 || sc.weak !== 1 || Object.keys(sc).length !== 3) {
    console.error("FAIL strengthCounts", sc); process.exit(1);
  }

  const ind = draft.observedEvidenceSummary.indicatorIds;
  if (ind.length !== 2 || ind[0] !== "ind_1" || ind[1] !== "ind_2") {
    console.error("FAIL indicatorIds", ind); process.exit(1);
  }

  const cr = draft.observedEvidenceSummary.collectedAtRange;
  if (cr.earliest !== "2026-06-01T10:00:00.000Z" || cr.latest !== "2026-06-03T10:00:00.000Z") {
    console.error("FAIL collectedAtRange", cr); process.exit(1);
  }

  const sr = draft.observedEvidenceSummary.savedAtRange;
  if (sr.earliest !== "2026-06-01T10:00:00.000Z" || sr.latest !== "2026-06-03T10:00:00.000Z") {
    console.error("FAIL savedAtRange", sr); process.exit(1);
  }

  if ((draft as any).selectedSummaries !== undefined) {
    console.error("FAIL: draft contains raw summaries"); process.exit(1);
  }

  console.log("[*] Testing Draft Result Classification...");
  if (res.classification.createsFindingCandidateDraft !== true) {
    console.error("FAIL: classification.createsFindingCandidateDraft must be true"); process.exit(1);
  }
  if ((res.classification as any).createsFindingCandidate === true) {
    console.error("FAIL: createsFindingCandidate must be false"); process.exit(1);
  }
  if (res.explicitNonClaims.noFindingCandidateCreated !== true) {
    console.error("FAIL: explicitNonClaims.noFindingCandidateCreated must be true"); process.exit(1);
  }

  console.log("[*] Testing raw echo sanitization (Create)...");
  const badEchoReq = { ...baseReq, draftId: "secret_draft", scanId: "secret_scan" };
  const resBadEcho = await createReviewedEvidenceFindingCandidateDraft(badEchoReq as any, "invalid_date");
  assertFail(resBadEcho, "invalid_draft_metadata");
  const badEchoJson = JSON.stringify(resBadEcho);
  if (badEchoJson.includes("secret") || badEchoJson.includes("invalid_date")) {
    console.error("FAIL: Raw echo detected", badEchoJson); process.exit(1);
  }

  console.log("[*] Testing Invalid Request (extra key)...");
  const extraKeyReq = { ...baseReq, extraKey: true };
  assertFail(await createReviewedEvidenceFindingCandidateDraft(extraKeyReq as any, evaluatedAt), "invalid_draft_request");

  console.log("[*] Testing Selection Set Empty...");
  const emptySel = { ...validSelectionSet, selectedRefs: [], selectedSummaries: [], selectionStats: { ...validSelectionSet.selectionStats, selectedCount: 0 } };
  const emptyReq = { ...baseReq, selectionSet: emptySel };
  assertBlocked(await createReviewedEvidenceFindingCandidateDraft(emptyReq as any, evaluatedAt), "selection_set_empty");

  console.log("[*] Testing Selection Set Scan Mismatch...");
  const mismatchSel = {
    ...validSelectionSet,
    scanId: "other_scan",
    selectedRefs: validSelectionSet.selectedRefs.map(r => ({ ...r, scanId: "other_scan" })),
    selectedSummaries: validSelectionSet.selectedSummaries.map(s => ({ ...s, scanId: "other_scan" }))
  };
  const mismatchReq = { ...baseReq, selectionSet: mismatchSel };
  assertFail(await createReviewedEvidenceFindingCandidateDraft(mismatchReq as any, evaluatedAt), "source_scan_mismatch");

  console.log("[*] Testing Summary Read Model...");
  const baseSumReq: SummarizeReviewedEvidenceFindingCandidateDraftRequest = {
    contractVersion: "fixguard-reviewed-evidence-finding-candidate-draft/v0",
    kind: "summarize_reviewed_evidence_finding_candidate_draft_request",
    summaryId: "sum_1",
    scanId,
    requestedAt: evaluatedAt,
    draft,
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
  };

  const sumRes = await summarizeReviewedEvidenceFindingCandidateDraft(baseSumReq, evaluatedAt);
  if (sumRes.status !== "summarized") {
    console.error("FAIL: Summary failed", sumRes); process.exit(1);
  }
  
  if (sumRes.summary!.candidateKind !== "reviewed_evidence_group" || sumRes.summary!.selectedCount !== 3) {
    console.error("FAIL: Summary content invalid", sumRes.summary); process.exit(1);
  }

  console.log("[*] Testing raw echo sanitization (Summary)...");
  const badSumReq = { ...baseSumReq, summaryId: "secret_sum", scanId: "secret_scan" };
  const badSumRes = await summarizeReviewedEvidenceFindingCandidateDraft(badSumReq as any, "invalid_date");
  assertFail(badSumRes, "invalid_draft_summary_metadata");
  const badSumJson = JSON.stringify(badSumRes);
  if (badSumJson.includes("secret") || badSumJson.includes("invalid_date")) {
    console.error("FAIL: Raw echo detected in summary", badSumJson); process.exit(1);
  }

  console.log("[*] Testing Invalid Request (missing keys)...");
  const { classification: _class1, ...missingReq } = baseReq;
  assertFail(await createReviewedEvidenceFindingCandidateDraft(missingReq as any, evaluatedAt), "invalid_draft_request");

  console.log("[*] Testing Classification Invalid (extra key, string boolean, true)...");
  assertFail(await createReviewedEvidenceFindingCandidateDraft({ ...baseReq, classification: { ...baseReq.classification, extra: false } } as any, evaluatedAt), "invalid_draft_metadata");
  const { createsFindingCandidate: __, ...missingClass } = baseReq.classification;
  assertFail(await createReviewedEvidenceFindingCandidateDraft({ ...baseReq, classification: missingClass } as any, evaluatedAt), "invalid_draft_metadata");
  assertFail(await createReviewedEvidenceFindingCandidateDraft({ ...baseReq, classification: { ...baseReq.classification, createsFindingCandidate: "false" } } as any, evaluatedAt), "invalid_draft_metadata");
  assertFail(await createReviewedEvidenceFindingCandidateDraft({ ...baseReq, classification: { ...baseReq.classification, createsFindingCandidate: true } } as any, evaluatedAt), "invalid_draft_metadata");

  console.log("[*] Testing Unsafe Draft/Scan IDs (no raw echo)...");
  const badIds = ["secret_id", "bad.id", "bad id", "bad/id", "a".repeat(65)];
  for (const bid of badIds) {
    const resBad1 = await createReviewedEvidenceFindingCandidateDraft({ ...baseReq, draftId: bid }, evaluatedAt);
    assertFail(resBad1, "invalid_draft_metadata");
    if (JSON.stringify(resBad1).includes(bid)) { console.error("FAIL: Raw echo bid", bid); process.exit(1); }

    const resBad2 = await createReviewedEvidenceFindingCandidateDraft({ ...baseReq, scanId: bid }, evaluatedAt);
    assertFail(resBad2, "invalid_draft_metadata");
    if (JSON.stringify(resBad2).includes(bid)) { console.error("FAIL: Raw echo bid", bid); process.exit(1); }
  }

  const resBadDate1 = await createReviewedEvidenceFindingCandidateDraft({ ...baseReq, requestedAt: "bad_date_string" }, evaluatedAt);
  assertFail(resBadDate1, "invalid_draft_metadata");
  if (JSON.stringify(resBadDate1).includes("bad_date_string")) { console.error("FAIL: Raw echo date"); process.exit(1); }

  const resBadDate2 = await createReviewedEvidenceFindingCandidateDraft(baseReq, "bad_date_string");
  assertFail(resBadDate2, "invalid_draft_metadata");
  if (JSON.stringify(resBadDate2).includes("bad_date_string")) { console.error("FAIL: Raw echo date"); process.exit(1); }

  console.log("[*] Testing Selection Set Negative Cases...");
  const invalidSelReq = { ...baseReq, selectionSet: { ...validSelectionSet, kind: "wrong" } };
  assertFail(await createReviewedEvidenceFindingCandidateDraft(invalidSelReq as any, evaluatedAt), "selection_set_invalid");
  
  const dupRefReq = { ...baseReq, selectionSet: { ...validSelectionSet, selectedRefs: [...validSelectionSet.selectedRefs, validSelectionSet.selectedRefs[0]], selectionStats: { ...validSelectionSet.selectionStats, selectedCount: 4 } } };
  assertFail(await createReviewedEvidenceFindingCandidateDraft(dupRefReq as any, evaluatedAt), "selection_set_invalid");

  console.log("[*] Testing Draft Validator Nested Exactness...");

  const duplicateRefDraft = {
    ...draft,
    sourceSelection: {
      ...draft.sourceSelection,
      selectedRefs: [
        draft.sourceSelection.selectedRefs[0],
        { ...draft.sourceSelection.selectedRefs[1], storeRecordId: draft.sourceSelection.selectedRefs[0].storeRecordId },
        draft.sourceSelection.selectedRefs[2]
      ]
    }
  };
  if (validateReviewedEvidenceFindingCandidateDraft(duplicateRefDraft as any)) {
    console.error("FAIL: draft allowed duplicate storeRecordId in refs"); process.exit(1);
  }
  
  const badDraft1 = { ...draft, extra: true };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraft1 as any)) { console.error("FAIL: draft extra top key"); process.exit(1); }
  
  const badDraft2 = { ...draft, sourceSelection: { ...draft.sourceSelection, extra: true } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraft2 as any)) { console.error("FAIL: draft extra src key"); process.exit(1); }

  const badDraft3 = { ...draft, observedEvidenceSummary: { ...draft.observedEvidenceSummary, extra: true } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraft3 as any)) { console.error("FAIL: draft extra obs key"); process.exit(1); }

  const badDraft4 = { ...draft, observedEvidenceSummary: { ...draft.observedEvidenceSummary, indicatorIds: [...draft.observedEvidenceSummary.indicatorIds, draft.observedEvidenceSummary.indicatorIds[0]] } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraft4 as any)) { console.error("FAIL: draft dup indicatorIds"); process.exit(1); }

  const badDraft5 = { ...draft, observedEvidenceSummary: { ...draft.observedEvidenceSummary, indicatorIds: ["ind_99"] } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraft5 as any)) { console.error("FAIL: draft wrong indicatorIds"); process.exit(1); }

  const badDraft6 = { ...draft, observedEvidenceSummary: { ...draft.observedEvidenceSummary, evidenceTypeCounts: { ...draft.observedEvidenceSummary.evidenceTypeCounts, unknown: 1 } } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraft6 as any)) { console.error("FAIL: draft wrong evidenceType"); process.exit(1); }

  const badDraft7 = { ...draft, observedEvidenceSummary: { ...draft.observedEvidenceSummary, evidenceTypeCounts: { http_difference: 999 } } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraft7 as any)) { console.error("FAIL: draft wrong type sum"); process.exit(1); }

  const badDraft8 = { ...draft, observedEvidenceSummary: { ...draft.observedEvidenceSummary, strengthCounts: { strong: 0 } } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraft8 as any)) { console.error("FAIL: draft zero count"); process.exit(1); }

  const badDraft9 = { ...draft, observedEvidenceSummary: { ...draft.observedEvidenceSummary, collectedAtRange: { earliest: draft.observedEvidenceSummary.collectedAtRange.latest, latest: draft.observedEvidenceSummary.collectedAtRange.earliest } } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraft9 as any)) { console.error("FAIL: draft bad date range"); process.exit(1); }

  const badDraft9b = { ...draft, observedEvidenceSummary: { ...draft.observedEvidenceSummary, savedAtRange: { earliest: draft.observedEvidenceSummary.savedAtRange.latest, latest: draft.observedEvidenceSummary.savedAtRange.earliest } } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraft9b as any)) { console.error("FAIL: draft bad savedAt date range"); process.exit(1); }

  const badDraftStrengthPositiveIncorrectSum = { ...draft, observedEvidenceSummary: { ...draft.observedEvidenceSummary, strengthCounts: { strong: 1, weak: 1 } } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraftStrengthPositiveIncorrectSum as any)) { console.error("FAIL: draft positive but incorrect strength sum"); process.exit(1); }

  const badDraftInvalidStrengthEnum = { ...draft, observedEvidenceSummary: { ...draft.observedEvidenceSummary, strengthCounts: { ...draft.observedEvidenceSummary.strengthCounts, not_allowed_strength: 1 } } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraftInvalidStrengthEnum as any)) { console.error("FAIL: draft invalid strength enum"); process.exit(1); }

  const badDraftIncorrectSelectedCount = { ...draft, sourceSelection: { ...draft.sourceSelection, selectedCount: 99 } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraftIncorrectSelectedCount as any)) { console.error("FAIL: draft incorrect selectedCount"); process.exit(1); }

  const badDraftStringBoolean = { ...draft, explicitNonClaims: { ...draft.explicitNonClaims, noFindingCandidateCreated: "true" } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraftStringBoolean as any)) { console.error("FAIL: draft string boolean"); process.exit(1); }

  const badDraftUnsafeRefIds = { ...draft, sourceSelection: { ...draft.sourceSelection, selectedRefs: [{ ...draft.sourceSelection.selectedRefs[0], storeRecordId: "secret_id" }, draft.sourceSelection.selectedRefs[1], draft.sourceSelection.selectedRefs[2]] } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraftUnsafeRefIds as any)) { console.error("FAIL: draft unsafe ref ID"); process.exit(1); }

  console.log("[*] Testing Formal Candidate / Claim Boundaries...");
  if ((res as any).draft?.selectedSummaries !== undefined) { console.error("FAIL: selectedSummaries in draft"); process.exit(1); }
  if ((res as any).draft?.vulnerability !== undefined) { console.error("FAIL: vulnerability in draft"); process.exit(1); }
  if ((res as any).draft?.severity !== undefined) { console.error("FAIL: severity in draft"); process.exit(1); }
  const resBadForDraft = await createReviewedEvidenceFindingCandidateDraft({ ...baseReq, draftId: "bad/id" }, evaluatedAt);
  if ((resBadForDraft as any).draft !== undefined) { console.error("FAIL: draft on non-created"); process.exit(1); }

  console.log("[*] Testing Summary Read Model Coverage...");
  assertFail(await summarizeReviewedEvidenceFindingCandidateDraft(baseSumReq, "invalid"), "invalid_draft_summary_metadata");
  assertFail(await summarizeReviewedEvidenceFindingCandidateDraft({ ...baseSumReq, requestedAt: "invalid" } as any, evaluatedAt), "invalid_draft_summary_metadata");
  assertFail(await summarizeReviewedEvidenceFindingCandidateDraft({ ...baseSumReq, classification: { ...baseSumReq.classification, extra: true } } as any, evaluatedAt), "invalid_draft_summary_metadata");
  assertFail(await summarizeReviewedEvidenceFindingCandidateDraft({ ...baseSumReq, classification: missingClass } as any, evaluatedAt), "invalid_draft_summary_metadata");
  assertFail(await summarizeReviewedEvidenceFindingCandidateDraft({ ...baseSumReq, classification: { ...baseSumReq.classification, createsFindingCandidate: "false" } } as any, evaluatedAt), "invalid_draft_summary_metadata");
  assertFail(await summarizeReviewedEvidenceFindingCandidateDraft({ ...baseSumReq, classification: { ...baseSumReq.classification, createsFindingCandidate: true } } as any, evaluatedAt), "invalid_draft_summary_metadata");

  const scanSumReq = { ...baseSumReq, scanId: "other" };
  assertFail(await summarizeReviewedEvidenceFindingCandidateDraft(scanSumReq, evaluatedAt), "source_scan_mismatch");

  const sumBadIds = ["secret_id", "bad.id", "bad id", "bad/id", "a".repeat(65)];
  for (const bid of sumBadIds) {
    const sBad1 = await summarizeReviewedEvidenceFindingCandidateDraft({ ...baseSumReq, summaryId: bid }, evaluatedAt);
    assertFail(sBad1, "invalid_draft_summary_metadata");
    if (JSON.stringify(sBad1).includes(bid)) { console.error("FAIL: Raw echo sbid"); process.exit(1); }
  }

  const { kind: _k2, ...sumMissing } = baseSumReq;
  assertFail(await summarizeReviewedEvidenceFindingCandidateDraft(sumMissing as any, evaluatedAt), "invalid_draft_summary_request");

  console.log("[*] Testing Exact Summary Result Shape...");
  const sumKeys = Object.keys(sumRes.summary!).sort().join(",");
  const expectedSumKeys = ["draftId", "scanId", "sourceSelectionId", "selectedCount", "candidateKind", "triageState", "confidenceState", "evidenceTypeCounts", "strengthCounts", "indicatorIds", "createdAt"].sort().join(",");
  if (sumKeys !== expectedSumKeys) {
    console.error("FAIL: Exact summary keys mismatch. Expected:", expectedSumKeys, "Got:", sumKeys);
    process.exit(1);
  }
  if ((sumRes.summary as any).draft !== undefined || (sumRes.summary as any).selectedRefs !== undefined || (sumRes.summary as any).selectedSummaries !== undefined || (sumRes.summary as any).sourceSelection !== undefined) {
    console.error("FAIL: Summary result leaked unapproved keys"); process.exit(1);
  }

  console.log("[*] Testing indicatorId Source of Truth...");
  const badDraft10 = { ...draft, observedEvidenceSummary: { ...draft.observedEvidenceSummary, indicatorIds: ["ind_3", "ind_4"] } };
  if (validateReviewedEvidenceFindingCandidateDraft(badDraft10 as any)) {
    console.error("FAIL: draft validator must enforce indicatorIds matches selectedRefs"); process.exit(1);
  }
  // This proves that indicatorIds are bounded by selectedRefs.

  console.log("=== M53 DB-Free Reviewed Evidence Finding Candidate Draft Smoke PASS ===");
}

runSmoke();
