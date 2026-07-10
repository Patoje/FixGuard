import {
  promoteReviewedEvidenceFindingCandidateDraft,
  validateReviewedEvidenceFormalFindingCandidate
} from "../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionService.js";
import {
  summarizeReviewedEvidenceFormalFindingCandidate
} from "../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionReadModel.js";
import type {
  PromoteReviewedEvidenceFindingCandidateDraftRequest,
  ReviewedEvidenceFindingCandidateTriageDecision,
  ReviewedEvidenceFormalFindingCandidate
} from "../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionContracts.js";
import type {
  ReviewedEvidenceFindingCandidateDraft
} from "../finding-candidate-draft/ReviewedEvidenceFindingCandidateDraftContracts.js";
import assert from "node:assert";

async function runSmokeTest() {
  console.log("--- V2 Reviewed Evidence Finding Candidate Promotion (M54) Smoke Test ---");
  
  const scanId = "scan_0000000000000_1a2b3c4";
  const candidateId = "candidate_11111_0a0a0a";
  const draftId = "draft_22222_0a0a0a";
  const selectionId = "selection_33333_0a0a0a";
  const evaluatedAt = "2026-07-10T12:00:00.000Z";
  
  const validDraft: ReviewedEvidenceFindingCandidateDraft = {
    contractVersion: "fixguard-reviewed-evidence-finding-candidate-draft/v0",
    kind: "reviewed_evidence_finding_candidate_draft",
    draftId,
    scanId,
    createdAt: evaluatedAt,
    sourceSelection: {
      selectionId,
      selectionMode: "explicit_store_record_ids",
      selectedCount: 2,
      selectedRefs: [
        { storeRecordId: "store_1", evidenceId: "ev_1", scanId, indicatorId: "ind_1" },
        { storeRecordId: "store_2", evidenceId: "ev_2", scanId, indicatorId: "ind_2" }
      ]
    },
    observedEvidenceSummary: {
      evidenceTypeCounts: { http_difference: 2 },
      strengthCounts: { strong: 2 },
      indicatorIds: ["ind_1", "ind_2"],
      collectedAtRange: { earliest: evaluatedAt, latest: evaluatedAt },
      savedAtRange: { earliest: evaluatedAt, latest: evaluatedAt }
    },
    draftTriage: {
      triageState: "requires_human_triage",
      confidenceState: "evidence_grouped_not_confirmed",
      humanReviewRequired: true
    },
    draftLabels: {
      candidateKind: "reviewed_evidence_group",
      labelSource: "closed_boundary_generated"
    },
    storage: { persisted: false, persistedToDatabase: false, externalized: false },
    explicitNonClaims: {
      noFindingCandidateCreated: true,
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
      createsFindingCandidateDraft: true,
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

  const validTriageDecision: ReviewedEvidenceFindingCandidateTriageDecision = {
    decisionId: "decision_123",
    reviewerId: "reviewer_456",
    reviewedAt: evaluatedAt,
    decision: "approve_finding_candidate_promotion",
    attestations: {
      reviewedDraft: true,
      reviewedEvidenceRefs: true,
      understandsCandidateIsNotConfirmedFinding: true,
      understandsNoVulnerabilityConfirmed: true,
      understandsNoExploitabilityClaim: true,
      understandsNoSeverityRiskImpactAssigned: true,
      understandsNoRemediationAdvice: true,
      authorizedPromotionToFormalCandidate: true
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
    }
  };

  const baseReq: PromoteReviewedEvidenceFindingCandidateDraftRequest = {
    contractVersion: "fixguard-reviewed-evidence-finding-candidate-promotion/v0",
    kind: "promote_reviewed_evidence_finding_candidate_draft_request",
    candidateId,
    scanId,
    requestedAt: evaluatedAt,
    draft: validDraft,
    triageDecision: validTriageDecision,
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

  console.log("[*] Testing Request Validation (Negative Cases)...");

  assertFail(await promoteReviewedEvidenceFindingCandidateDraft({ ...baseReq, extra: 1 } as any, evaluatedAt), "invalid_promotion_request");
  
  const reqNoDraft = { ...baseReq };
  delete (reqNoDraft as any).draft;
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft(reqNoDraft as any, evaluatedAt), "invalid_promotion_request");

  assertFail(await promoteReviewedEvidenceFindingCandidateDraft({ ...baseReq, classification: { ...baseReq.classification, extra: false } } as any, evaluatedAt), "invalid_promotion_metadata");
  
  const reqClassMiss = { ...baseReq, classification: { ...baseReq.classification } };
  delete (reqClassMiss.classification as any).createsFormalFindingCandidate;
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft(reqClassMiss as any, evaluatedAt), "invalid_promotion_metadata");
  
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft({ ...baseReq, classification: { ...baseReq.classification, createsFormalFindingCandidate: "false" } } as any, evaluatedAt), "invalid_promotion_metadata");
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft({ ...baseReq, classification: { ...baseReq.classification, createsFormalFindingCandidate: true } } as any, evaluatedAt), "invalid_promotion_metadata");

  const reqUnsafeCandidateId = await promoteReviewedEvidenceFindingCandidateDraft({ ...baseReq, candidateId: "secret_id" }, evaluatedAt);
  assertFail(reqUnsafeCandidateId, "invalid_promotion_metadata");
  if (JSON.stringify(reqUnsafeCandidateId).includes("secret_id")) { console.error("FAIL raw echo"); process.exit(1); }

  const reqUnsafeScanId = await promoteReviewedEvidenceFindingCandidateDraft({ ...baseReq, scanId: "secret_id" }, evaluatedAt);
  assertFail(reqUnsafeScanId, "invalid_promotion_metadata");
  if (JSON.stringify(reqUnsafeScanId).includes("secret_id")) { console.error("FAIL raw echo"); process.exit(1); }

  const reqInvalidTime = await promoteReviewedEvidenceFindingCandidateDraft({ ...baseReq, requestedAt: "bad" }, evaluatedAt);
  assertFail(reqInvalidTime, "invalid_promotion_metadata");
  if (JSON.stringify(reqInvalidTime).includes("bad")) { console.error("FAIL raw echo"); process.exit(1); }

  const reqInvalidEvalTime = await promoteReviewedEvidenceFindingCandidateDraft(baseReq, "bad_time");
  assertFail(reqInvalidEvalTime, "invalid_promotion_metadata");
  if (JSON.stringify(reqInvalidEvalTime).includes("bad_time")) { console.error("FAIL raw echo"); process.exit(1); }
  if (!JSON.stringify(reqInvalidEvalTime).includes("TIMESTAMP_REDACTED")) { console.error("FAIL missing redacted sentinel"); process.exit(1); }

  console.log("[*] Testing Draft Validation (Negative Cases)...");
  
  const invalidDraftReq = { ...baseReq, draft: { ...validDraft, kind: "wrong" } };
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft(invalidDraftReq as any, evaluatedAt), "draft_invalid");
  
  const scanMismatchDraftReq = { ...baseReq, draft: { ...validDraft, scanId: "different" } };
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft(scanMismatchDraftReq as any, evaluatedAt), "draft_invalid"); // draft validator catches the mismatch early if refs scanId don't match, or we catch it
  
  const draftScanMismatch2Req = { ...baseReq, scanId: "different" };
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft(draftScanMismatch2Req as any, evaluatedAt), "source_scan_mismatch");

  console.log("[*] Testing Triage Decision (Negative Cases)...");
  
  const reqNoTriage = { ...baseReq };
  delete (reqNoTriage as any).triageDecision;
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft(reqNoTriage as any, evaluatedAt), "invalid_promotion_request");

  const tdNoDec = { ...baseReq, triageDecision: { ...validTriageDecision } };
  delete (tdNoDec.triageDecision as any).decision;
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft(tdNoDec as any, evaluatedAt), "invalid_triage_decision");

  const tdExtra = { ...baseReq, triageDecision: { ...validTriageDecision, extra: true } };
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft(tdExtra as any, evaluatedAt), "invalid_triage_decision");
  
  const tdUnsafeDecId = await promoteReviewedEvidenceFindingCandidateDraft({ ...baseReq, triageDecision: { ...validTriageDecision, decisionId: "secret_id" } }, evaluatedAt);
  assertFail(tdUnsafeDecId, "invalid_triage_decision");
  if (JSON.stringify(tdUnsafeDecId).includes("secret_id")) { console.error("FAIL raw echo"); process.exit(1); }
  
  const tdUnsafeRevId = await promoteReviewedEvidenceFindingCandidateDraft({ ...baseReq, triageDecision: { ...validTriageDecision, reviewerId: "secret_id" } }, evaluatedAt);
  assertFail(tdUnsafeRevId, "invalid_triage_decision");
  if (JSON.stringify(tdUnsafeRevId).includes("secret_id")) { console.error("FAIL raw echo"); process.exit(1); }
  
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft({ ...baseReq, triageDecision: { ...validTriageDecision, reviewedAt: "bad" } }, evaluatedAt), "invalid_triage_decision");

  assertBlocked(await promoteReviewedEvidenceFindingCandidateDraft({ ...baseReq, triageDecision: { ...validTriageDecision, decision: "reject_finding_candidate_promotion" } }, evaluatedAt), "triage_decision_rejected");
  assertBlocked(await promoteReviewedEvidenceFindingCandidateDraft({ ...baseReq, triageDecision: { ...validTriageDecision, decision: "needs_more_evidence" } }, evaluatedAt), "triage_needs_more_evidence");
  
  assertBlocked(await promoteReviewedEvidenceFindingCandidateDraft({ ...baseReq, triageDecision: { ...validTriageDecision, attestations: { ...validTriageDecision.attestations, authorizedPromotionToFormalCandidate: false } } }, evaluatedAt), "triage_authorization_missing");

  const tdAttMiss1 = { ...baseReq, triageDecision: { ...validTriageDecision, attestations: { ...validTriageDecision.attestations } } };
  delete (tdAttMiss1.triageDecision.attestations as any).understandsNoExploitabilityClaim;
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft(tdAttMiss1 as any, evaluatedAt), "invalid_triage_decision");

  const tdAttMiss2 = { ...baseReq, triageDecision: { ...validTriageDecision, attestations: { ...validTriageDecision.attestations } } };
  delete (tdAttMiss2.triageDecision.attestations as any).understandsNoRemediationAdvice;
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft(tdAttMiss2 as any, evaluatedAt), "invalid_triage_decision");

  const tdAttExtra = { ...baseReq, triageDecision: { ...validTriageDecision, attestations: { ...validTriageDecision.attestations, extra: true } } };
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft(tdAttExtra as any, evaluatedAt), "invalid_triage_decision");

  const tdAttStr = { ...baseReq, triageDecision: { ...validTriageDecision, attestations: { ...validTriageDecision.attestations, reviewedDraft: "true" } } };
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft(tdAttStr as any, evaluatedAt), "invalid_triage_decision");
  
  const tdNcStr = { ...baseReq, triageDecision: { ...validTriageDecision, explicitNonClaims: { ...validTriageDecision.explicitNonClaims, noPersistence: "true" } } };
  assertFail(await promoteReviewedEvidenceFindingCandidateDraft(tdNcStr as any, evaluatedAt), "invalid_triage_decision");

  const tdNcMiss = { ...baseReq, triageDecision: { ...validTriageDecision, explicitNonClaims: { ...validTriageDecision.explicitNonClaims } } };
  delete (tdNcMiss.triageDecision.explicitNonClaims as any).noRemediationAdvice;
  const tdNcMissRes = await promoteReviewedEvidenceFindingCandidateDraft(tdNcMiss as any, evaluatedAt);
  assertFail(tdNcMissRes, "invalid_triage_decision");
  if ((tdNcMissRes as any).candidate) { console.error("FAIL leaked candidate"); process.exit(1); }

  const tdNcExtra = { ...baseReq, triageDecision: { ...validTriageDecision, explicitNonClaims: { ...validTriageDecision.explicitNonClaims, extraClaim: true } } };
  const tdNcExtraRes = await promoteReviewedEvidenceFindingCandidateDraft(tdNcExtra as any, evaluatedAt);
  assertFail(tdNcExtraRes, "invalid_triage_decision");
  if ((tdNcExtraRes as any).candidate) { console.error("FAIL leaked candidate"); process.exit(1); }

  console.log("[*] Testing Happy Path: Promote Candidate...");
  const res = await promoteReviewedEvidenceFindingCandidateDraft(baseReq, evaluatedAt);
  if (res.status !== "candidate_created" || !res.candidate || res.reasonCode !== "formal_finding_candidate_created") {
    console.error("FAIL: Happy path failed", res);
    process.exit(1);
  }

  const candidate = res.candidate;
  if (!validateReviewedEvidenceFormalFindingCandidate(candidate)) {
    console.error("FAIL: valid candidate failed self-validation");
    process.exit(1);
  }

  console.log("[*] Verifying Candidate Constraints...");
  if (candidate.sourceDraft.draftId !== validDraft.draftId) { console.error("FAIL mismatch"); process.exit(1); }
  if (candidate.evidenceRefs.selectedCount !== 2) { console.error("FAIL mismatch"); process.exit(1); }
  if (candidate.humanTriage.decisionId !== validTriageDecision.decisionId) { console.error("FAIL mismatch"); process.exit(1); }
  if (JSON.stringify(candidate).includes("evidenceType")) { /* string check */ } // observedEvidenceSummary matches

  assert.strictEqual(candidate.sourceDraft.draftId, validDraft.draftId);
  assert.strictEqual(candidate.sourceDraft.sourceSelectionId, validDraft.sourceSelection.selectionId);
  assert.strictEqual(candidate.sourceDraft.selectedCount, validDraft.sourceSelection.selectedCount);
  assert.strictEqual(candidate.sourceDraft.candidateKind, validDraft.draftLabels.candidateKind);
  assert.strictEqual(candidate.sourceDraft.triageState, validDraft.draftTriage.triageState);
  assert.strictEqual(candidate.sourceDraft.confidenceState, validDraft.draftTriage.confidenceState);
  assert.deepEqual(candidate.evidenceRefs.selectedRefs, validDraft.sourceSelection.selectedRefs);
  assert.deepEqual(candidate.observedEvidenceSummary, validDraft.observedEvidenceSummary);
  
  // No raw EvidenceRecord
  if (JSON.stringify(candidate).includes("body") || JSON.stringify(candidate).includes("targetUrl") || JSON.stringify(candidate).includes("request")) {
    console.error("FAIL leaked raw data"); process.exit(1);
  }
  
  // No M50 wrapper
  if (JSON.stringify(candidate).includes("reviewedEvidenceGroup") || JSON.stringify(candidate).includes("reviewedEvidencePromotionResult")) {
    console.error("FAIL leaked wrapper"); process.exit(1);
  }
  
  // No selectedSummaries
  if (JSON.stringify(candidate).includes("selectedSummaries") || JSON.stringify(candidate).includes("safeSummary")) {
    console.error("FAIL leaked selectedSummaries"); process.exit(1);
  }

  // No draft-only payloads
  if (JSON.stringify(candidate).includes('"sourceSelection":') || JSON.stringify(candidate).includes('"draftTriage":') || JSON.stringify(candidate).includes('"draftLabels":')) {
    console.error("FAIL leaked draft-only payloads"); process.exit(1);
  }

  console.log("[*] Testing Formal Candidate Validator (Negative Cases)...");
  
  if (validateReviewedEvidenceFormalFindingCandidate({ ...candidate, extra: true })) { console.error("FAIL allowed extra top key"); process.exit(1); }
  if (validateReviewedEvidenceFormalFindingCandidate({ ...candidate, humanTriage: { ...candidate.humanTriage, extra: true } })) { console.error("FAIL allowed extra nested key"); process.exit(1); }
  if (validateReviewedEvidenceFormalFindingCandidate({ ...candidate, candidateState: { ...candidate.candidateState, extra: true } })) { console.error("FAIL allowed extra nested key"); process.exit(1); }

  const dupRef = { ...candidate, evidenceRefs: { ...candidate.evidenceRefs, selectedRefs: [candidate.evidenceRefs.selectedRefs[0], { ...candidate.evidenceRefs.selectedRefs[1], storeRecordId: candidate.evidenceRefs.selectedRefs[0].storeRecordId }] } };
  if (validateReviewedEvidenceFormalFindingCandidate(dupRef)) { console.error("FAIL allowed duplicate refs"); process.exit(1); }

  const wrongCount = { ...candidate, evidenceRefs: { ...candidate.evidenceRefs, selectedCount: 99 } };
  if (validateReviewedEvidenceFormalFindingCandidate(wrongCount)) { console.error("FAIL allowed wrong count sum"); process.exit(1); }
  
  const invalidTypeCountSum = { ...candidate, observedEvidenceSummary: { ...candidate.observedEvidenceSummary, evidenceTypeCounts: { http_difference: 99 } } };
  if (validateReviewedEvidenceFormalFindingCandidate(invalidTypeCountSum)) { console.error("FAIL allowed invalid type count sum"); process.exit(1); }

  const invalidStrengthCountSum = { ...candidate, observedEvidenceSummary: { ...candidate.observedEvidenceSummary, strengthCounts: { strong: 99 } } };
  if (validateReviewedEvidenceFormalFindingCandidate(invalidStrengthCountSum)) { console.error("FAIL allowed invalid strength count sum"); process.exit(1); }

  const invalidEnum = { ...candidate, observedEvidenceSummary: { ...candidate.observedEvidenceSummary, evidenceTypeCounts: { invalid: 2 } } };
  if (validateReviewedEvidenceFormalFindingCandidate(invalidEnum)) { console.error("FAIL allowed invalid enum key"); process.exit(1); }

  const invalidStrengthEnum = { ...candidate, observedEvidenceSummary: { ...candidate.observedEvidenceSummary, strengthCounts: { invalid: 2 } } };
  if (validateReviewedEvidenceFormalFindingCandidate(invalidStrengthEnum)) { console.error("FAIL allowed invalid strength enum key"); process.exit(1); }
  
  const unsafeRef = { ...candidate, evidenceRefs: { ...candidate.evidenceRefs, selectedRefs: [{ ...candidate.evidenceRefs.selectedRefs[0], storeRecordId: "secret_id" }, candidate.evidenceRefs.selectedRefs[1]] } };
  if (validateReviewedEvidenceFormalFindingCandidate(unsafeRef)) { console.error("FAIL allowed unsafe ref"); process.exit(1); }

  const invalidTime = { ...candidate, observedEvidenceSummary: { ...candidate.observedEvidenceSummary, collectedAtRange: { earliest: "2026-10-10T12:00:00.000Z", latest: "2020-10-10T12:00:00.000Z" } } };
  if (validateReviewedEvidenceFormalFindingCandidate(invalidTime)) { console.error("FAIL allowed invalid timestamp range"); process.exit(1); }
  
  const invalidSavedAt = { ...candidate, observedEvidenceSummary: { ...candidate.observedEvidenceSummary, savedAtRange: { earliest: "2026-10-10T12:00:00.000Z", latest: "2020-10-10T12:00:00.000Z" } } };
  if (validateReviewedEvidenceFormalFindingCandidate(invalidSavedAt)) { console.error("FAIL allowed invalid savedAtRange"); process.exit(1); }
  
  const strBool = { ...candidate, explicitNonClaims: { ...candidate.explicitNonClaims, noPersistence: "true" } };
  if (validateReviewedEvidenceFormalFindingCandidate(strBool)) { console.error("FAIL allowed string boolean"); process.exit(1); }

  const createsTrue1 = { ...candidate, classification: { ...candidate.classification, createsConfirmedFinding: true } };
  if (validateReviewedEvidenceFormalFindingCandidate(createsTrue1)) { console.error("FAIL allowed createsConfirmedFinding"); process.exit(1); }
  const createsTrue2 = { ...candidate, classification: { ...candidate.classification, confirmsVulnerabilities: true } };
  if (validateReviewedEvidenceFormalFindingCandidate(createsTrue2)) { console.error("FAIL allowed confirmsVulnerabilities"); process.exit(1); }
  const createsTrue3 = { ...candidate, classification: { ...candidate.classification, makesSeverityClaims: true } };
  if (validateReviewedEvidenceFormalFindingCandidate(createsTrue3)) { console.error("FAIL allowed makesSeverityClaims"); process.exit(1); }
  const createsTrue4 = { ...candidate, classification: { ...candidate.classification, makesRiskClaims: true } };
  if (validateReviewedEvidenceFormalFindingCandidate(createsTrue4)) { console.error("FAIL allowed makesRiskClaims"); process.exit(1); }
  const createsTrue5 = { ...candidate, classification: { ...candidate.classification, makesImpactClaims: true } };
  if (validateReviewedEvidenceFormalFindingCandidate(createsTrue5)) { console.error("FAIL allowed makesImpactClaims"); process.exit(1); }
  const createsTrue6 = { ...candidate, classification: { ...candidate.classification, providesRemediationAdvice: true } };
  if (validateReviewedEvidenceFormalFindingCandidate(createsTrue6)) { console.error("FAIL allowed providesRemediationAdvice"); process.exit(1); }
  const createsTrue7 = { ...candidate, classification: { ...candidate.classification, makesExploitabilityClaims: true } };
  if (validateReviewedEvidenceFormalFindingCandidate(createsTrue7)) { console.error("FAIL allowed makesExploitabilityClaims"); process.exit(1); }

  console.log("[*] Testing Non-Created Outcomes...");
  const resFail = await promoteReviewedEvidenceFindingCandidateDraft({ ...baseReq, candidateId: "secret_id" }, evaluatedAt);
  if (resFail.candidate || (resFail.classification as any).createsFormalFindingCandidate !== false) {
    console.error("FAIL non-created outcome leaked candidate or claims"); process.exit(1);
  }

  console.log("[*] Testing Summary Read Model...");
  const sumReq = {
    contractVersion: "fixguard-reviewed-evidence-finding-candidate-promotion/v0",
    kind: "summarize_reviewed_evidence_formal_finding_candidate_request",
    summaryId: "summary_1",
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
  };

  const sumRes = await summarizeReviewedEvidenceFormalFindingCandidate(sumReq, evaluatedAt);
  if (sumRes.status !== "summarized" || !sumRes.summary || sumRes.reasonCode !== "formal_finding_candidate_summary_created") {
    console.error("FAIL summary", sumRes); process.exit(1);
  }
  
  if (sumRes.summary.candidateId !== candidate.candidateId) { console.error("FAIL summary content"); process.exit(1); }
  
  assert.deepEqual(
    Object.keys(sumRes.summary).sort(),
    [
      "candidateId",
      "confirmationState",
      "createdAt",
      "evidenceTypeCounts",
      "indicatorIds",
      "lifecycleState",
      "persistenceState",
      "reportState",
      "scanId",
      "selectedCount",
      "sourceDraftId",
      "sourceSelectionId",
      "strengthCounts",
    ].sort(),
  );

  assert.strictEqual(sumRes.summary.candidateId, candidate.candidateId);
  assert.strictEqual(sumRes.summary.scanId, candidate.scanId);
  assert.strictEqual(sumRes.summary.sourceDraftId, candidate.sourceDraft.draftId);
  assert.strictEqual(sumRes.summary.sourceSelectionId, candidate.sourceDraft.sourceSelectionId);
  assert.strictEqual(sumRes.summary.selectedCount, candidate.evidenceRefs.selectedCount);
  assert.strictEqual(sumRes.summary.lifecycleState, candidate.candidateState.lifecycleState);
  assert.strictEqual(sumRes.summary.confirmationState, candidate.candidateState.confirmationState);
  assert.strictEqual(sumRes.summary.reportState, candidate.candidateState.reportState);
  assert.strictEqual(sumRes.summary.persistenceState, candidate.candidateState.persistenceState);
  assert.deepEqual(sumRes.summary.evidenceTypeCounts, candidate.observedEvidenceSummary.evidenceTypeCounts);
  assert.deepEqual(sumRes.summary.strengthCounts, candidate.observedEvidenceSummary.strengthCounts);
  assert.deepEqual(sumRes.summary.indicatorIds, candidate.observedEvidenceSummary.indicatorIds);
  assert.strictEqual(sumRes.summary.createdAt, candidate.createdAt);

  const summaryStr = JSON.stringify(sumRes.summary);
  if (summaryStr.includes('"candidate":')) { console.error("FAIL leaked candidate object"); process.exit(1); }
  if (summaryStr.includes('"draft":')) { console.error("FAIL leaked draft"); process.exit(1); }
  if (summaryStr.includes('"sourceSelection":')) { console.error("FAIL leaked sourceSelection"); process.exit(1); }
  if (summaryStr.includes('"selectedRefs":')) { console.error("FAIL leaked selectedRefs"); process.exit(1); }
  if (summaryStr.includes('"selectedSummaries":')) { console.error("FAIL leaked selectedSummaries"); process.exit(1); }
  if (summaryStr.includes('"observedEvidenceSummary":')) { console.error("FAIL leaked observedEvidenceSummary"); process.exit(1); }
  if (summaryStr.includes('"humanTriage":')) { console.error("FAIL leaked humanTriage"); process.exit(1); }
  if (summaryStr.includes('"classification":')) { console.error("FAIL leaked classification"); process.exit(1); }
  if (summaryStr.includes('"storage":')) { console.error("FAIL leaked storage"); process.exit(1); }
  if (summaryStr.includes('"explicitNonClaims":')) { console.error("FAIL leaked explicitNonClaims"); process.exit(1); }
  if (summaryStr.includes('"title":') || summaryStr.includes('"description":') || summaryStr.includes('"narrative":') || summaryStr.includes('"rationale":') || summaryStr.includes('"remediation":') || summaryStr.includes('"recommendation":')) {
    console.error("FAIL leaked forbidden claims"); process.exit(1);
  }

  const sumFail1 = await summarizeReviewedEvidenceFormalFindingCandidate({ ...sumReq, candidate: wrongCount }, evaluatedAt);
  if (sumFail1.reasonCode !== "candidate_validation_failed") { console.error("FAIL summary validator"); process.exit(1); }

  const sumFail2 = await summarizeReviewedEvidenceFormalFindingCandidate({ ...sumReq, scanId: "different" }, evaluatedAt);
  if (sumFail2.reasonCode !== "source_scan_mismatch") { console.error("FAIL summary scan mismatch"); process.exit(1); }

  const sumFail3 = await summarizeReviewedEvidenceFormalFindingCandidate({ ...sumReq, extra: 1 }, evaluatedAt);
  if (sumFail3.reasonCode !== "invalid_candidate_summary_request") { console.error("FAIL summary request validation"); process.exit(1); }

  const sumFail4 = await summarizeReviewedEvidenceFormalFindingCandidate({ ...sumReq, summaryId: "secret_id" }, evaluatedAt);
  if (sumFail4.reasonCode !== "invalid_candidate_summary_metadata") { console.error("FAIL summary request metadata validation"); process.exit(1); }
  if (JSON.stringify(sumFail4).includes("secret_id")) { console.error("FAIL summary raw echo"); process.exit(1); }

  const sumFail5 = await summarizeReviewedEvidenceFormalFindingCandidate({ ...sumReq, requestedAt: "bad_time" }, evaluatedAt);
  if (sumFail5.reasonCode !== "invalid_candidate_summary_metadata") { console.error("FAIL summary invalid requestedAt"); process.exit(1); }
  if (JSON.stringify(sumFail5).includes("bad_time")) { console.error("FAIL raw echo"); process.exit(1); }

  const sumFail6 = await summarizeReviewedEvidenceFormalFindingCandidate(sumReq, "bad_time");
  if (sumFail6.reasonCode !== "invalid_candidate_summary_metadata") { console.error("FAIL summary invalid evaluatedAt"); process.exit(1); }
  if (JSON.stringify(sumFail6).includes("bad_time")) { console.error("FAIL raw echo"); process.exit(1); }
  if (!JSON.stringify(sumFail6).includes("TIMESTAMP_REDACTED")) { console.error("FAIL missing redacted sentinel"); process.exit(1); }

  const sumClassReq1 = { ...sumReq, classification: { ...sumReq.classification, makesRiskClaims: true } };
  const sumFail7 = await summarizeReviewedEvidenceFormalFindingCandidate(sumClassReq1 as any, evaluatedAt);
  if (sumFail7.reasonCode !== "invalid_candidate_summary_metadata") { console.error("FAIL summary true classification"); process.exit(1); }

  const sumClassReq2 = { ...sumReq, classification: { ...sumReq.classification, extra: true } };
  const sumFail8 = await summarizeReviewedEvidenceFormalFindingCandidate(sumClassReq2 as any, evaluatedAt);
  if (sumFail8.reasonCode !== "invalid_candidate_summary_metadata") { console.error("FAIL summary extra classification"); process.exit(1); }

  const sumClassReq3 = { ...sumReq, classification: { ...sumReq.classification } };
  delete (sumClassReq3.classification as any).makesRiskClaims;
  const sumFail9 = await summarizeReviewedEvidenceFormalFindingCandidate(sumClassReq3 as any, evaluatedAt);
  if (sumFail9.reasonCode !== "invalid_candidate_summary_metadata") { console.error("FAIL summary missing classification"); process.exit(1); }

  const sumClassReq4 = { ...sumReq, classification: { ...sumReq.classification, makesRiskClaims: "false" } };
  const sumFail10 = await summarizeReviewedEvidenceFormalFindingCandidate(sumClassReq4 as any, evaluatedAt);
  if (sumFail10.reasonCode !== "invalid_candidate_summary_metadata") { console.error("FAIL summary string bool classification"); process.exit(1); }

  console.log("--- V2 M54 Smoke Test Completed Successfully ---");
}

runSmokeTest().catch(console.error);
