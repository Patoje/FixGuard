import { evaluateHumanReviewedEvidencePromotion } from "../evidence-review/HumanReviewedEvidencePromotionService.js";

const safeClass = {
  createsNonPersistedEvidenceRecord: false,
  createsPersistedEvidence: false,
  createsFindingCandidate: false,
  createsSafeReportItem: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetwork: false,
  executesTools: false,
  persistsData: false,
};

const fullM49NonClaims = {
  noConfirmedVulnerability: true,
  noFindingCreated: true,
  noFindingCandidateCreated: true,
  noPersistedEvidenceCreated: true,
  noSeverityRiskOrImpactClaim: true,
  noExternalReportCreated: true,
  noRawSensitiveDataIncluded: true,
  noNetworkExecution: true,
  noToolExecution: true
};

const fullM49Class = {
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetwork: false,
  executesTools: false,
  persistsData: false
};

const baseRequest: any = {
  contractVersion: "fixguard-human-reviewed-evidence-promotion/v0",
  kind: "human_reviewed_evidence_promotion_request",
  promotionId: "prm_12345",
  scanId: "scn_999",
  requestedAt: "2026-07-01T12:00:00.000Z",
  sourceIndicatorRef: {
    kind: "reviewed_indicator_reference",
    indicatorId: "ind_test1",
    scanId: "scn_999"
  },
  reviewDecision: {
    decision: "approve_evidence",
    reviewerId: "usr_111",
    reviewedAt: "2026-07-01T12:01:00.000Z"
  },
  classification: safeClass,
  validationResult: {
    contractVersion: "fixguard-authorized-comparison-validation/v0",
    kind: "authorized_comparison_validation_result",
    validationId: "val_ok",
    scanId: "scn_999",
    status: "completed",
    reasonCode: "completed_with_evidence_draft",
    classification: fullM49Class,
    explicitNonClaims: fullM49NonClaims,
    evidenceDraft: {
      draftKind: "non_persisted_comparison_evidence_draft",
      draftId: "drf_123",
      sourceComparisonId: "cmp_456",
      suggestedEvidenceType: "http_difference",
      suggestedStrength: "moderate",
      requiresHumanReview: true,
      notPersisted: true,
      notARealFinding: true,
      notConfirmedEvidence: true,
      notForExternalDelivery: true,
      notM45EvidenceRecord: true,
      safeRationale: "safe",
      sourceSnapshotIds: {
        baselineSnapshotId: "bsl_123",
        validationSnapshotId: "val_456"
      }
    }
  }
};

function runTest(name: string, overridesOrReq: any, expectStatus: string, expectReasonCode?: string, expectRecord?: boolean, evalAt?: string) {
  const req = overridesOrReq.contractVersion ? overridesOrReq : { ...baseRequest, ...overridesOrReq };
  const res = evaluateHumanReviewedEvidencePromotion(req, evalAt ?? "2026-07-01T12:02:00.000Z");
  if (res.status !== expectStatus) {
    console.error(`FAIL: ${name}. Expected status ${expectStatus}, got ${res.status} (${res.reasonCode})`);
    process.exit(1);
  }
  if (expectReasonCode && res.reasonCode !== expectReasonCode) {
    console.error(`FAIL: ${name}. Expected reasonCode ${expectReasonCode}, got ${res.reasonCode}`);
    process.exit(1);
  }
  if (expectRecord === true && !res.nonPersistedEvidenceRecord) {
    console.error(`FAIL: ${name}. Expected record but got none.`);
    process.exit(1);
  }
  if (expectRecord === false && res.nonPersistedEvidenceRecord) {
    console.error(`FAIL: ${name}. Expected NO record but got one.`);
    process.exit(1);
  }
  console.log(`PASS: ${name}`);
}

function runSmoke() {
  console.log("=== M50 Extended Smoke Test ===");

  runTest("happy path approve_evidence -> promoted + nonPersistedEvidenceRecord present", {}, "promoted", "promoted_to_non_persisted_evidence_record", true);

  // 5.1 Invalid evaluatedAt tests
  runTest("invalid evaluatedAt: 2026-07-01Tnot-valid -> failed", {}, "failed", "invalid_promotion_metadata", false, "2026-07-01Tnot-valid");
  runTest("invalid evaluatedAt: 2026-07-01 -> failed", {}, "failed", "invalid_promotion_metadata", false, "2026-07-01");
  runTest("invalid evaluatedAt: not-a-date -> failed", {}, "failed", "invalid_promotion_metadata", false, "not-a-date");

  runTest("reject -> rejected + no evidence record", { reviewDecision: { ...baseRequest.reviewDecision, decision: "reject" } }, "rejected", "rejected_by_human_review", false);

  runTest("needs_more_review -> needs_more_review + no evidence record", { reviewDecision: { ...baseRequest.reviewDecision, decision: "needs_more_review" } }, "needs_more_review", "human_review_requested_more_review", false);

  // Missing review decision
  const reqMissingRev = { ...baseRequest };
  delete reqMissingRev.reviewDecision;
  runTest("missing reviewDecision -> failed", reqMissingRev, "failed", "human_review_required", false);

  runTest("invalid review decision -> failed", { reviewDecision: { ...baseRequest.reviewDecision, decision: "invalid" } }, "failed", "invalid_promotion_request", false);

  runTest("safeReviewNote extra field -> failed, no record", { safeReviewNote: "hello" }, "failed", "invalid_promotion_request", false);

  runTest("extraTopLevel -> failed, no record", { extraTopLevel: "hello" }, "failed", "invalid_promotion_request", false);

  // Unsafe reviewerId tests
  runTest("unsafe reviewerId: secret -> failed", { reviewDecision: { ...baseRequest.reviewDecision, reviewerId: "secret_123" } }, "failed", "invalid_promotion_metadata", false);
  runTest("unsafe reviewerId: vulnerable -> failed", { reviewDecision: { ...baseRequest.reviewDecision, reviewerId: "vulnerable_usr" } }, "failed", "invalid_promotion_metadata", false);
  runTest("unsafe reviewerId: user with spaces -> failed", { reviewDecision: { ...baseRequest.reviewDecision, reviewerId: "user with spaces" } }, "failed", "invalid_promotion_metadata", false);
  runTest("unsafe reviewerId: user/123 -> failed", { reviewDecision: { ...baseRequest.reviewDecision, reviewerId: "user/123" } }, "failed", "invalid_promotion_metadata", false);
  runTest("unsafe reviewerId: user.name -> failed", { reviewDecision: { ...baseRequest.reviewDecision, reviewerId: "user.name" } }, "failed", "invalid_promotion_metadata", false);
  runTest("unsafe reviewerId: overlong -> failed", { reviewDecision: { ...baseRequest.reviewDecision, reviewerId: "a".repeat(100) } }, "failed", "invalid_promotion_metadata", false);

  // Invalid reviewedAt
  runTest("invalid reviewedAt: 2026-07-01Tnot-valid", { reviewDecision: { ...baseRequest.reviewDecision, reviewedAt: "2026-07-01Tnot-valid" } }, "failed", "invalid_promotion_metadata", false);
  runTest("invalid reviewedAt: missing", { reviewDecision: { ...baseRequest.reviewDecision, reviewedAt: undefined } }, "failed", "invalid_promotion_metadata", false);

  // Missing sourceIndicatorRef
  const reqMissingInd = { ...baseRequest };
  delete reqMissingInd.sourceIndicatorRef;
  runTest("missing sourceIndicatorRef -> blocked", reqMissingInd, "blocked", "source_indicator_ref_missing", false);

  runTest("unsafe sourceIndicatorRef.indicatorId -> failed", { sourceIndicatorRef: { ...baseRequest.sourceIndicatorRef, indicatorId: "token_abc" } }, "failed", "invalid_promotion_metadata", false);

  // 5.3 unsafe sourceIndicatorRef.indicatorId
  runTest("indicatorId: id with spaces -> failed", { sourceIndicatorRef: { ...baseRequest.sourceIndicatorRef, indicatorId: "id with spaces" } }, "failed", "invalid_promotion_metadata", false);
  runTest("indicatorId: ind_secret_token -> failed", { sourceIndicatorRef: { ...baseRequest.sourceIndicatorRef, indicatorId: "ind_secret_token" } }, "failed", "invalid_promotion_metadata", false);
  runTest("indicatorId: authorization_difference -> failed", { sourceIndicatorRef: { ...baseRequest.sourceIndicatorRef, indicatorId: "authorization_difference" } }, "failed", "invalid_promotion_metadata", false);
  runTest("indicatorId: vulnerable -> failed", { sourceIndicatorRef: { ...baseRequest.sourceIndicatorRef, indicatorId: "vulnerable" } }, "failed", "invalid_promotion_metadata", false);
  runTest("indicatorId: exploit -> failed", { sourceIndicatorRef: { ...baseRequest.sourceIndicatorRef, indicatorId: "exploit" } }, "failed", "invalid_promotion_metadata", false);

  runTest("sourceIndicatorRef.scanId mismatch -> blocked", { sourceIndicatorRef: { ...baseRequest.sourceIndicatorRef, scanId: "wrong" } }, "blocked", "source_scan_mismatch", false);
  
  runTest("validationResult.scanId mismatch -> blocked", { validationResult: { ...baseRequest.validationResult, scanId: "wrong" } }, "blocked", "source_scan_mismatch", false);

  runTest("approve_evidence with M49 status blocked -> blocked", { validationResult: { ...baseRequest.validationResult, status: "blocked" } }, "blocked", "source_validation_not_completed", false);
  
  runTest("approve_evidence with M49 completed but wrong reason -> blocked", { validationResult: { ...baseRequest.validationResult, reasonCode: "blocked_scope_denied" } }, "blocked", "source_validation_not_evidence_ready", false);
  
  runTest("approve_evidence with M49 completed but no draft -> blocked", { validationResult: { ...baseRequest.validationResult, evidenceDraft: undefined } }, "blocked", "source_evidence_draft_missing", false);

  runTest("approve_evidence with M49 draft invalid suggestedStrength info -> blocked", { validationResult: { ...baseRequest.validationResult, evidenceDraft: { ...baseRequest.validationResult.evidenceDraft, suggestedStrength: "info" } } }, "blocked", "source_evidence_draft_invalid", false);
  
  runTest("approve_evidence with M49 draft invalid sourceSnapshotIds extra -> blocked", { validationResult: { ...baseRequest.validationResult, evidenceDraft: { ...baseRequest.validationResult.evidenceDraft, sourceSnapshotIds: { ...baseRequest.validationResult.evidenceDraft.sourceSnapshotIds, extra: "foo" } } } }, "blocked", "source_evidence_draft_invalid", false);
  
  runTest("approve_evidence with M49 draft sourceSnapshotIds array -> blocked", { validationResult: { ...baseRequest.validationResult, evidenceDraft: { ...baseRequest.validationResult.evidenceDraft, sourceSnapshotIds: ["a", "b"] } } }, "blocked", "source_evidence_draft_invalid", false);

  const missingClassVal = { ...baseRequest.validationResult };
  delete missingClassVal.classification;
  runTest("approve_evidence with M49 classification missing -> blocked", { validationResult: missingClassVal }, "blocked", "blocked_policy_not_review_safe", false);

  runTest("approve_evidence with M49 classification makesRiskClaims true -> blocked", { validationResult: { ...baseRequest.validationResult, classification: { ...fullM49Class, makesRiskClaims: true } } }, "blocked", "blocked_policy_not_review_safe", false);

  runTest("approve_evidence with M49 classification extra key -> blocked", { validationResult: { ...baseRequest.validationResult, classification: { ...fullM49Class, extra: false } } }, "blocked", "blocked_policy_not_review_safe", false);
  
  runTest("approve_evidence with M49 classification string false -> blocked", { validationResult: { ...baseRequest.validationResult, classification: { ...fullM49Class, makesRiskClaims: "false" } } }, "blocked", "blocked_policy_not_review_safe", false);

  const missingNonClaimsVal = { ...baseRequest.validationResult };
  delete missingNonClaimsVal.explicitNonClaims;
  runTest("approve_evidence with M49 explicitNonClaims missing -> blocked", { validationResult: missingNonClaimsVal }, "blocked", "blocked_policy_not_review_safe", false);

  runTest("approve_evidence with M49 explicitNonClaims partial -> blocked", { validationResult: { ...baseRequest.validationResult, explicitNonClaims: { noConfirmedVulnerability: true } } }, "blocked", "blocked_policy_not_review_safe", false);

  runTest("approve_evidence with M49 explicitNonClaims false -> blocked", { validationResult: { ...baseRequest.validationResult, explicitNonClaims: { ...fullM49NonClaims, noConfirmedVulnerability: false } } }, "blocked", "blocked_policy_not_review_safe", false);

  runTest("approve_evidence with M49 explicitNonClaims string true -> blocked", { validationResult: { ...baseRequest.validationResult, explicitNonClaims: { ...fullM49NonClaims, noConfirmedVulnerability: "true" } } }, "blocked", "blocked_policy_not_review_safe", false);

  runTest("approve_evidence with M49 explicitNonClaims extra key -> blocked", { validationResult: { ...baseRequest.validationResult, explicitNonClaims: { ...fullM49NonClaims, extra: true } } }, "blocked", "blocked_policy_not_review_safe", false);

  runTest("unsafe promotionId (token) -> failed", { promotionId: "token_123" }, "failed", "invalid_promotion_metadata", false);
  runTest("unsafe promotionId (spaces) -> failed", { promotionId: "bad id" }, "failed", "invalid_promotion_metadata", false);
  runTest("unsafe promotionId (slash) -> failed", { promotionId: "bad/id" }, "failed", "invalid_promotion_metadata", false);
  runTest("unsafe promotionId (dot) -> failed", { promotionId: "bad.id" }, "failed", "invalid_promotion_metadata", false);
  runTest("unsafe promotionId (overlong) -> failed", { promotionId: "a".repeat(100) }, "failed", "invalid_promotion_metadata", false);

  runTest("unsafe scanId (secret) -> failed", { scanId: "secret_123" }, "failed", "invalid_promotion_metadata", false);
  runTest("unsafe scanId (spaces) -> failed", { scanId: "bad id" }, "failed", "invalid_promotion_metadata", false);
  runTest("unsafe scanId (slash) -> failed", { scanId: "bad/id" }, "failed", "invalid_promotion_metadata", false);
  runTest("unsafe scanId (dot) -> failed", { scanId: "bad.id" }, "failed", "invalid_promotion_metadata", false);
  runTest("unsafe scanId (overlong) -> failed", { scanId: "a".repeat(100) }, "failed", "invalid_promotion_metadata", false);

  const reqMissingClass = { ...baseRequest };
  delete reqMissingClass.classification;
  runTest("request classification missing -> failed", reqMissingClass, "failed", "invalid_promotion_request", false);

  runTest("request classification extra -> failed", { classification: { ...safeClass, extra: false } }, "failed", "invalid_promotion_request", false);
  
  runTest("request classification string false -> failed", { classification: { ...safeClass, createsNonPersistedEvidenceRecord: "false" } }, "failed", "invalid_promotion_request", false);

  // 5.2 unsafe-but-not-forbidden validation IDs in sourceValidationSummary
  const rValSpaces = evaluateHumanReviewedEvidencePromotion({ ...baseRequest, validationResult: { ...baseRequest.validationResult, validationId: "val with spaces" } }, "2026-07-01T12:02:00.000Z");
  if (rValSpaces.sourceValidationSummary?.validationId !== "VALIDATION_ID_REDACTED") {
    console.error("FAIL: val with spaces should be REDACTED in summary");
    process.exit(1);
  }
  if (JSON.stringify(rValSpaces).includes("val with spaces")) {
    console.error("FAIL: val with spaces echoed in result");
    process.exit(1);
  }
  
  const rValSecret = evaluateHumanReviewedEvidencePromotion({ ...baseRequest, validationResult: { ...baseRequest.validationResult, validationId: "val_secret_token" } }, "2026-07-01T12:02:00.000Z");
  if (rValSecret.sourceValidationSummary?.validationId !== "VALIDATION_ID_REDACTED") {
    console.error("FAIL: val_secret_token should be REDACTED in summary");
    process.exit(1);
  }
  if (JSON.stringify(rValSecret).includes("val_secret_token")) {
    console.error("FAIL: val_secret_token echoed in result");
    process.exit(1);
  }

  // EvidenceRecord validation failed hook
  // We need to bypass the isStrictSafeId on indicatorId at the boundary to test validateEvidenceRecord.
  // Wait, if it fails at the boundary, we can't test EvidenceRecord construction failure on indicatorId here.
  // Let's use an invalid evidenceType to trigger M49 rejection, which is the closest we can get to testing draft construction failure.
  runTest("constructed EvidenceRecord invalid -> blocked (caught at M49)", { validationResult: { ...baseRequest.validationResult, evidenceDraft: { ...baseRequest.validationResult.evidenceDraft, suggestedEvidenceType: "invalid_type" } } }, "blocked", "source_evidence_draft_invalid", false);

  // Check result flags on success vs fail
  const rHappy = evaluateHumanReviewedEvidencePromotion(baseRequest, "2026-07-01T12:02:00.000Z");
  if (!rHappy.classification.createsNonPersistedEvidenceRecord) {
    console.error("FAIL: result classification createsNonPersistedEvidenceRecord should be true when promoted");
    process.exit(1);
  }
  
  const rFail = evaluateHumanReviewedEvidencePromotion(reqMissingClass, "2026-07-01T12:02:00.000Z");
  if (rFail.classification.createsNonPersistedEvidenceRecord) {
    console.error("FAIL: result classification createsNonPersistedEvidenceRecord should be false when failed");
    process.exit(1);
  }

  console.log("=== M50 Extended Smoke Test PASS ===");
}

runSmoke();
