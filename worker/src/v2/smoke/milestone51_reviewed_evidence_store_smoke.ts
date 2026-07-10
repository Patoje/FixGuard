import { saveReviewedEvidence } from "../evidence-store/ReviewedEvidenceStoreService.js";
import { getReviewedEvidence, listReviewedEvidence } from "../evidence-store/ReviewedEvidenceReadModel.js";
import { InMemoryReviewedEvidenceStoreRepository } from "../evidence-store/InMemoryReviewedEvidenceStoreRepository.js";
import type { SaveReviewedEvidenceRequest, GetReviewedEvidenceRequest, ListReviewedEvidenceRequest } from "../evidence-store/ReviewedEvidenceStoreContracts.js";
import type { HumanReviewedEvidencePromotionResult } from "../evidence-review/HumanReviewedEvidencePromotionContracts.js";

async function runSmoke() {
  console.log("--- M51 DB-Free Reviewed Evidence Store + Read Model Boundary DB-free Smoke Test ---");

  const repo = new InMemoryReviewedEvidenceStoreRepository();
  const repo2 = new InMemoryReviewedEvidenceStoreRepository(); // secondary repo for failure isolation tests

  const safeSaveId = "save_" + Date.now();
  const safeScanId = "scan_" + Date.now();
  const evaluatedAt = new Date().toISOString();

  const validEvidenceRecord = {
    contractVersion: "fixguard-evidence-boundary/v0" as const,
    kind: "evidence_record" as const,
    evidenceId: "evidence_abc123",
    scanId: safeScanId,
    indicatorId: "ind_456",
    collectedAt: evaluatedAt,
    collectedBy: "response_comparator" as any,
    evidenceType: "authorization_difference" as any,
    strength: "strong" as any,
    redaction: {
      isRedacted: true,
      redactionMethod: "none"
    },
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false
    }
  };

  const validPromotionResult: HumanReviewedEvidencePromotionResult = {
    contractVersion: "fixguard-human-reviewed-evidence-promotion/v0",
    kind: "human_reviewed_evidence_promotion_result",
    promotionId: "promo_123",
    scanId: safeScanId,
    evaluatedAt: evaluatedAt,
    status: "promoted",
    reasonCode: "promoted_to_non_persisted_evidence_record",
    nonPersistedEvidenceRecord: validEvidenceRecord as any,
    reviewSummary: { decision: "approve_evidence", reviewerId: "rev_99", reviewedAt: evaluatedAt },
    sourceValidationSummary: { validationId: "val_22", status: "completed", reasonCode: "completed_with_evidence_draft", evidenceDraftPresent: true },
    explicitNonClaims: {
      noConfirmedVulnerability: true,
      noFindingCreated: true,
      noFindingCandidateCreated: true,
      noSafeReportItemCreated: true,
      noExternalReportCreated: true,
      noSeverityRiskOrImpactClaim: true,
      noPersistence: true,
      noNetworkExecution: true,
      noToolExecution: true
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
  };

  const safeClassStoreReq = {
    storesReviewedEvidenceRecord: false as const,
    storesInMemoryOnly: false as const,
    persistsToDatabase: false as const,
    createsFindingCandidate: false as const,
    createsSafeReportItem: false as const,
    confirmsVulnerabilities: false as const,
    makesRiskClaims: false as const,
    makesSeverityClaims: false as const,
    makesImpactClaims: false as const,
    executesNetwork: false as const,
    executesTools: false as const
  };

  const saveReq: SaveReviewedEvidenceRequest = {
    contractVersion: "fixguard-reviewed-evidence-store/v0",
    kind: "save_reviewed_evidence_request",
    saveId: safeSaveId,
    scanId: safeScanId,
    requestedAt: evaluatedAt,
    promotionResult: validPromotionResult,
    classification: safeClassStoreReq
  };

  // 1. Test happy path save
  const resSave = await saveReviewedEvidence(saveReq, evaluatedAt, repo);
  if (resSave.status !== "saved" || !resSave.record || !resSave.summary) {
    console.error("FAIL: Happy path save failed", resSave);
    process.exit(1);
  }
  if (resSave.record.storeRecordId !== safeSaveId || resSave.record.savedAt !== evaluatedAt) {
    console.error("FAIL: Store record ID or savedAt mismatch");
    process.exit(1);
  }
  if (!resSave.classification.storesReviewedEvidenceRecord || !resSave.classification.storesInMemoryOnly) {
    console.error("FAIL: Result classification not correctly set on save success");
    process.exit(1);
  }
  console.log("[+] Happy path save successful.");

  // 2. Test Get by Store Record ID
  const getReq1: GetReviewedEvidenceRequest = {
    contractVersion: "fixguard-reviewed-evidence-store/v0",
    kind: "get_reviewed_evidence_request",
    readId: "read_1",
    scanId: safeScanId,
    requestedAt: evaluatedAt,
    lookup: { by: "storeRecordId", storeRecordId: safeSaveId },
    classification: safeClassStoreReq
  };
  const getRes1 = await getReviewedEvidence(getReq1, evaluatedAt, repo);
  if (getRes1.status !== "found" || getRes1.record?.storeRecordId !== safeSaveId) {
    console.error("FAIL: Get by storeRecordId failed", getRes1);
    process.exit(1);
  }
  console.log("[+] Get by storeRecordId successful.");

  // 3. Test Get by Evidence ID
  const getReq2: GetReviewedEvidenceRequest = {
    contractVersion: "fixguard-reviewed-evidence-store/v0",
    kind: "get_reviewed_evidence_request",
    readId: "read_2",
    scanId: safeScanId,
    requestedAt: evaluatedAt,
    lookup: { by: "evidenceId", evidenceId: "evidence_abc123" },
    classification: safeClassStoreReq
  };
  const getRes2 = await getReviewedEvidence(getReq2, evaluatedAt, repo);
  if (getRes2.status !== "found" || getRes2.record?.evidenceRecord.evidenceId !== "evidence_abc123") {
    console.error("FAIL: Get by evidenceId failed", getRes2);
    process.exit(1);
  }
  console.log("[+] Get by evidenceId successful.");

  // 4. Test list and deterministic sort
  // Add a second record
  const saveReq2: SaveReviewedEvidenceRequest = {
    ...saveReq,
    saveId: "save_2_earlier",
    promotionResult: {
      ...validPromotionResult,
      nonPersistedEvidenceRecord: {
        ...validEvidenceRecord,
        evidenceId: "evidence_def456"
      } as any
    }
  };
  const earlyEval = new Date(Date.now() - 10000).toISOString();
  await saveReviewedEvidence(saveReq2, earlyEval, repo);

  const listReq: ListReviewedEvidenceRequest = {
    contractVersion: "fixguard-reviewed-evidence-store/v0",
    kind: "list_reviewed_evidence_request",
    listId: "list_1",
    scanId: safeScanId,
    requestedAt: evaluatedAt,
    classification: safeClassStoreReq
  };
  const listRes = await listReviewedEvidence(listReq, evaluatedAt, repo);
  if (listRes.status !== "listed" || listRes.summaries.length !== 2) {
    console.error("FAIL: List failed or incorrect count", listRes);
    process.exit(1);
  }
  if (listRes.summaries[0].storeRecordId !== safeSaveId) {
    console.error("FAIL: List deterministic ordering savedAt DESC failed", listRes.summaries);
    process.exit(1);
  }
  console.log("[+] List works with summaries only, sorted by savedAt DESC.");

  // Test limit cap and non-integer
  const listReqLimitBad: ListReviewedEvidenceRequest = {
    ...listReq,
    options: { limit: -5 }
  };
  const listResBad = await listReviewedEvidence(listReqLimitBad, evaluatedAt, repo);
  if (listResBad.status !== "failed" || listResBad.reasonCode !== "invalid_list_metadata") {
    console.error("FAIL: List did not reject negative limit safely", listResBad);
    process.exit(1);
  }
  console.log("[+] List safely rejects invalid limits.");

  const listReqLimitCap: ListReviewedEvidenceRequest = {
    ...listReq,
    options: { limit: 150 } // should cap at 100
  };
  const listResCap = await listReviewedEvidence(listReqLimitCap, evaluatedAt, repo);
  if (listResCap.status !== "listed") {
    console.error("FAIL: List failed when over max limit", listResCap);
    process.exit(1);
  }

  // 5. Duplicate test
  const dupSave = await saveReviewedEvidence(saveReq, evaluatedAt, repo);
  if (dupSave.status !== "duplicate" || dupSave.reasonCode !== "duplicate_reviewed_evidence_record") {
    console.error("FAIL: Duplicate saveId did not fail correctly", dupSave);
    process.exit(1);
  }
  console.log("[+] Duplicate storeRecordId safely handled.");

  // 6. Mutation test
  if (getRes1.record) {
    getRes1.record.storeRecordId = "mutated_id";
  }
  const checkMutation = await getReviewedEvidence(getReq1, evaluatedAt, repo);
  if (checkMutation.record?.storeRecordId === "mutated_id") {
    console.error("FAIL: Repository leaked reference, mutating result mutated repo!");
    process.exit(1);
  }
  console.log("[+] Repository is mutation-safe (clones on get).");

  // 7. Test M50 failures blocked
  const badPromo = { ...validPromotionResult, status: "blocked" as any, reasonCode: "human_review_requested_more_review" as any };
  const saveReqBadM50: SaveReviewedEvidenceRequest = { ...saveReq, saveId: "save_bad_m50", promotionResult: badPromo };
  const resBadM50 = await saveReviewedEvidence(saveReqBadM50, evaluatedAt, repo);
  if (resBadM50.status !== "blocked" || resBadM50.reasonCode !== "source_promotion_not_promoted") {
    console.error("FAIL: Bad M50 status not blocked", resBadM50);
    process.exit(1);
  }

  // 8. Test invalid EvidenceRecord validation
  const badEvidPromo = { ...validPromotionResult, nonPersistedEvidenceRecord: { ...validEvidenceRecord, strength: "invalid" as any } as any };
  const saveReqBadEvid: SaveReviewedEvidenceRequest = { ...saveReq, saveId: "save_bad_evid", promotionResult: badEvidPromo };
  const resBadEvid = await saveReviewedEvidence(saveReqBadEvid, evaluatedAt, repo);
  if (resBadEvid.status !== "blocked" || resBadEvid.reasonCode !== "source_evidence_record_invalid") {
    console.error("FAIL: Invalid EvidenceRecord not blocked", resBadEvid);
    process.exit(1);
  }

  // 9. Unknown top level field get request
  const badGet = { ...getReq1, unknown_field: true };
  const resBadGet = await getReviewedEvidence(badGet, evaluatedAt, repo);
  if (resBadGet.status !== "failed" || resBadGet.reasonCode !== "invalid_read_request") {
    console.error("FAIL: Extra key in get request not rejected", resBadGet);
    process.exit(1);
  }

  // 10. Not found get
  const notFoundGet: GetReviewedEvidenceRequest = { ...getReq1, lookup: { by: "storeRecordId", storeRecordId: "missing" } };
  const resNotFound = await getReviewedEvidence(notFoundGet, evaluatedAt, repo);
  if (resNotFound.status !== "not_found" || resNotFound.reasonCode !== "not_found") {
    console.error("FAIL: not found get handled incorrectly", resNotFound);
    process.exit(1);
  }

  // 11. Unsafe lookup id
  const unsafeGet: GetReviewedEvidenceRequest = { ...getReq1, lookup: { by: "storeRecordId", storeRecordId: "secret_id" } };
  const resUnsafeGet = await getReviewedEvidence(unsafeGet, evaluatedAt, repo);
  if (resUnsafeGet.status !== "failed" || resUnsafeGet.reasonCode !== "invalid_read_metadata") {
    console.error("FAIL: Unsafe lookup ID not rejected", resUnsafeGet);
    process.exit(1);
  }

  // 12. Add M50 exact validation smoke cases
  const saveReqBase = saveReq;
  const badM50Cases = [
    { name: "unsafe promotionId secret_id", mod: { promotionId: "secret_id" }, expReason: "source_promotion_policy_unsafe" },
    { name: "unsafe promotionId bad id", mod: { promotionId: "bad id" }, expReason: "source_promotion_policy_unsafe" },
    { name: "unsafe promotionId bad/id", mod: { promotionId: "bad/id" }, expReason: "source_promotion_policy_unsafe" },
    { name: "unsafe promotionId bad.id", mod: { promotionId: "bad.id" }, expReason: "source_promotion_policy_unsafe" },
    { name: "invalid evaluatedAt", mod: { evaluatedAt: "2026-07-01Tnot-valid" }, expReason: "source_promotion_policy_unsafe" },
    { name: "extra M50 top-level key", mod: { extra_key: true }, expReason: "source_promotion_policy_unsafe" },
    { name: "missing explicitNonClaims", mod: { explicitNonClaims: undefined }, expReason: "source_promotion_policy_unsafe" },
    { name: "extra explicitNonClaims key", mod: { explicitNonClaims: { ...validPromotionResult.explicitNonClaims, extra: true } }, expReason: "source_promotion_policy_unsafe" },
    { name: "explicitNonClaims.noPersistence missing", mod: { explicitNonClaims: { ...validPromotionResult.explicitNonClaims, noPersistence: undefined } }, expReason: "source_promotion_policy_unsafe" },
    { name: "explicitNonClaims.noPersistence false", mod: { explicitNonClaims: { ...validPromotionResult.explicitNonClaims, noPersistence: false } }, expReason: "source_promotion_policy_unsafe" },
    { name: "explicitNonClaims string true", mod: { explicitNonClaims: { ...validPromotionResult.explicitNonClaims, noPersistence: "true" } as any }, expReason: "source_promotion_policy_unsafe" },
    { name: "missing M50 classification", mod: { classification: undefined }, expReason: "source_promotion_policy_unsafe" },
    { name: "extra classification key", mod: { classification: { ...validPromotionResult.classification, extra: true } }, expReason: "source_promotion_policy_unsafe" },
    { name: "classification string false", mod: { classification: { ...validPromotionResult.classification, persistsData: "false" } as any }, expReason: "source_promotion_policy_unsafe" },
    { name: "classification value true where false required", mod: { classification: { ...validPromotionResult.classification, persistsData: true } }, expReason: "source_promotion_policy_unsafe" },
  ];
  
  for (const c of badM50Cases) {
    const promo = { ...validPromotionResult, ...c.mod };
    const req = { ...saveReqBase, saveId: "save_bad_" + Math.random().toString(36).slice(2), promotionResult: promo };
    const res = await saveReviewedEvidence(req, evaluatedAt, repo);
    if (res.status !== "blocked" || res.reasonCode !== c.expReason) {
      console.error(`FAIL: ${c.name} not rejected`, res);
      process.exit(1);
    }
  }

  // 13. Add duplicate evidenceId smoke
  const saveReqDupEvid: SaveReviewedEvidenceRequest = {
    ...saveReq,
    saveId: "save_dup_evid",
    promotionResult: { ...validPromotionResult }
  };
  const resDupEvid = await saveReviewedEvidence(saveReqDupEvid, evaluatedAt, repo);
  if (resDupEvid.status !== "duplicate" || resDupEvid.reasonCode !== "duplicate_reviewed_evidence_record") {
    console.error("FAIL: Duplicate evidenceId not rejected", resDupEvid);
    process.exit(1);
  }

  // 14. Add repository save/read throw smoke
  const throwingRepo = {
    save: async () => { throw new Error("Save error"); },
    getByStoreRecordId: async () => { throw new Error("Read error"); },
    getByEvidenceId: async () => { throw new Error("Read error"); },
    listByScanId: async () => { throw new Error("Read error"); }
  };
  const resThrowSave = await saveReviewedEvidence({ ...saveReq, saveId: "save_throw" }, evaluatedAt, throwingRepo as any);
  if (resThrowSave.status !== "failed" || resThrowSave.reasonCode !== "repository_save_failed") {
    console.error("FAIL: Throwing save not handled", resThrowSave);
    process.exit(1);
  }
  const resThrowGet1 = await getReviewedEvidence(getReq1, evaluatedAt, throwingRepo as any);
  if (resThrowGet1.status !== "failed" || resThrowGet1.reasonCode !== "repository_read_failed") {
    console.error("FAIL: Throwing get not handled", resThrowGet1);
    process.exit(1);
  }
  const resThrowGet2 = await getReviewedEvidence(getReq2, evaluatedAt, throwingRepo as any);
  if (resThrowGet2.status !== "failed" || resThrowGet2.reasonCode !== "repository_read_failed") {
    console.error("FAIL: Throwing get not handled", resThrowGet2);
    process.exit(1);
  }
  const resThrowList = await listReviewedEvidence(listReq, evaluatedAt, throwingRepo as any);
  if (resThrowList.status !== "failed" || resThrowList.reasonCode !== "repository_read_failed") {
    console.error("FAIL: Throwing list not handled", resThrowList);
    process.exit(1);
  }

  // 15. Add get lookup smoke
  const badLookups = [
    { name: "extra key", lookup: { by: "storeRecordId", storeRecordId: safeSaveId, extra: true } },
    { name: "both IDs", lookup: { by: "storeRecordId", storeRecordId: safeSaveId, evidenceId: "abc" } },
    { name: "neither ID", lookup: { by: "storeRecordId" } },
    { name: "mismatched evidenceId", lookup: { by: "storeRecordId", evidenceId: "abc" } },
    { name: "mismatched storeRecordId", lookup: { by: "evidenceId", storeRecordId: safeSaveId } },
    { name: "not object", lookup: "not_object" },
    { name: "null", lookup: null },
    { name: "unsafe storeRecordId", lookup: { by: "storeRecordId", storeRecordId: "secret_id" } },
    { name: "unsafe evidenceId", lookup: { by: "evidenceId", evidenceId: "secret_id" } },
  ];
  for (const bl of badLookups) {
    const req = { ...getReq1, lookup: bl.lookup };
    const res = await getReviewedEvidence(req, evaluatedAt, repo);
    if (res.status !== "failed") {
      console.error(`FAIL: Lookup ${bl.name} not rejected`, res);
      process.exit(1);
    }
  }

  // 16. Add list options smoke
  const badListOpts = [
    { name: "extra key", opts: { limit: 2, extra: true } },
    { name: "not object", opts: "not_object" },
    { name: "null", opts: null },
    { name: "array", opts: [] },
    { name: "limit 0", opts: { limit: 0 } },
    { name: "limit -1", opts: { limit: -1 } },
    { name: "limit 1.5", opts: { limit: 1.5 } },
    { name: "limit string", opts: { limit: "2" } },
  ];
  for (const bopts of badListOpts) {
    const req = { ...listReq, options: bopts.opts };
    const res = await listReviewedEvidence(req, evaluatedAt, repo);
    if (res.status !== "failed") {
      console.error(`FAIL: List options ${bopts.name} not rejected`, res);
      process.exit(1);
    }
  }

  // 17. Add list ordering tie-break smoke
  const repoT = new InMemoryReviewedEvidenceStoreRepository();
  const time1 = "2026-07-01T12:00:00.000Z";
  const time2 = "2026-07-01T13:00:00.000Z";
  
  await saveReviewedEvidence({ ...saveReq, saveId: "save_b", promotionResult: { ...validPromotionResult, nonPersistedEvidenceRecord: { ...validEvidenceRecord, evidenceId: "ev_b" } as any } }, time1, repoT);
  await saveReviewedEvidence({ ...saveReq, saveId: "save_a", promotionResult: { ...validPromotionResult, nonPersistedEvidenceRecord: { ...validEvidenceRecord, evidenceId: "ev_a" } as any } }, time1, repoT);
  await saveReviewedEvidence({ ...saveReq, saveId: "save_c", promotionResult: { ...validPromotionResult, nonPersistedEvidenceRecord: { ...validEvidenceRecord, evidenceId: "ev_c" } as any } }, time2, repoT);
  
  const listTRes = await listReviewedEvidence(listReq, evaluatedAt, repoT);
  if (listTRes.summaries.map(s => s.storeRecordId).join(",") !== "save_c,save_a,save_b") {
    console.error("FAIL: List ordering tie-break failed", listTRes.summaries);
    process.exit(1);
  }

  // 18. Add default limit behavior smoke
  const defaultListReq = { ...listReq, options: undefined };
  const resDefList = await listReviewedEvidence(defaultListReq, evaluatedAt, repo);
  if (resDefList.status !== "listed") {
    console.error("FAIL: Default limit failed", resDefList);
    process.exit(1);
  }

  // 19. Corrupt repository get/list tests
  const makeCorruptRepo = (corruptFn: (r: any) => any) => {
    return {
      save: async (r: any) => r,
      getByStoreRecordId: async () => corruptFn(JSON.parse(JSON.stringify(resSave.record))),
      getByEvidenceId: async () => corruptFn(JSON.parse(JSON.stringify(resSave.record))),
      listByScanId: async () => [corruptFn(JSON.parse(JSON.stringify(resSave.record)))]
    } as any;
  };
  
  const corruptCases = [
    { name: "storeRecordId", fn: (r: any) => { r.storeRecordId = "secret_id"; return r; } },
    { name: "sourcePromotionId", fn: (r: any) => { r.source.sourcePromotionId = "secret_id"; return r; } },
    { name: "evidenceId", fn: (r: any) => { r.evidenceRecord.evidenceId = "secret_id"; return r; } },
    { name: "evidenceType", fn: (r: any) => { r.evidenceRecord.evidenceType = "not_allowed"; return r; } }
  ];

  for (const cc of corruptCases) {
    const cRepo = makeCorruptRepo(cc.fn);
    const gRes = await getReviewedEvidence(getReq1, evaluatedAt, cRepo);
    if (gRes.status !== "failed" || gRes.reasonCode !== "store_record_validation_failed") {
      console.error(`FAIL: Corrupt ${cc.name} get not rejected safely`, gRes);
      process.exit(1);
    }
    if ("record" in gRes || "summary" in gRes) {
      console.error(`FAIL: Corrupt ${cc.name} get leaked record/summary`, gRes);
      process.exit(1);
    }
    
    const lRes = await listReviewedEvidence(listReq, evaluatedAt, cRepo);
    if (lRes.status !== "failed" || lRes.reasonCode !== "store_record_validation_failed") {
      console.error(`FAIL: Corrupt ${cc.name} list not rejected safely`, lRes);
      process.exit(1);
    }
  }

  // 20. save store record validator coverage
  const badNestedCases = [
    { name: "evidenceId bad.id", fn: (ev: any) => { ev.evidenceId = "bad.id"; return ev; } },
    { name: "evidenceId bad id", fn: (ev: any) => { ev.evidenceId = "bad id"; return ev; } },
    { name: "evidenceId bad/id", fn: (ev: any) => { ev.evidenceId = "bad/id"; return ev; } },
    { name: "evidenceId overlong", fn: (ev: any) => { ev.evidenceId = "a".repeat(100); return ev; } },
    { name: "indicatorId bad.id", fn: (ev: any) => { ev.indicatorId = "bad.id"; return ev; } },
    { name: "scanId bad.id", fn: (ev: any) => { ev.scanId = "bad.id"; return ev; } },
    { name: "collectedAt date-only", fn: (ev: any) => { ev.collectedAt = "2026-07-01"; return ev; } },
    { name: "collectedAt invalid", fn: (ev: any) => { ev.collectedAt = "2026-07-01Tnot-valid"; return ev; } },
    { name: "collectedAt not-a-date", fn: (ev: any) => { ev.collectedAt = "not-a-date"; return ev; } },
  ];
  
  for (const cc of badNestedCases) {
    // Test save path rejection (via mutating M50 input)
    const badM50Record = cc.fn(JSON.parse(JSON.stringify(validEvidenceRecord)));
    const saveReqBadNested: SaveReviewedEvidenceRequest = {
      ...saveReq,
      saveId: "save_bad_nested_" + Math.random().toString(36).slice(2),
      promotionResult: { ...validPromotionResult, nonPersistedEvidenceRecord: badM50Record }
    };
    const resBadNestedSave = await saveReviewedEvidence(saveReqBadNested, evaluatedAt, repo);
    if (resBadNestedSave.status !== "blocked" && resBadNestedSave.status !== "failed") {
      console.error(`FAIL: Save allowed corrupt ${cc.name}`, resBadNestedSave);
      process.exit(1);
    }
    const rc = resBadNestedSave.reasonCode;
    if (rc !== "store_record_validation_failed" && rc !== "source_evidence_record_invalid" && rc !== "source_scan_mismatch") {
      console.error(`FAIL: Save corrupt ${cc.name} failed with wrong reasonCode ${rc}`);
      process.exit(1);
    }
    if (JSON.stringify(resBadNestedSave).includes("bad.id")) {
      console.error(`FAIL: Save corrupt ${cc.name} leaked unsafe raw string`);
      process.exit(1);
    }

    // Test get/list path rejection (via mutating repository)
    const storeRecordFn = (r: any) => {
      r.evidenceRecord = cc.fn(r.evidenceRecord);
      return r;
    };
    const cRepo = makeCorruptRepo(storeRecordFn);
    const gRes = await getReviewedEvidence(getReq1, evaluatedAt, cRepo);
    if (gRes.status !== "failed" || gRes.reasonCode !== "store_record_validation_failed") {
      console.error(`FAIL: Corrupt ${cc.name} get not rejected safely`, gRes);
      process.exit(1);
    }
    if (JSON.stringify(gRes).includes("bad.id")) {
      console.error(`FAIL: Corrupt ${cc.name} get leaked unsafe raw string`);
      process.exit(1);
    }
    
    const lRes = await listReviewedEvidence(listReq, evaluatedAt, cRepo);
    if (lRes.status !== "failed" || lRes.reasonCode !== "store_record_validation_failed") {
      console.error(`FAIL: Corrupt ${cc.name} list not rejected safely`, lRes);
      process.exit(1);
    }
    if (JSON.stringify(lRes).includes("bad.id")) {
      console.error(`FAIL: Corrupt ${cc.name} list leaked unsafe raw string`);
      process.exit(1);
    }
  }
  
  console.log("=== M51 DB-Free Reviewed Evidence Store Smoke PASS ===");
}

runSmoke();
