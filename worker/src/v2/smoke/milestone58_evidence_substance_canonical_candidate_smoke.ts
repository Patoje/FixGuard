import assert from "node:assert";
import {
  validateEvidenceSubstance,
  validateExecutionLineage,
  validateEvidenceRecord
} from "../evidence/EvidenceBoundaryService.js";
import type {
  EvidenceRecord,
  ExecutionLineage,
  EvidenceSubstancePayload
} from "../evidence/EvidenceBoundaryContracts.js";
import {
  evaluateHumanReviewedEvidencePromotion
} from "../evidence-review/HumanReviewedEvidencePromotionService.js";
import type {
  HumanReviewedEvidencePromotionRequest
} from "../evidence-review/HumanReviewedEvidencePromotionContracts.js";
import {
  promoteReviewedEvidenceFindingCandidateDraft,
  validateReviewedEvidenceFormalFindingCandidate
} from "../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionService.js";
import {
  projectCanonicalCandidate
} from "../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionContracts.js";
import type {
  PromoteReviewedEvidenceFindingCandidateDraftRequest,
  ReviewedEvidenceFindingCandidateTriageDecision,
  ReviewedEvidenceFormalFindingCandidate,
  CanonicalFindingCandidate
} from "../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionContracts.js";
import type {
  ReviewedEvidenceFindingCandidateDraft
} from "../finding-candidate-draft/ReviewedEvidenceFindingCandidateDraftContracts.js";

async function runMilestone58Smoke() {
  console.log("=== FixGuard V2 Milestone 58: Evidence Substance & Canonical Candidate Smoke ===");

  const scanId = "scn_m58_test_001";
  const assessmentId = "asm_m58_test_001";
  const grantId = "grt_m58_test_001";
  const decisionId = "dec_m58_test_001";
  const actorId = "usr_auditor_001";
  const validationId = "val_m58_test_001";
  const indicatorId = "ind_m58_diff_001";
  const now = "2026-09-07T20:00:00.000Z";

  const validLineage: ExecutionLineage = {
    assessmentId,
    scanId,
    authorizationGrantId: grantId,
    authorizationDecisionId: decisionId,
    actorId,
    validationId
  };

  // =========================================================================
  // Section 1: Substantive Evidence Validation & Discrimination
  // =========================================================================
  console.log("[*] Section 1: Testing Evidence Substance & Discriminated Payloads...");

  // 1.1 Lineage validation standalone
  {
    const validLinRes = validateExecutionLineage(validLineage);
    assert.strictEqual(validLinRes.isValid, true);

    const missingKeyLin: any = { ...validLineage };
    delete missingKeyLin.validationId;
    const missingLinRes = validateExecutionLineage(missingKeyLin);
    assert.strictEqual(missingLinRes.isValid, false);
    assert.strictEqual(missingLinRes.errorCode, "unsafe_content_rejected");

    const extraKeyLin: any = { ...validLineage, unauthorizedToken: "secret" };
    const extraLinRes = validateExecutionLineage(extraKeyLin);
    assert.strictEqual(extraLinRes.isValid, false);
    console.log("  [+] Lineage exact-key closed-world check passed.");
  }

  // 1.2 Happy path: HTTP differential substance with lineage
  const baseSubstantiveHttpEvidence: EvidenceRecord = {
    contractVersion: "fixguard-evidence-boundary/v0",
    kind: "evidence_record",
    evidenceId: "evd_subst_http_001",
    scanId,
    indicatorId,
    collectedAt: now,
    collectedBy: "response_comparator",
    evidenceType: "http_difference",
    strength: "strong",
    redaction: { isRedacted: true, redactionMethod: "m48_safe_comparison_draft" },
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false
    },
    lineage: validLineage,
    baseline: {
      method: "GET",
      statusCode: 200,
      contentLength: 1250,
      responseTimeMs: 45
    },
    attackOrValidation: {
      method: "GET",
      statusCode: 500,
      contentLength: 320,
      responseTimeMs: 80
    },
    difference: {
      statusCodeChanged: true,
      contentLengthDeltaPercent: -74.4
    }
  };

  {
    const subRes = validateEvidenceSubstance(baseSubstantiveHttpEvidence);
    assert.strictEqual(subRes.isValid, true);
    console.log("  [+] Valid HTTP differential substantive evidence accepted.");
  }

  // 1.3 Hollow/empty payload rejection (zero differential signals)
  {
    const hollowEvidence: EvidenceRecord = {
      ...baseSubstantiveHttpEvidence,
      evidenceId: "evd_hollow_001",
      difference: {} // empty differential signal
    };
    const hollowRes = validateEvidenceSubstance(hollowEvidence);
    assert.strictEqual(hollowRes.isValid, false);
    assert.strictEqual(hollowRes.errorCode, "insufficient_evidence_substance");
    console.log("  [+] Hollow HTTP difference evidence safely rejected with insufficient_evidence_substance.");
  }

  // 1.4 Missing lineage on substantive evidence
  {
    const noLineageEvidence: EvidenceRecord = {
      ...baseSubstantiveHttpEvidence,
      evidenceId: "evd_no_lin_001",
      lineage: undefined
    };
    const noLinRes = validateEvidenceSubstance(noLineageEvidence);
    assert.strictEqual(noLinRes.isValid, false);
    assert.strictEqual(noLinRes.errorCode, "insufficient_evidence_substance");
    console.log("  [+] Substantive evidence without lineage safely rejected.");
  }

  // 1.5 Lineage scanId mismatch rejection
  {
    const mismatchedLineageEvidence: EvidenceRecord = {
      ...baseSubstantiveHttpEvidence,
      evidenceId: "evd_mismatch_lin_001",
      lineage: {
        ...validLineage,
        scanId: "scn_different_999"
      }
    };
    const misLinRes = validateEvidenceSubstance(mismatchedLineageEvidence);
    assert.strictEqual(misLinRes.isValid, false);
    assert.strictEqual(misLinRes.errorCode, "invalid_lineage");
    console.log("  [+] Substantive evidence with lineage scanId mismatch safely rejected.");
  }

  // 1.6 Timing delta substantive payload checks
  {
    const validTimingEvidence: EvidenceRecord = {
      ...baseSubstantiveHttpEvidence,
      evidenceId: "evd_subst_timing_001",
      evidenceType: "time_based_difference",
      difference: {
        responseTimeDeltaMs: 4500
      }
    };
    const timingRes = validateEvidenceSubstance(validTimingEvidence);
    assert.strictEqual(timingRes.isValid, true);

    const invalidTimingEvidence: EvidenceRecord = {
      ...validTimingEvidence,
      evidenceId: "evd_invalid_timing_001",
      difference: {
        responseTimeDeltaMs: 0 // non-positive delta is hollow
      }
    };
    const invalidTimingRes = validateEvidenceSubstance(invalidTimingEvidence);
    assert.strictEqual(invalidTimingRes.isValid, false);
    assert.strictEqual(invalidTimingRes.errorCode, "insufficient_evidence_substance");
    console.log("  [+] Time-based difference substance validated strictly (positive responseTimeDeltaMs required).");
  }

  // 1.7 OOB callback substantive payload checks
  {
    const validOobEvidence: EvidenceRecord = {
      ...baseSubstantiveHttpEvidence,
      evidenceId: "evd_subst_oob_001",
      evidenceType: "oob_callback",
      baseline: undefined,
      attackOrValidation: undefined,
      difference: undefined,
      oobCallback: {
        correlationId: "cor_oob_12345",
        receivedAt: now,
        protocol: "dns",
        sourceIpHash: "hash_ip_abc",
        rawCallbackHash: "hash_raw_xyz"
      }
    };
    const oobRes = validateEvidenceSubstance(validOobEvidence);
    assert.strictEqual(oobRes.isValid, true);

    const hollowOobEvidence: EvidenceRecord = {
      ...validOobEvidence,
      evidenceId: "evd_hollow_oob_001",
      oobCallback: undefined
    };
    const hollowOobRes = validateEvidenceSubstance(hollowOobEvidence);
    assert.strictEqual(hollowOobRes.isValid, false);
    assert.strictEqual(hollowOobRes.errorCode, "insufficient_evidence_substance");
    console.log("  [+] OOB callback substance validated strictly.");
  }

  // =========================================================================
  // Section 2: Human-Reviewed Evidence Promotion with Substance & Lineage
  // =========================================================================
  console.log("[*] Section 2: Testing Human-Reviewed Evidence Promotion with Substance & Lineage...");

  const basePromotionRequest: HumanReviewedEvidencePromotionRequest = {
    contractVersion: "fixguard-human-reviewed-evidence-promotion/v0",
    kind: "human_reviewed_evidence_promotion_request",
    promotionId: "prm_m58_test_001",
    scanId,
    requestedAt: now,
    sourceIndicatorRef: {
      kind: "reviewed_indicator_reference",
      indicatorId,
      scanId
    },
    reviewDecision: {
      decision: "approve_evidence",
      reviewerId: "usr_analyst_001",
      reviewedAt: now
    },
    substancePayload: {
      evidenceType: "http_difference",
      baseline: {
        method: "GET",
        statusCode: 200,
        contentLength: 1000
      },
      attackOrValidation: {
        method: "GET",
        statusCode: 403,
        contentLength: 120
      },
      difference: {
        statusCodeChanged: true,
        authStateChanged: true
      }
    },
    classification: {
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
      persistsData: false
    },
    validationResult: {
      contractVersion: "fixguard-authorized-comparison-validation/v0",
      kind: "authorized_comparison_validation_result",
      validationId,
      scanId,
      evaluatedAt: now,
      status: "completed",
      reasonCode: "completed_with_evidence_draft",
      provenance: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId
      },
      classification: {
        createsRealFindings: false,
        createsPersistedEvidence: false,
        confirmsVulnerabilities: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false,
        executesNetwork: false,
        executesTools: false,
        persistsData: false
      },
      explicitNonClaims: {
        noConfirmedVulnerability: true,
        noFindingCreated: true,
        noFindingCandidateCreated: true,
        noPersistedEvidenceCreated: true,
        noSeverityRiskOrImpactClaim: true,
        noExternalReportCreated: true,
        noRawSensitiveDataIncluded: true,
        noNetworkExecution: true,
        noToolExecution: true
      },
      evidenceDraft: {
        draftKind: "non_persisted_comparison_evidence_draft",
        draftId: "drf_m58_001",
        sourceComparisonId: "cmp_m58_001",
        suggestedEvidenceType: "http_difference",
        suggestedStrength: "strong",
        requiresHumanReview: true,
        notPersisted: true,
        notARealFinding: true,
        notConfirmedEvidence: true,
        notForExternalDelivery: true,
        notM45EvidenceRecord: true,
        safeRationale: "differential observed",
        sourceSnapshotIds: {
          baselineSnapshotId: "bsl_001",
          validationSnapshotId: "val_001"
        }
      }
    }
  };

  // 2.1 Happy path promotion
  {
    const promoRes = evaluateHumanReviewedEvidencePromotion(basePromotionRequest, now);
    assert.strictEqual(promoRes.status, "promoted");
    assert.strictEqual(promoRes.reasonCode, "promoted_to_non_persisted_evidence_record");
    assert.ok(promoRes.nonPersistedEvidenceRecord);
    assert.deepStrictEqual(promoRes.nonPersistedEvidenceRecord.lineage, validLineage);
    assert.strictEqual(promoRes.nonPersistedEvidenceRecord.difference?.statusCodeChanged, true);
    console.log("  [+] M50 human review promotion seamlessly attaches ExecutionLineage and substantive payload.");
  }

  // 2.2 Lineage mismatch in M49 provenance triggers blocked_lineage_mismatch
  {
    const mismatchedProvenanceReq: HumanReviewedEvidencePromotionRequest = {
      ...basePromotionRequest,
      promotionId: "prm_mismatch_001",
      validationResult: {
        ...basePromotionRequest.validationResult,
        provenance: {
          ...basePromotionRequest.validationResult.provenance!,
          scanId: "scn_other_999" // mismatch with request.scanId
        }
      }
    };
    const mismatchRes = evaluateHumanReviewedEvidencePromotion(mismatchedProvenanceReq, now);
    assert.strictEqual(mismatchRes.status, "blocked");
    assert.strictEqual(mismatchRes.reasonCode, "blocked_lineage_mismatch");
    console.log("  [+] Lineage scanId mismatch between validation provenance and request fails closed (blocked_lineage_mismatch).");
  }

  // 2.3 Hollow substance payload rejected during promotion
  {
    const hollowSubstanceReq: HumanReviewedEvidencePromotionRequest = {
      ...basePromotionRequest,
      promotionId: "prm_hollow_001",
      substancePayload: {
        evidenceType: "http_difference",
        baseline: { method: "GET" },
        attackOrValidation: { method: "GET" },
        difference: {} // empty difference -> hollow!
      }
    };
    const hollowRes = evaluateHumanReviewedEvidencePromotion(hollowSubstanceReq, now);
    assert.strictEqual(hollowRes.status, "blocked");
    assert.strictEqual(hollowRes.reasonCode, "insufficient_evidence_substance");
    console.log("  [+] Hollow substance payload rejected during promotion (insufficient_evidence_substance).");
  }

  // =========================================================================
  // Section 3: Lineage Continuity in Candidate Promotion (M54)
  // =========================================================================
  console.log("[*] Section 3: Testing Lineage Continuity in Candidate Promotion...");

  const candidateId = "cnd_m58_canonical_001";
  const draftId = "drf_candidate_001";
  const selectionId = "sel_candidate_001";

  const validDraft: ReviewedEvidenceFindingCandidateDraft = {
    contractVersion: "fixguard-reviewed-evidence-finding-candidate-draft/v0",
    kind: "reviewed_evidence_finding_candidate_draft",
    draftId,
    scanId,
    createdAt: now,
    sourceSelection: {
      selectionId,
      selectionMode: "explicit_store_record_ids",
      selectedCount: 1,
      selectedRefs: [
        { storeRecordId: "str_001", evidenceId: "evd_001", scanId, indicatorId }
      ]
    },
    observedEvidenceSummary: {
      evidenceTypeCounts: { http_difference: 1 },
      strengthCounts: { strong: 1 },
      indicatorIds: [indicatorId],
      collectedAtRange: { earliest: now, latest: now },
      savedAtRange: { earliest: now, latest: now }
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
    decisionId: "dec_triage_001",
    reviewerId: "usr_auditor_001",
    reviewedAt: now,
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

  const baseCandidatePromotionReq: PromoteReviewedEvidenceFindingCandidateDraftRequest = {
    contractVersion: "fixguard-reviewed-evidence-finding-candidate-promotion/v0",
    kind: "promote_reviewed_evidence_finding_candidate_draft_request",
    candidateId,
    scanId,
    requestedAt: now,
    draft: validDraft,
    triageDecision: validTriageDecision,
    lineage: validLineage,
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

  // 3.1 Happy path candidate promotion with lineage
  let promotedCandidate: ReviewedEvidenceFormalFindingCandidate;
  {
    const candRes = await promoteReviewedEvidenceFindingCandidateDraft(baseCandidatePromotionReq, now);
    assert.strictEqual(candRes.status, "candidate_created");
    assert.strictEqual(candRes.reasonCode, "formal_finding_candidate_created");
    assert.ok(candRes.candidate);
    assert.deepStrictEqual(candRes.candidate.lineage, validLineage);
    promotedCandidate = candRes.candidate;
    console.log("  [+] Candidate promotion preserves complete ExecutionLineage.");
  }

  // 3.2 Candidate promotion lineage mismatch fails closed
  {
    const mismatchedLineageReq: PromoteReviewedEvidenceFindingCandidateDraftRequest = {
      ...baseCandidatePromotionReq,
      candidateId: "cnd_mismatch_001",
      lineage: {
        ...validLineage,
        scanId: "scn_other_999" // mismatch with request.scanId
      }
    };
    const candMisRes = await promoteReviewedEvidenceFindingCandidateDraft(mismatchedLineageReq, now);
    assert.strictEqual(candMisRes.status, "blocked");
    assert.strictEqual(candMisRes.reasonCode, "blocked_lineage_mismatch");
    console.log("  [+] Candidate promotion rejects lineage scanId mismatch with blocked_lineage_mismatch.");
  }

  // 3.3 Candidate promotion with malformed lineage fails closed
  {
    const malformedLineageReq: any = {
      ...baseCandidatePromotionReq,
      candidateId: "cnd_malformed_001",
      lineage: {
        assessmentId,
        scanId // missing other 4 fields
      }
    };
    const malRes = await promoteReviewedEvidenceFindingCandidateDraft(malformedLineageReq, now);
    assert.strictEqual(malRes.status, "failed");
    assert.strictEqual(malRes.reasonCode, "invalid_promotion_metadata");
    console.log("  [+] Candidate promotion rejects malformed lineage fails closed.");
  }

  // =========================================================================
  // Section 4: Forgery Rejection & Canonical Semantics (ADR-003 & ADR-005)
  // =========================================================================
  console.log("[*] Section 4: Testing Forgery Rejection & Canonical Semantics...");

  // 4.1 Injected severity key rejected fail-closed by exact-key validator
  {
    const forgedCandidate: any = {
      ...promotedCandidate,
      severity: "CRITICAL" // forbidden autonomous severity claim
    };
    const isVal = validateReviewedEvidenceFormalFindingCandidate(forgedCandidate);
    assert.strictEqual(isVal, false, "Candidate with injected severity must be rejected");
    console.log("  [+] Forged candidate with injected severity: 'CRITICAL' rejected fail-closed.");
  }

  // 4.2 Injected remediation advice rejected fail-closed
  {
    const forgedRemediationCandidate: any = {
      ...promotedCandidate,
      remediationAdvice: "Patch software immediately"
    };
    const isVal = validateReviewedEvidenceFormalFindingCandidate(forgedRemediationCandidate);
    assert.strictEqual(isVal, false, "Candidate with injected remediation must be rejected");
    console.log("  [+] Forged candidate with injected remediation advice rejected fail-closed.");
  }

  // 4.3 Missing or corrupted explicit non-claims rejected fail-closed
  {
    const compromisedNonClaimsCandidate: any = {
      ...promotedCandidate,
      explicitNonClaims: {
        ...promotedCandidate.explicitNonClaims,
        noConfirmedVulnerability: false // violation!
      }
    };
    const isVal = validateReviewedEvidenceFormalFindingCandidate(compromisedNonClaimsCandidate);
    assert.strictEqual(isVal, false, "Candidate with compromised explicitNonClaims must be rejected");
    console.log("  [+] Candidate with compromised explicit non-claims (noConfirmedVulnerability: false) rejected fail-closed.");
  }

  // 4.4 Canonical candidate projection (projectCanonicalCandidate)
  {
    const canonical: CanonicalFindingCandidate = projectCanonicalCandidate(promotedCandidate);
    assert.strictEqual(canonical.candidateId, candidateId);
    assert.strictEqual(canonical.kind, "reviewed_evidence_formal_finding_candidate");
    assert.strictEqual(canonical.explicitNonClaims.noConfirmedVulnerability, true);
    assert.strictEqual(canonical.explicitNonClaims.noSeverityRiskOrImpactClaim, true);
    assert.strictEqual(canonical.explicitNonClaims.noRemediationAdvice, true);
    console.log("  [+] Canonical candidate identity verified (ReviewedEvidenceFormalFindingCandidate is canonical).");
  }

  // =========================================================================
  // Section 5: End-to-End Lineage & Substance Lineage Chain
  // =========================================================================
  console.log("[*] Section 5: Verifying End-to-End Lineage & Substance Chain...");
  {
    // Verify lineage integrity from origin validation through candidate
    assert.strictEqual(promotedCandidate.lineage?.assessmentId, assessmentId);
    assert.strictEqual(promotedCandidate.lineage?.scanId, scanId);
    assert.strictEqual(promotedCandidate.lineage?.authorizationGrantId, grantId);
    assert.strictEqual(promotedCandidate.lineage?.authorizationDecisionId, decisionId);
    assert.strictEqual(promotedCandidate.lineage?.actorId, actorId);
    assert.strictEqual(promotedCandidate.lineage?.validationId, validationId);

    // Verify zero autonomous claims
    assert.strictEqual((promotedCandidate as any).severity, undefined);
    assert.strictEqual((promotedCandidate as any).risk, undefined);
    assert.strictEqual((promotedCandidate as any).remediation, undefined);
    assert.strictEqual(promotedCandidate.classification.confirmsVulnerabilities, false);
    assert.strictEqual(promotedCandidate.classification.makesSeverityClaims, false);
    assert.strictEqual(promotedCandidate.classification.providesRemediationAdvice, false);

    console.log("  [+] Complete unbroken lineage tuple preserved across all pipeline boundaries.");
  }

  console.log("=== V2 Milestone 58 Smoke Test Completed Successfully ===");
}

runMilestone58Smoke().catch(err => {
  console.error("FATAL: Milestone 58 Smoke Test Failed:", err);
  process.exit(1);
});
