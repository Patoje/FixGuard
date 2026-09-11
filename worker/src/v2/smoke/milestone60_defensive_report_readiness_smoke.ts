import assert from "node:assert";
import process from "node:process";

import { InMemoryFormalFindingCandidateRepository } from "../finding-candidate-promotion/InMemoryFormalFindingCandidateRepository.js";
import type { ReviewedEvidenceFormalFindingCandidate } from "../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionContracts.js";
import type { ExecutionLineage } from "../evidence/EvidenceBoundaryContracts.js";
import {
  ReportGenerationError,
  validateDefensiveAssessmentReport,
  type GenerateDefensiveReportCommand
} from "../reporting-boundary/DefensiveReportContracts.js";
import { DefensiveReportReadinessService } from "../reporting-boundary/DefensiveReportReadinessService.js";

function buildValidCandidate(
  candidateId: string,
  scanId: string,
  assessmentId: string
): ReviewedEvidenceFormalFindingCandidate {
  const now = new Date().toISOString();
  const lineage: ExecutionLineage = {
    assessmentId,
    scanId,
    authorizationGrantId: "grt_m60_smoke_001",
    authorizationDecisionId: "dec_m60_smoke_001",
    actorId: "usr_m60_auditor",
    validationId: "val_m60_smoke_001"
  };

  return {
    contractVersion: "fixguard-reviewed-evidence-formal-finding-candidate/v0",
    kind: "reviewed_evidence_formal_finding_candidate",
    candidateId,
    scanId,
    createdAt: now,
    lineage,
    sourceDraft: {
      draftId: `drf_${candidateId}`,
      sourceSelectionId: "sel_m60_001",
      selectedCount: 1,
      candidateKind: "reviewed_evidence_group",
      triageState: "requires_human_triage",
      confidenceState: "evidence_grouped_not_confirmed"
    },
    humanTriage: {
      decisionId: "dec_triage_m60_001",
      reviewerId: "usr_m60_auditor",
      reviewedAt: now,
      decision: "approve_finding_candidate_promotion",
      humanApprovedPromotion: true
    },
    evidenceRefs: {
      selectedRefs: [
        {
          storeRecordId: "str_m60_ref_001",
          evidenceId: "evd_m60_ref_001",
          scanId,
          indicatorId: "ind_m60_diff_001"
        }
      ],
      selectedCount: 1
    },
    observedEvidenceSummary: {
      evidenceTypeCounts: { http_difference: 1 },
      strengthCounts: { strong: 1 },
      indicatorIds: ["ind_m60_diff_001"],
      collectedAtRange: { earliest: now, latest: now },
      savedAtRange: { earliest: now, latest: now }
    },
    candidateState: {
      lifecycleState: "formal_candidate_created",
      confirmationState: "not_confirmed",
      reportState: "not_reported",
      persistenceState: "not_persisted",
      requiresFurtherHumanReview: true
    },
    storage: {
      persisted: false,
      persistedToDatabase: false,
      externalized: false
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
      createsFormalFindingCandidate: true,
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
}

async function runMilestone60Smoke() {
  console.log("=== FixGuard V2 Milestone 60: Defensive Report Readiness Gate Smoke (Patch 1) ===");

  const sessionId = "asm_m60_test_001";
  const scanId = "scn_m60_test_001";
  const operatorSignatureId = "usr_lead_auditor_001";
  const now = new Date().toISOString();
  const operatorAttestationText =
    "Authorized defensive audit completed. Observed findings reflect target responses without speculative severities.";

  const repository = new InMemoryFormalFindingCandidateRepository();
  const service = new DefensiveReportReadinessService(repository);

  // -------------------------------------------------------------------------
  // 1. Happy Path: Valid Signed Defensive Assessment Report
  // -------------------------------------------------------------------------
  console.log("[*] Section 1: Testing Happy Path Report Generation...");
  const validCandidate = buildValidCandidate("cnd_m60_safe_01", scanId, sessionId);
  await repository.saveCandidate(validCandidate);

  const validCommand: GenerateDefensiveReportCommand = {
    reportId: "rep_m60_001",
    sessionId,
    scanId,
    requestedAt: now,
    operatorSignatureId,
    operatorVerifiedAt: now,
    operatorAttestationText
  };

  const report = await service.generateReport(validCommand);
  assert.strictEqual(report.contractVersion, "fixguard-defensive-assessment-report/v0");
  assert.strictEqual(report.kind, "defensive_assessment_report");
  assert.strictEqual(report.reportId, "rep_m60_001");
  assert.strictEqual(report.sessionId, sessionId);
  assert.strictEqual(report.scanId, scanId);
  assert.strictEqual(report.candidateCount, 1);
  assert.strictEqual(report.candidates.length, 1);
  assert.strictEqual(report.candidates[0].candidateId, "cnd_m60_safe_01");

  // Operator Attestation assertions: directly mapped without defaults or inferred values
  assert.strictEqual(report.operatorAttestation.operatorSignatureId, operatorSignatureId);
  assert.strictEqual(report.operatorAttestation.verifiedAt, now);
  assert.strictEqual(report.operatorAttestation.attestationText, operatorAttestationText);

  // Audit Limitations assertions
  assert.strictEqual(report.auditLimitations.isPointInTimeAssessment, true);
  assert.strictEqual(report.auditLimitations.defensiveAssessmentOnly, true);
  assert.strictEqual(report.auditLimitations.noConfirmedVulnerabilities, true);
  assert.strictEqual(report.auditLimitations.noExploitabilityConfirmed, true);
  assert.strictEqual(report.auditLimitations.noSeverityRiskOrImpactClaims, true);
  assert.strictEqual(report.auditLimitations.noRemediationGuarantees, true);
  assert.strictEqual(report.auditLimitations.humanAuthorizedOnly, true);

  // Explicit Non-Claims assertions
  assert.strictEqual(report.explicitNonClaims.noConfirmedFindings, true);
  assert.strictEqual(report.explicitNonClaims.noConfirmedVulnerabilities, true);
  assert.strictEqual(report.explicitNonClaims.noExploitabilityClaims, true);
  assert.strictEqual(report.explicitNonClaims.noSeverityClaims, true);
  assert.strictEqual(report.explicitNonClaims.noRiskScoreClaims, true);
  assert.strictEqual(report.explicitNonClaims.noCvssClaims, true);
  assert.strictEqual(report.explicitNonClaims.noRemediationAdvice, true);
  assert.strictEqual(report.explicitNonClaims.noAutonomousExploitation, true);

  // Self-validation
  assert.strictEqual(validateDefensiveAssessmentReport(report), true);
  console.log("  [+] Happy path report compiled and validated with intact limitations.");

  // -------------------------------------------------------------------------
  // 2. Gatekeeper Test: Missing or Empty Operator Signature Fails Closed
  // -------------------------------------------------------------------------
  console.log("[*] Section 2: Testing Missing or Empty Operator Signature...");

  await assert.rejects(
    service.generateReport({ ...validCommand, operatorSignatureId: "" }),
    (err: any) => {
      assert.ok(err instanceof ReportGenerationError);
      assert.strictEqual(err.code, "missing_operator_signature");
      return true;
    },
    "Must fail closed with missing_operator_signature on empty string"
  );

  await assert.rejects(
    service.generateReport({ ...validCommand, operatorSignatureId: "   " }),
    (err: any) => {
      assert.ok(err instanceof ReportGenerationError);
      assert.strictEqual(err.code, "missing_operator_signature");
      return true;
    },
    "Must fail closed with missing_operator_signature on whitespace"
  );

  await assert.rejects(
    service.generateReport({ ...validCommand, operatorSignatureId: undefined as any }),
    (err: any) => {
      assert.ok(err instanceof ReportGenerationError);
      assert.strictEqual(err.code, "missing_operator_signature");
      return true;
    },
    "Must fail closed with missing_operator_signature on undefined"
  );

  // Missing attestation text or verifiedAt
  await assert.rejects(
    service.generateReport({ ...validCommand, operatorAttestationText: "" }),
    (err: any) => {
      assert.ok(err instanceof ReportGenerationError);
      assert.strictEqual(err.code, "invalid_report_request");
      return true;
    },
    "Must fail closed on empty operatorAttestationText"
  );

  await assert.rejects(
    service.generateReport({ ...validCommand, operatorVerifiedAt: "invalid_time" }),
    (err: any) => {
      assert.ok(err instanceof ReportGenerationError);
      assert.strictEqual(err.code, "invalid_report_request");
      return true;
    },
    "Must fail closed on invalid operatorVerifiedAt"
  );

  console.log("  [+] Gatekeeper successfully blocked unsigned or incomplete report attempts.");

  // -------------------------------------------------------------------------
  // 3. Gatekeeper Test: Corrupted Candidate (Injected Severity Claim)
  // -------------------------------------------------------------------------
  console.log("[*] Section 3: Testing Rejection of Corrupted Candidate with Injected Severity...");
  const corruptedRepo = {
    listCandidatesByScanId: async () => {
      const cand: any = buildValidCandidate("cnd_m60_corrupt_01", scanId, sessionId);
      cand.severity = "CRITICAL"; // Malicious DB or cache injection
      return [cand];
    },
    saveCandidate: async (c: any) => c,
    getCandidate: async () => null,
    getCandidateByDraftId: async () => null
  };

  const corruptedService = new DefensiveReportReadinessService(corruptedRepo);
  await assert.rejects(
    corruptedService.generateReport(validCommand),
    (err: any) => {
      assert.ok(err instanceof ReportGenerationError);
      assert.strictEqual(err.code, "report_generation_aborted_corrupted_candidate");
      return true;
    },
    "Must fail closed when candidate contains injected severity"
  );
  console.log("  [+] Repository with injected severity correctly aborted report generation.");

  // -------------------------------------------------------------------------
  // 4. Gatekeeper Test: Candidate Compromised Non-Claims Invariant
  // -------------------------------------------------------------------------
  console.log("[*] Section 4: Testing Rejection of Broken Candidate Non-Claims...");
  const brokenNonClaimsRepo = {
    listCandidatesByScanId: async () => {
      const cand = buildValidCandidate("cnd_m60_broken_nc", scanId, sessionId);
      (cand.explicitNonClaims as any).noConfirmedVulnerability = false; // Invariant violated
      return [cand];
    },
    saveCandidate: async (c: any) => c,
    getCandidate: async () => null,
    getCandidateByDraftId: async () => null
  };

  const brokenNcService = new DefensiveReportReadinessService(brokenNonClaimsRepo);
  await assert.rejects(
    brokenNcService.generateReport(validCommand),
    (err: any) => {
      assert.ok(err instanceof ReportGenerationError);
      assert.strictEqual(err.code, "report_generation_aborted_corrupted_candidate");
      return true;
    },
    "Must fail closed when candidate non-claims are violated"
  );
  console.log("  [+] Candidate with violated non-claim invariants correctly aborted report generation.");

  // -------------------------------------------------------------------------
  // 5. Gatekeeper Test: Hollow Candidate (Zero Evidence Substance)
  // -------------------------------------------------------------------------
  console.log("[*] Section 5: Testing Rejection of Candidate with Zero Evidence Substance...");
  const hollowCandidateRepo = {
    listCandidatesByScanId: async () => {
      const cand = buildValidCandidate("cnd_m60_hollow", scanId, sessionId);
      cand.evidenceRefs.selectedCount = 0;
      cand.evidenceRefs.selectedRefs = [];
      return [cand];
    },
    saveCandidate: async (c: any) => c,
    getCandidate: async () => null,
    getCandidateByDraftId: async () => null
  };

  const hollowService = new DefensiveReportReadinessService(hollowCandidateRepo);
  await assert.rejects(
    hollowService.generateReport(validCommand),
    (err: any) => {
      assert.ok(err instanceof ReportGenerationError);
      assert.strictEqual(err.code, "report_generation_aborted_insufficient_substance");
      return true;
    },
    "Must fail closed when candidate has zero evidence substance"
  );
  console.log("  [+] Hollow candidate correctly aborted with report_generation_aborted_insufficient_substance.");

  // -------------------------------------------------------------------------
  // 6. Security Gatekeeper: Scope Boundary & Session/Scan Mismatch (Adversarial)
  // -------------------------------------------------------------------------
  console.log("[*] Section 6: Testing Scope Boundary & Scan Mismatch Adversarial Injections...");

  // 6.1 Adversarial test: candidate with different scanId
  const mismatchedScanRepo = {
    listCandidatesByScanId: async () => {
      const cand = buildValidCandidate("cnd_m60_scan_tamper", "scn_attacker_forged_999", sessionId);
      return [cand];
    },
    saveCandidate: async (c: any) => c,
    getCandidate: async () => null,
    getCandidateByDraftId: async () => null
  };

  const mismatchScanService = new DefensiveReportReadinessService(mismatchedScanRepo);
  await assert.rejects(
    mismatchScanService.generateReport(validCommand),
    (err: any) => {
      assert.ok(err instanceof ReportGenerationError);
      assert.strictEqual(err.code, "report_generation_aborted_corrupted_candidate");
      return true;
    },
    "Must fail closed when candidate scanId differs from report command scanId"
  );
  console.log("  [+] Candidate scanId mismatch caught and aborted with report_generation_aborted_corrupted_candidate.");

  // 6.2 Candidate with divergent lineage scanId
  const mismatchedLineageScanRepo = {
    listCandidatesByScanId: async () => {
      const cand = buildValidCandidate("cnd_m60_lin_tamper", scanId, sessionId);
      if (cand.lineage) {
        cand.lineage.scanId = "scn_divergent_lineage_888";
      }
      return [cand];
    },
    saveCandidate: async (c: any) => c,
    getCandidate: async () => null,
    getCandidateByDraftId: async () => null
  };

  const mismatchLineageService = new DefensiveReportReadinessService(mismatchedLineageScanRepo);
  await assert.rejects(
    mismatchLineageService.generateReport(validCommand),
    (err: any) => {
      assert.ok(err instanceof ReportGenerationError);
      assert.strictEqual(err.code, "report_generation_aborted_corrupted_candidate");
      return true;
    },
    "Must fail closed when candidate lineage scanId differs from command scanId"
  );
  console.log("  [+] Candidate lineage scanId divergence caught and aborted.");

  // 6.3 Candidate with divergent session ID
  const mismatchedSessionRepo = {
    listCandidatesByScanId: async () => {
      const cand = buildValidCandidate("cnd_m60_mismatch", scanId, "different_session_999");
      return [cand];
    },
    saveCandidate: async (c: any) => c,
    getCandidate: async () => null,
    getCandidateByDraftId: async () => null
  };

  const mismatchService = new DefensiveReportReadinessService(mismatchedSessionRepo);
  await assert.rejects(
    mismatchService.generateReport(validCommand),
    (err: any) => {
      assert.ok(err instanceof ReportGenerationError);
      assert.strictEqual(err.code, "report_generation_aborted_corrupted_candidate");
      return true;
    },
    "Must fail closed when candidate session ID diverges from command"
  );
  console.log("  [+] Lineage session mismatch correctly aborted report generation.");

  // -------------------------------------------------------------------------
  // 7. Report-Level Speculative Property & Scope Immunity
  // -------------------------------------------------------------------------
  console.log("[*] Section 7: Testing Report Schema Immunity against Speculative Properties & Scope Violations...");

  // Tampered candidate scanId inside report
  const tamperedCandidateScanIdReport: any = {
    ...report,
    candidates: [{ ...report.candidates[0], scanId: "scn_cross_tenant_leak" }]
  };
  assert.strictEqual(validateDefensiveAssessmentReport(tamperedCandidateScanIdReport), false);
  console.log("  [+] Report validator strictly rejected candidate with divergent scanId.");

  // Speculative property injections
  const tamperedReportSeverity: any = { ...report, severity: "CRITICAL" };
  assert.strictEqual(validateDefensiveAssessmentReport(tamperedReportSeverity), false);

  const tamperedReportCvss: any = { ...report, cvss: 9.8 };
  assert.strictEqual(validateDefensiveAssessmentReport(tamperedReportCvss), false);

  const tamperedReportRisk: any = { ...report, risk_score: 95 };
  assert.strictEqual(validateDefensiveAssessmentReport(tamperedReportRisk), false);

  const tamperedReportRemediation: any = { ...report, remediation_advice: "Patch immediately" };
  assert.strictEqual(validateDefensiveAssessmentReport(tamperedReportRemediation), false);

  console.log("  [+] Root-level exact-key validator strictly rejected all speculative fields.");

  console.log("=== Milestone 60 Smoke Suite Finished Successfully (100% Pass) ===");
}

runMilestone60Smoke().catch((err) => {
  console.error("[-] Milestone 60 smoke test failed with unexpected error:", err);
  process.exit(1);
});
