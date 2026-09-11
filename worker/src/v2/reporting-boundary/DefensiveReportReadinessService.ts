import type { FormalFindingCandidateRepository } from "../finding-candidate-promotion/FindingCandidatePersistenceContracts.js";
import { validateReviewedEvidenceFormalFindingCandidate } from "../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionService.js";
import {
  type DefensiveAssessmentReport,
  type GenerateDefensiveReportCommand,
  ReportGenerationError,
  isStrictSafeId,
  isStrictIsoTimestamp,
  isSafeAttestationText,
  validateDefensiveAssessmentReport
} from "./DefensiveReportContracts.js";

export class DefensiveReportReadinessService {
  constructor(
    private readonly candidateRepository: FormalFindingCandidateRepository
  ) {}

  public async generateReport(
    command: GenerateDefensiveReportCommand
  ): Promise<DefensiveAssessmentReport> {
    if (!command || typeof command !== "object" || Array.isArray(command)) {
      throw new ReportGenerationError(
        "invalid_report_request",
        "Command must be a non-null object"
      );
    }

    // 1. Mandatory Human-in-the-Loop Operator Signature & Attestation Validation
    const signature = command.operatorSignatureId;
    if (!signature || typeof signature !== "string" || signature.trim().length === 0) {
      throw new ReportGenerationError(
        "missing_operator_signature",
        "operatorSignatureId is mandatory and cannot be empty or omitted"
      );
    }

    if (!isStrictSafeId(signature)) {
      throw new ReportGenerationError(
        "invalid_report_request",
        "operatorSignatureId must satisfy strict identifier format"
      );
    }

    if (!isStrictIsoTimestamp(command.operatorVerifiedAt)) {
      throw new ReportGenerationError(
        "invalid_report_request",
        "operatorVerifiedAt must be a valid ISO 8601 UTC timestamp"
      );
    }

    const attestationText = command.operatorAttestationText;
    if (!attestationText || typeof attestationText !== "string" || attestationText.trim().length === 0) {
      throw new ReportGenerationError(
        "invalid_report_request",
        "operatorAttestationText is mandatory and cannot be empty or omitted"
      );
    }

    if (attestationText.length < 10 || attestationText.length > 500) {
      throw new ReportGenerationError(
        "invalid_report_request",
        "operatorAttestationText length must be between 10 and 500 characters"
      );
    }

    if (!isSafeAttestationText(attestationText)) {
      throw new ReportGenerationError(
        "invalid_report_request",
        "operatorAttestationText contains forbidden or unsafe terms"
      );
    }

    // 2. Validate Command Metadata
    if (!isStrictSafeId(command.reportId)) {
      throw new ReportGenerationError(
        "invalid_report_request",
        "reportId is missing or has invalid format"
      );
    }

    if (!isStrictSafeId(command.sessionId)) {
      throw new ReportGenerationError(
        "invalid_report_request",
        "sessionId is missing or has invalid format"
      );
    }

    if (!isStrictSafeId(command.scanId)) {
      throw new ReportGenerationError(
        "invalid_report_request",
        "scanId is missing or has invalid format"
      );
    }

    if (!isStrictIsoTimestamp(command.requestedAt)) {
      throw new ReportGenerationError(
        "invalid_report_request",
        "requestedAt must be a valid ISO 8601 UTC timestamp"
      );
    }

    // 3. Fetch Candidates strictly through Repository Port (DB-Free compliant)
    const rawCandidates = await this.candidateRepository.listCandidatesByScanId(command.scanId);

    // 4. Defensive Re-validation of Candidate Integrity, Substance & Scope
    for (const candidate of rawCandidates) {
      // 4.1 Re-validate evidence substance (non-hollow)
      if (
        !candidate ||
        typeof candidate !== "object" ||
        !candidate.evidenceRefs ||
        typeof candidate.evidenceRefs !== "object" ||
        candidate.evidenceRefs.selectedCount <= 0 ||
        !Array.isArray(candidate.evidenceRefs.selectedRefs) ||
        candidate.evidenceRefs.selectedRefs.length === 0
      ) {
        throw new ReportGenerationError(
          "report_generation_aborted_insufficient_substance",
          `Candidate ${candidate?.candidateId || "unknown"} contains zero substantive evidence references`
        );
      }

      // 4.2 Strict domain shape validation
      const isValid = validateReviewedEvidenceFormalFindingCandidate(candidate);
      if (!isValid) {
        throw new ReportGenerationError(
          "report_generation_aborted_corrupted_candidate",
          `Candidate ${candidate?.candidateId || "unknown"} failed domain shape validation`
        );
      }

      // 4.3 Scope Boundary: Candidate scanId must strictly match the report command scanId
      if (candidate.scanId !== command.scanId) {
        throw new ReportGenerationError(
          "report_generation_aborted_corrupted_candidate",
          `Candidate ${candidate.candidateId} scanId (${candidate.scanId}) does not match command scanId (${command.scanId})`
        );
      }

      if (candidate.lineage?.scanId && candidate.lineage.scanId !== command.scanId) {
        throw new ReportGenerationError(
          "report_generation_aborted_corrupted_candidate",
          `Candidate ${candidate.candidateId} lineage scanId (${candidate.lineage.scanId}) does not match command scanId (${command.scanId})`
        );
      }

      // 4.4 Re-validate unbroken non-claims
      const nc = candidate.explicitNonClaims;
      if (
        nc.noConfirmedFinding !== true ||
        nc.noConfirmedVulnerability !== true ||
        nc.noExploitabilityClaim !== true ||
        nc.noSeverityRiskOrImpactClaim !== true ||
        nc.noRemediationAdvice !== true ||
        nc.noSafeReportItemCreated !== true ||
        nc.noExternalReportCreated !== true ||
        nc.noNetworkExecution !== true ||
        nc.noToolExecution !== true ||
        nc.noPersistence !== true
      ) {
        throw new ReportGenerationError(
          "report_generation_aborted_corrupted_candidate",
          `Candidate ${candidate.candidateId} has violated non-claim invariants`
        );
      }

      // 4.5 Check for unauthorized injected classification keys
      const candidateObj = candidate as Record<string, unknown>;
      if (
        "severity" in candidateObj ||
        "risk_score" in candidateObj ||
        "cvss" in candidateObj ||
        "remediation" in candidateObj ||
        "remediation_advice" in candidateObj
      ) {
        throw new ReportGenerationError(
          "report_generation_aborted_corrupted_candidate",
          `Candidate ${candidate.candidateId} contains forbidden speculative classification keys`
        );
      }

      // 4.6 Lineage assessmentId consistency
      if (candidate.lineage?.assessmentId && candidate.lineage.assessmentId !== command.sessionId) {
        throw new ReportGenerationError(
          "report_generation_aborted_corrupted_candidate",
          `Candidate ${candidate.candidateId} lineage assessmentId does not match session ${command.sessionId}`
        );
      }
    }

    // 5. Build Canonical Defensive Assessment Report (Direct Mapping without Defaults or Inferred Values)
    const candidatesClone = JSON.parse(JSON.stringify(rawCandidates));

    const report: DefensiveAssessmentReport = {
      contractVersion: "fixguard-defensive-assessment-report/v0",
      kind: "defensive_assessment_report",
      reportId: command.reportId,
      sessionId: command.sessionId,
      scanId: command.scanId,
      generatedAt: command.requestedAt,
      operatorAttestation: {
        operatorSignatureId: command.operatorSignatureId,
        verifiedAt: command.operatorVerifiedAt,
        attestationText: command.operatorAttestationText
      },
      auditLimitations: {
        isPointInTimeAssessment: true,
        defensiveAssessmentOnly: true,
        noConfirmedVulnerabilities: true,
        noExploitabilityConfirmed: true,
        noSeverityRiskOrImpactClaims: true,
        noRemediationGuarantees: true,
        humanAuthorizedOnly: true
      },
      candidateCount: candidatesClone.length,
      candidates: candidatesClone,
      explicitNonClaims: {
        noConfirmedFindings: true,
        noConfirmedVulnerabilities: true,
        noExploitabilityClaims: true,
        noSeverityClaims: true,
        noRiskScoreClaims: true,
        noCvssClaims: true,
        noRemediationAdvice: true,
        noAutonomousExploitation: true
      }
    };

    // 6. Strict Self-Validation before returning to consumer
    if (!validateDefensiveAssessmentReport(report)) {
      throw new ReportGenerationError(
        "report_validation_failed",
        "Generated report failed closed-world exact-key schema validation"
      );
    }

    return report;
  }
}
