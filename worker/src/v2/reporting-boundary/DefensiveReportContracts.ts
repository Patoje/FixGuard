import type { ReviewedEvidenceFormalFindingCandidate } from "../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionContracts.js";
import { validateReviewedEvidenceFormalFindingCandidate } from "../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionService.js";

export type DefensiveReportContractVersion = "fixguard-defensive-assessment-report/v0";

export type OperatorAttestation = {
  operatorSignatureId: string;
  verifiedAt: string;
  attestationText: string;
};

export type AuditLimitations = {
  isPointInTimeAssessment: true;
  defensiveAssessmentOnly: true;
  noConfirmedVulnerabilities: true;
  noExploitabilityConfirmed: true;
  noSeverityRiskOrImpactClaims: true;
  noRemediationGuarantees: true;
  humanAuthorizedOnly: true;
};

export type DefensiveReportExplicitNonClaims = {
  noConfirmedFindings: true;
  noConfirmedVulnerabilities: true;
  noExploitabilityClaims: true;
  noSeverityClaims: true;
  noRiskScoreClaims: true;
  noCvssClaims: true;
  noRemediationAdvice: true;
  noAutonomousExploitation: true;
};

export type DefensiveAssessmentReport = {
  contractVersion: DefensiveReportContractVersion;
  kind: "defensive_assessment_report";
  reportId: string;
  sessionId: string;
  scanId: string;
  generatedAt: string;
  operatorAttestation: OperatorAttestation;
  auditLimitations: AuditLimitations;
  candidateCount: number;
  candidates: ReviewedEvidenceFormalFindingCandidate[];
  explicitNonClaims: DefensiveReportExplicitNonClaims;
};

export interface GenerateDefensiveReportCommand {
  reportId: string;
  sessionId: string;
  scanId: string;
  requestedAt: string;
  operatorSignatureId: string;
  operatorVerifiedAt: string;
  operatorAttestationText: string;
}

export type ReportGenerationErrorCode =
  | "missing_operator_signature"
  | "invalid_report_request"
  | "report_generation_aborted_corrupted_candidate"
  | "report_generation_aborted_insufficient_substance"
  | "report_validation_failed";

export class ReportGenerationError extends Error {
  constructor(
    public readonly code: ReportGenerationErrorCode,
    message: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(`[${code}] ${message}`);
    this.name = "ReportGenerationError";
  }
}

const UNSAFE_TERMS = [
  "authorization", "bearer", "cookie", "set-cookie", "password", "secret",
  "token", "api_key", "apikey", "access_token", "refresh_token",
  "raw_request", "raw response", "raw_body", "raw body", "raw_headers", "raw headers",
  "sqli", "idor", "bola", "auth bypass", "vulnerable", "exploit", "critical severity", "target is vulnerable"
];

function isSafeString(val: unknown): boolean {
  if (typeof val !== "string") return false;
  const lower = val.toLowerCase();
  return !UNSAFE_TERMS.some((term) => lower.includes(term));
}

export const FORBIDDEN_ATTESTATION_TERMS = [
  "bearer", "cookie", "set-cookie", "password", "secret",
  "api_key", "apikey", "access_token", "refresh_token",
  "raw_request", "raw_response", "raw_body", "raw_headers",
  "confirmed vulnerability", "target is vulnerable", "critical severity"
];

export function isSafeAttestationText(val: unknown): boolean {
  if (typeof val !== "string") return false;
  const lower = val.toLowerCase();
  return !FORBIDDEN_ATTESTATION_TERMS.some((term) => lower.includes(term));
}

export function isStrictSafeId(val: unknown): val is string {
  if (typeof val !== "string") return false;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(val)) return false;
  return isSafeString(val);
}

export function isStrictIsoTimestamp(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

const ALLOWED_REPORT_KEYS = new Set([
  "contractVersion",
  "kind",
  "reportId",
  "sessionId",
  "scanId",
  "generatedAt",
  "operatorAttestation",
  "auditLimitations",
  "candidateCount",
  "candidates",
  "explicitNonClaims"
]);

const FORBIDDEN_SPECULATIVE_KEYS = [
  "severity",
  "risk_score",
  "riskScore",
  "cvss",
  "cvss_score",
  "remediation",
  "remediation_advice",
  "remediationAdvice",
  "impact",
  "impact_score",
  "exploit",
  "exploitability"
];

export function validateDefensiveAssessmentReport(report: unknown): report is DefensiveAssessmentReport {
  if (!report || typeof report !== "object" || Array.isArray(report)) return false;

  const raw = report as Record<string, unknown>;

  // Check for any forbidden speculative keys at root level
  for (const forbidden of FORBIDDEN_SPECULATIVE_KEYS) {
    if (forbidden in raw) return false;
  }

  // Exact-key closed-world verification
  const keys = Object.keys(raw);
  if (keys.length !== 11) return false;
  for (const k of keys) {
    if (!ALLOWED_REPORT_KEYS.has(k)) return false;
  }

  if (raw.contractVersion !== "fixguard-defensive-assessment-report/v0") return false;
  if (raw.kind !== "defensive_assessment_report") return false;

  if (!isStrictSafeId(raw.reportId)) return false;
  if (!isStrictSafeId(raw.sessionId)) return false;
  if (!isStrictSafeId(raw.scanId)) return false;
  if (!isStrictIsoTimestamp(raw.generatedAt)) return false;

  // Operator attestation validation
  const att = raw.operatorAttestation;
  if (!att || typeof att !== "object" || Array.isArray(att)) return false;
  const attKeys = Object.keys(att);
  if (attKeys.length !== 3) return false;
  const attRecord = att as Record<string, unknown>;
  if (!isStrictSafeId(attRecord.operatorSignatureId)) return false;
  if (!isStrictIsoTimestamp(attRecord.verifiedAt)) return false;
  if (typeof attRecord.attestationText !== "string" || attRecord.attestationText.length < 10 || attRecord.attestationText.length > 500) {
    return false;
  }
  if (!isSafeAttestationText(attRecord.attestationText)) return false;

  // Audit limitations validation
  const lim = raw.auditLimitations;
  if (!lim || typeof lim !== "object" || Array.isArray(lim)) return false;
  const limKeys = Object.keys(lim);
  if (limKeys.length !== 7) return false;
  const limRecord = lim as Record<string, unknown>;
  if (
    limRecord.isPointInTimeAssessment !== true ||
    limRecord.defensiveAssessmentOnly !== true ||
    limRecord.noConfirmedVulnerabilities !== true ||
    limRecord.noExploitabilityConfirmed !== true ||
    limRecord.noSeverityRiskOrImpactClaims !== true ||
    limRecord.noRemediationGuarantees !== true ||
    limRecord.humanAuthorizedOnly !== true
  ) {
    return false;
  }

  // Explicit non-claims validation
  const nc = raw.explicitNonClaims;
  if (!nc || typeof nc !== "object" || Array.isArray(nc)) return false;
  const ncKeys = Object.keys(nc);
  if (ncKeys.length !== 8) return false;
  const ncRecord = nc as Record<string, unknown>;
  if (
    ncRecord.noConfirmedFindings !== true ||
    ncRecord.noConfirmedVulnerabilities !== true ||
    ncRecord.noExploitabilityClaims !== true ||
    ncRecord.noSeverityClaims !== true ||
    ncRecord.noRiskScoreClaims !== true ||
    ncRecord.noCvssClaims !== true ||
    ncRecord.noRemediationAdvice !== true ||
    ncRecord.noAutonomousExploitation !== true
  ) {
    return false;
  }

  // Candidates list validation
  if (!Array.isArray(raw.candidates)) return false;
  if (typeof raw.candidateCount !== "number" || !Number.isInteger(raw.candidateCount) || raw.candidateCount < 0) return false;
  if (raw.candidates.length !== raw.candidateCount) return false;

  for (const candidate of raw.candidates) {
    if (!validateReviewedEvidenceFormalFindingCandidate(candidate)) {
      return false;
    }
    // Scope boundary validation: every candidate must belong strictly to the report's scanId
    const candObj = candidate as { scanId?: unknown; lineage?: { scanId?: unknown } };
    if (candObj.scanId !== raw.scanId) {
      return false;
    }
    if (candObj.lineage?.scanId && candObj.lineage.scanId !== raw.scanId) {
      return false;
    }
  }

  return true;
}
