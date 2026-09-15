/**
 * FixGuard V2 — Defensive HTML Report Generator Service (Milestone P2-6)
 *
 * Coordinates the construction of standalone, legally defensible, self-contained
 * defensive HTML assessment reports.
 *
 * Crucial Invariants:
 * 1. Operator Attestation Required: Strictly enforces authenticated operator signature
 *    and attestation statement (minimum 10 characters). Absent or blank attestations fail closed.
 * 2. Only Human-Approved Findings: Renders only confirmed Finding records. Unreviewed drafts
 *    are never rendered in findings tables.
 * 3. Mandatory Audit Limitations: Explicitly details scope constraints and defensive non-claims.
 * 4. Lineage Preservation: Renders the continuous lineage tuple for every reported finding.
 */

import type { OrchestratedAssessmentRecord } from '../application/OrchestratedAssessmentContracts.js';
import {
  ReportGenerationError,
  isStrictSafeId,
  isSafeAttestationText,
} from './DefensiveReportContracts.js';
import { isForbiddenSyntheticReviewerId } from '../api/validation/ApiRequestValidators.js';
import {
  buildReportStyles,
  buildHeaderSection,
  buildExecutiveSummarySection,
  buildAuditLimitationsSection,
  buildConfirmedFindingsSection,
  buildRecommendationsSection,
  buildOperatorAttestationSection,
} from './ReportSectionBuilders.js';

export interface GenerateHtmlReportParams {
  readonly assessmentRecord: OrchestratedAssessmentRecord;
  readonly operatorId: string;
  readonly attestationText: string;
  readonly verifiedAt?: string;
}

export class ReportGeneratorService {
  /**
   * Generates a complete standalone HTML defensive assessment report.
   */
  public generateHtmlReport(params: GenerateHtmlReportParams): string {
    const { assessmentRecord, operatorId, attestationText } = params;

    if (!assessmentRecord || typeof assessmentRecord !== 'object') {
      throw new ReportGenerationError(
        'invalid_report_request',
        'Parameter assessmentRecord must be a valid OrchestratedAssessmentRecord'
      );
    }

    // 1. Mandatory Operator Signature Validation
    if (!operatorId || typeof operatorId !== 'string' || operatorId.trim().length === 0) {
      throw new ReportGenerationError(
        'missing_operator_signature',
        'Field operatorId is mandatory and cannot be empty or omitted'
      );
    }

    const trimmedOperatorId = operatorId.trim();
    if (!isStrictSafeId(trimmedOperatorId)) {
      throw new ReportGenerationError(
        'invalid_report_request',
        'Field operatorId must satisfy strict identifier format'
      );
    }

    if (isForbiddenSyntheticReviewerId(trimmedOperatorId)) {
      throw new ReportGenerationError(
        'invalid_report_request',
        `Field operatorId contains forbidden synthetic reviewer pattern '${trimmedOperatorId}'`
      );
    }

    // 2. Mandatory Operator Attestation Text Validation (Min 10 characters)
    if (!attestationText || typeof attestationText !== 'string' || attestationText.trim().length === 0) {
      throw new ReportGenerationError(
        'invalid_report_request',
        'Field attestationText is mandatory and cannot be empty or omitted'
      );
    }

    const trimmedAttestation = attestationText.trim();
    if (trimmedAttestation.length < 10) {
      throw new ReportGenerationError(
        'invalid_report_request',
        'Field attestationText must contain at least 10 characters'
      );
    }

    if (trimmedAttestation.length > 1000) {
      throw new ReportGenerationError(
        'invalid_report_request',
        'Field attestationText exceeds maximum length of 1000 characters'
      );
    }

    if (!isSafeAttestationText(trimmedAttestation)) {
      throw new ReportGenerationError(
        'invalid_report_request',
        'Field attestationText contains forbidden or unsafe terms'
      );
    }

    const verifiedAt = params.verifiedAt ?? new Date().toISOString();

    // 3. Assemble HTML Sections
    const styles = buildReportStyles();
    const headerHtml = buildHeaderSection(assessmentRecord);
    const summaryHtml = buildExecutiveSummarySection(assessmentRecord);
    const limitationsHtml = buildAuditLimitationsSection();
    const findingsHtml = buildConfirmedFindingsSection(
      assessmentRecord.findings || [],
      assessmentRecord.lineage
    );
    const recommendationsHtml = buildRecommendationsSection(
      assessmentRecord.recommendations || []
    );
    const attestationHtml = buildOperatorAttestationSection({
      operatorId: trimmedOperatorId,
      verifiedAt,
      attestationText: trimmedAttestation,
    });

    const targetTitle = assessmentRecord.targetDomain;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FixGuard V2 Defensive Security Report — ${targetTitle}</title>
  <style>
${styles}
  </style>
</head>
<body>
  <div class="report-container">
    ${headerHtml}
    ${summaryHtml}
    ${limitationsHtml}
    ${findingsHtml}
    ${recommendationsHtml}
    ${attestationHtml}
    <footer class="footer">
      Generated by FixGuard V2 Defensive Security Assessment Engine • Autonomous Invariant: Tools execute. Intelligence decides. Humans authorize.
    </footer>
  </div>
</body>
</html>`;
  }
}

export function validateOperatorAttestation(attestationText: string): void {
  if (!attestationText || typeof attestationText !== 'string' || attestationText.trim().length === 0) {
    throw new ReportGenerationError(
      'missing_operator_signature',
      'Field attestationText is mandatory and cannot be empty or omitted'
    );
  }

  const trimmed = attestationText.trim();
  if (trimmed.length < 10) {
    throw new ReportGenerationError(
      'missing_operator_signature',
      'Field attestationText must contain at least 10 characters'
    );
  }

  if (trimmed.length > 1000) {
    throw new ReportGenerationError(
      'invalid_report_request',
      'Field attestationText exceeds maximum length of 1000 characters'
    );
  }

  if (!isSafeAttestationText(trimmed)) {
    throw new ReportGenerationError(
      'invalid_report_request',
      'Field attestationText contains forbidden or unsafe terms'
    );
  }
}

export function generateDefensiveHtmlReport(params: {
  record: OrchestratedAssessmentRecord;
  operatorId: string;
  attestationText: string;
  generatedAt?: string;
}): string {
  const service = new ReportGeneratorService();
  return service.generateHtmlReport({
    assessmentRecord: params.record,
    operatorId: params.operatorId,
    attestationText: params.attestationText,
    verifiedAt: params.generatedAt,
  });
}
