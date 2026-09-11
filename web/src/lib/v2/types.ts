/**
 * FixGuard V2 API Gateway Types & DTOs
 *
 * Strictly aligned with FixGuard V2 contracts (Layer 9 Reporting Boundary,
 * Layer 8 Candidate Draft & Promotion, Layer 7 Storage, Layer 4 Application).
 * Zero imports from legacy V1 models or Drizzle ORM.
 */

export interface AssessmentSummaryDto {
  sessionId: string;
  targetUri: string;
  lifecycleStatus: string;
  version: number;
  createdAt: string;
  updatedAt: string;
  evidenceCount: number;
  pendingRecommendationCount: number;
  approvedRequestCount: number;
  executionFailureCount: number;
  auditEntryCount: number;
}

export interface SafeFindingSummaryDto {
  id: string;
  type: string;
  severity: string;
  title: string;
  target: string;
  confidence: number;
}

export interface SafeRecommendationSummaryDto {
  id: string;
  capability: string;
  targetUri: string;
  rationale: string;
  riskLevel: string;
}

export interface AssessmentDetailsDto extends AssessmentSummaryDto {
  findings: SafeFindingSummaryDto[];
  pendingRecommendations: SafeRecommendationSummaryDto[];
  errors: string[];
}

export interface ReviewedEvidenceFindingCandidateDraftDto {
  contractVersion: 'fixguard-reviewed-evidence-finding-candidate-draft/v0';
  kind: 'reviewed_evidence_finding_candidate_draft';
  draftId: string;
  scanId: string;
  createdAt: string;
  sourceSelection: {
    selectionId: string;
    selectionMode: string;
    selectedCount: number;
    selectedRefs: Array<{
      storeRecordId: string;
      evidenceId: string;
      scanId: string;
      indicatorId?: string;
    }>;
  };
  observedEvidenceSummary: {
    evidenceTypeCounts: Record<string, number>;
    indicatorCounts?: Record<string, number>;
    distinctIndicatorCount?: number;
    hostCounts?: Record<string, number>;
    distinctHostCount?: number;
  };
  draftTriage: {
    triageState: string;
    confidenceState: string;
    humanReviewRequired: boolean;
  };
  draftLabels: {
    candidateKind: string;
    labelSource: string;
    [key: string]: unknown;
  };
  explicitNonClaims: Record<string, boolean>;
  classification: Record<string, boolean>;
}

export interface FormalFindingCandidateDto {
  contractVersion: 'fixguard-reviewed-evidence-formal-finding-candidate/v0';
  kind: 'reviewed_evidence_formal_finding_candidate';
  candidateId: string;
  scanId: string;
  draftId: string;
  createdAt: string;
  sourceSelection: {
    selectionId: string;
    selectionMode: string;
    selectedCount: number;
    selectedRefs: Array<{
      storeRecordId: string;
      evidenceId: string;
      scanId: string;
      indicatorId?: string;
    }>;
  };
  observedEvidenceSummary: {
    evidenceTypeCounts: Record<string, number>;
    indicatorCounts?: Record<string, number>;
    distinctIndicatorCount?: number;
    hostCounts?: Record<string, number>;
    distinctHostCount?: number;
  };
  triageAssessment: {
    decisionId: string;
    reviewerId: string;
    reviewedAt: string;
    disposition: string;
    justification?: string;
  };
  canonicalLabels: {
    candidateKind: string;
    labelSource: string;
    [key: string]: unknown;
  };
  explicitNonClaims: Record<string, boolean>;
  classification: Record<string, boolean>;
}

export interface DefensiveAssessmentReportDto {
  contractVersion: 'fixguard-defensive-assessment-report/v0';
  kind: 'defensive_assessment_report';
  reportId: string;
  assessmentId: string;
  scanId: string;
  generatedAt: string;
  operatorAttestation: {
    operatorSignatureId: string;
    verifiedAt: string;
    attestationText: string;
  };
  candidateCount: number;
  candidates: FormalFindingCandidateDto[];
  auditLimitations: {
    scopeBoundariesEnforced: boolean;
    egressFilteringActive: boolean;
    noAutonomousExploitation: boolean;
    humanAuthorizedOnly: boolean;
    disclaimerText: string;
  };
  explicitNonClaims: Record<string, boolean>;
}

export interface SafeErrorResponseBody {
  error: string;
  message: string;
  conflictKey?: string;
  sessionId?: string;
  recordId?: string;
}

export interface PromoteCandidateParams {
  candidateId: string;
  scanId: string;
  draftId: string;
  reviewerId: string;
  triageDecisionId: string;
}

export interface GenerateReportParams {
  reportId: string;
  sessionId: string;
  scanId: string;
  requestedAt: string;
  operatorSignatureId: string;
  operatorVerifiedAt: string;
  operatorAttestationText: string;
}

export interface ListEvidenceDraftsResponse {
  scanId: string;
  draftCount: number;
  drafts: ReviewedEvidenceFindingCandidateDraftDto[];
}

export interface PromoteCandidateResponse {
  status: string;
  reasonCode: string;
  candidate: FormalFindingCandidateDto;
}
