import type { LifecycleState } from '../runtime/AssessmentState';

export interface CreateAssessmentCommand {
  targetUri: string;
}

export interface StartInitialReconCommand {
  sessionId: string;
}

export interface LoadAssessmentQuery {
  sessionId: string;
}

export interface ApproveRecommendationCommand {
  sessionId: string;
  recommendationId: string;
  operatorId: string;
  // Intentionally omitting optional overrides parameter for M24 safety.
}

export interface RejectRecommendationCommand {
  sessionId: string;
  recommendationId: string;
  operatorId: string;
  reason: string;
}

export interface CompleteAssessmentCommand {
  sessionId: string;
}

// ---------------------------------------------------------
// Result DTOs (Safe views of internal state)
// ---------------------------------------------------------

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
  riskLevel: string; // mapped from severity
}

export interface AssessmentSummaryDto {
  sessionId: string;
  targetUri: string;
  lifecycleStatus: LifecycleState;
  version: number;
  createdAt: number;
  updatedAt: number;
  evidenceCount: number;
  pendingRecommendationCount: number;
  approvedRequestCount: number;
  executionFailureCount: number;
  auditEntryCount: number;
}

export interface AssessmentDetailsDto extends AssessmentSummaryDto {
  findings: SafeFindingSummaryDto[];
  pendingRecommendations: SafeRecommendationSummaryDto[];
  errors: string[];
}
