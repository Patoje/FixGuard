import type { AttackRecommendation } from '../intelligence/AttackRecommendation';

export type ApprovalStatus = 'pending' | 'approved' | 'approved_with_overrides' | 'rejected';

export interface ApprovalDecision {
  recommendationId: string;
  status: ApprovalStatus;
  operatorId: string;
  decidedAt: number;
  configOverrides?: Record<string, unknown>;
  rejectionReason?: string;
}

export interface AuditEntry {
  id: string;
  recommendationId: string;
  decision: ApprovalDecision;
  sourceRecommendation: AttackRecommendation;
  recordedAt: number;
}
