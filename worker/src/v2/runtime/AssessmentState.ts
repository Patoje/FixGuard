import type { EvidenceCollection } from '../core/Evidence';
import type { TargetProfile } from '../intelligence/TargetProfile';
import type { AttackRecommendation } from '../intelligence/AttackRecommendation';
import type { AuditEntry } from '../approval/ApprovalContracts';

export type LifecycleState =
  | 'initialized'
  | 'initial_execution_running'
  | 'intelligence_running'
  | 'awaiting_approval'
  | 'approved_execution_running'
  | 'profile_updated'
  | 'completed'
  | 'failed';

export interface ApprovedRequestRecord {
  id: string;
  recommendationId: string;
  capability: string;
  targetUri: string;
  approvedAt: number;
  operatorId: string;
  sourceRecommendationId: string;
  requestSummary: Record<string, unknown>;
}

export interface ExecutionFailureRecord {
  id: string;
  capability: string;
  targetUri: string;
  failedAt: number;
  errorMessage: string;
  recoverable: boolean;
  sourceRecommendationId?: string;
  lifecycleStatusAtFailure: LifecycleState;
}

export interface AssessmentState {
  sessionId: string;
  targetUri: string;
  lifecycleStatus: LifecycleState;
  evidenceCollections: EvidenceCollection[];
  currentProfile: TargetProfile | null;
  pendingRecommendations: AttackRecommendation[];
  approvedRequestRecords: ApprovedRequestRecord[];
  executionFailures: ExecutionFailureRecord[];
  auditEntries: AuditEntry[];
  errors: string[];
  timestamps: {
    created: number;
    lastUpdated: number;
  };
  version: number;
}
