import type { 
  AssessmentState, 
  LifecycleState, 
  ApprovedRequestRecord, 
  ExecutionFailureRecord 
} from '../runtime/AssessmentState';
import type { EvidenceCollection } from '../core/Evidence';
import type { AuditEntry } from '../approval/ApprovalContracts';

export interface AssessmentSessionSummary {
  sessionId: string;
  targetUri: string;
  lifecycleStatus: LifecycleState;
  version: number;
  createdAt: number;
  updatedAt: number;
  findingCount?: number;
  pendingRecommendationCount?: number;
  executionFailureCount?: number;
}

export interface AssessmentSessionFilter {
  targetUri?: string;
  lifecycleStatus?: LifecycleState;
  createdAfter?: number;
  createdBefore?: number;
  updatedAfter?: number;
  updatedBefore?: number;
  limit?: number;
  offset?: number;
}

export interface SaveAssessmentStateInput {
  state: AssessmentState;
  expectedVersion?: number;
}

export interface AppendEvidenceInput {
  sessionId: string;
  evidence: EvidenceCollection;
  capability: string;
  recordedAt: number;
  sourceApprovedRequestRecordId?: string;
}

export interface AppendAuditEntryInput {
  sessionId: string;
  entry: AuditEntry;
  recordedAt: number;
}

export interface AppendApprovedRequestInput {
  sessionId: string;
  record: ApprovedRequestRecord;
  recordedAt: number;
}

export interface AppendExecutionFailureInput {
  sessionId: string;
  record: ExecutionFailureRecord;
  recordedAt: number;
}

export interface AssessmentRepository {
  saveAssessmentState(input: SaveAssessmentStateInput): Promise<void>;
  loadAssessmentState(sessionId: string): Promise<AssessmentState | undefined>;
  listSessions(filter?: AssessmentSessionFilter): Promise<AssessmentSessionSummary[]>;

  appendEvidence(input: AppendEvidenceInput): Promise<void>;
  appendAuditEntry(input: AppendAuditEntryInput): Promise<void>;
  appendApprovedRequest(input: AppendApprovedRequestInput): Promise<void>;
  appendExecutionFailure(input: AppendExecutionFailureInput): Promise<void>;

  listEvidence(sessionId: string): Promise<EvidenceCollection[]>;
  listAuditEntries(sessionId: string): Promise<AuditEntry[]>;
  listApprovedRequests(sessionId: string): Promise<ApprovedRequestRecord[]>;
  listExecutionFailures(sessionId: string): Promise<ExecutionFailureRecord[]>;
}
