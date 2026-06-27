import type {
  AssessmentRepository,
  AssessmentSessionSummary,
  AssessmentSessionFilter,
  SaveAssessmentStateInput,
  AppendEvidenceInput,
  AppendAuditEntryInput,
  AppendApprovedRequestInput,
  AppendExecutionFailureInput
} from './AssessmentRepository';
import { StaleStateError } from './StorageErrors';
import type { 
  AssessmentState,
  ApprovedRequestRecord,
  ExecutionFailureRecord
} from '../runtime/AssessmentState';
import type { EvidenceCollection } from '../core/Evidence';
import type { AuditEntry } from '../approval/ApprovalContracts';

export class InMemoryAssessmentRepository implements AssessmentRepository {
  private readonly states = new Map<string, AssessmentState>();
  private readonly evidence = new Map<string, EvidenceCollection[]>();
  private readonly auditEntries = new Map<string, AuditEntry[]>();
  private readonly approvedRequests = new Map<string, ApprovedRequestRecord[]>();
  private readonly executionFailures = new Map<string, ExecutionFailureRecord[]>();

  private clone<T>(value: T): T {
    return JSON.parse(JSON.stringify(value));
  }

  public async saveAssessmentState(input: SaveAssessmentStateInput): Promise<void> {
    const sessionId = input.state.sessionId;
    const currentState = this.states.get(sessionId);

    if (input.expectedVersion !== undefined) {
      if (!currentState) {
        if (input.expectedVersion !== 0) {
          throw new StaleStateError(sessionId, input.expectedVersion, 0, `Stale state: expected version ${input.expectedVersion} but session does not exist`);
        }
      } else {
        if (currentState.version !== input.expectedVersion) {
          throw new StaleStateError(sessionId, input.expectedVersion, currentState.version, `Stale state: expected version ${input.expectedVersion} but found ${currentState.version}`);
        }
      }
    }

    this.states.set(sessionId, this.clone(input.state));
  }

  public async loadAssessmentState(sessionId: string): Promise<AssessmentState | undefined> {
    const state = this.states.get(sessionId);
    if (!state) return undefined;
    return this.clone(state);
  }

  public async listSessions(filter?: AssessmentSessionFilter): Promise<AssessmentSessionSummary[]> {
    let results: AssessmentSessionSummary[] = [];

    for (const state of this.states.values()) {
      let findingCount = 0;
      for (const ec of state.evidenceCollections) {
        findingCount += ec.findings.length;
      }

      results.push({
        sessionId: state.sessionId,
        targetUri: state.targetUri,
        lifecycleStatus: state.lifecycleStatus,
        version: state.version,
        createdAt: state.timestamps.created,
        updatedAt: state.timestamps.lastUpdated,
        findingCount,
        pendingRecommendationCount: state.pendingRecommendations.length,
        executionFailureCount: state.executionFailures.length
      });
    }

    if (filter) {
      if (filter.targetUri) {
        results = results.filter(s => s.targetUri === filter.targetUri);
      }
      if (filter.lifecycleStatus) {
        results = results.filter(s => s.lifecycleStatus === filter.lifecycleStatus);
      }
      if (filter.createdAfter !== undefined) {
        results = results.filter(s => s.createdAt > filter.createdAfter!);
      }
      if (filter.createdBefore !== undefined) {
        results = results.filter(s => s.createdAt < filter.createdBefore!);
      }
      if (filter.updatedAfter !== undefined) {
        results = results.filter(s => s.updatedAt > filter.updatedAfter!);
      }
      if (filter.updatedBefore !== undefined) {
        results = results.filter(s => s.updatedAt < filter.updatedBefore!);
      }
      if (filter.offset !== undefined) {
        results = results.slice(filter.offset);
      }
      if (filter.limit !== undefined) {
        results = results.slice(0, filter.limit);
      }
    }

    return results;
  }

  public async appendEvidence(input: AppendEvidenceInput): Promise<void> {
    if (!input.sessionId) throw new Error('sessionId required');
    const list = this.evidence.get(input.sessionId) || [];
    list.push(this.clone(input.evidence));
    this.evidence.set(input.sessionId, list);
  }

  public async appendAuditEntry(input: AppendAuditEntryInput): Promise<void> {
    if (!input.sessionId) throw new Error('sessionId required');
    const list = this.auditEntries.get(input.sessionId) || [];
    list.push(this.clone(input.entry));
    this.auditEntries.set(input.sessionId, list);
  }

  public async appendApprovedRequest(input: AppendApprovedRequestInput): Promise<void> {
    if (!input.sessionId) throw new Error('sessionId required');
    const list = this.approvedRequests.get(input.sessionId) || [];
    list.push(this.clone(input.record));
    this.approvedRequests.set(input.sessionId, list);
  }

  public async appendExecutionFailure(input: AppendExecutionFailureInput): Promise<void> {
    if (!input.sessionId) throw new Error('sessionId required');
    const list = this.executionFailures.get(input.sessionId) || [];
    list.push(this.clone(input.record));
    this.executionFailures.set(input.sessionId, list);
  }

  public async listEvidence(sessionId: string): Promise<EvidenceCollection[]> {
    return this.clone(this.evidence.get(sessionId) || []);
  }

  public async listAuditEntries(sessionId: string): Promise<AuditEntry[]> {
    return this.clone(this.auditEntries.get(sessionId) || []);
  }

  public async listApprovedRequests(sessionId: string): Promise<ApprovedRequestRecord[]> {
    return this.clone(this.approvedRequests.get(sessionId) || []);
  }

  public async listExecutionFailures(sessionId: string): Promise<ExecutionFailureRecord[]> {
    return this.clone(this.executionFailures.get(sessionId) || []);
  }
}
