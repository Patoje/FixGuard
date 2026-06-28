import { eq, and, asc, sql } from 'drizzle-orm';
import crypto from 'node:crypto';
import type { 
  AssessmentRepository,
  AssessmentSessionSummary,
  AssessmentSessionFilter,
  SaveAssessmentStateInput,
  AppendEvidenceInput,
  AppendAuditEntryInput,
  AppendApprovedRequestInput,
  AppendExecutionFailureInput
} from '../AssessmentRepository';
import { StaleStateError } from '../StorageErrors';
import type { AssessmentState } from '../../runtime/AssessmentState';
import type { EvidenceCollection } from '../../core/Evidence';
import type { AuditEntry } from '../../approval/ApprovalContracts';
import type { ApprovedRequestRecord, ExecutionFailureRecord } from '../../runtime/AssessmentState';

import {
  v2_assessment_sessions,
  v2_evidence_records,
  v2_audit_entries,
  v2_approved_request_records,
  v2_execution_failure_records
} from './schema';

const FORBIDDEN_KEYS = new Set([
  'binary', 'args', 'env', 'command', 'shell', 'stdin', 
  'executionRequest', 'capabilityRequest', 'execution_request', 'capability_request'
]);

function validateNoExecutableKeys(obj: unknown): void {
  if (obj === null || typeof obj !== 'object') return;
  if (Array.isArray(obj)) {
    for (const item of obj) validateNoExecutableKeys(item);
    return;
  }
  for (const key of Object.keys(obj)) {
    if (FORBIDDEN_KEYS.has(key)) {
      throw new Error(`Persistence validation failed: Executable key '${key}' is forbidden`);
    }
    validateNoExecutableKeys((obj as Record<string, unknown>)[key]);
  }
}

function cloneAndValidate<T>(obj: T): T {
  validateNoExecutableKeys(obj);
  return JSON.parse(JSON.stringify(obj));
}

function clone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

// Minimal type for generic DB
type GenericDb = any;

export class PostgresAssessmentRepository implements AssessmentRepository {
  constructor(private readonly db: GenericDb) {}

  public async saveAssessmentState(input: SaveAssessmentStateInput): Promise<void> {
    const sessionId = input.state.sessionId;
    const clonedState = cloneAndValidate(input.state);

    let findingCount = 0;
    for (const ec of clonedState.evidenceCollections) {
      findingCount += ec.findings.length;
    }

    if (input.expectedVersion === 0) {
      // Must not exist
      // Must not exist
      const result = await this.db.insert(v2_assessment_sessions)
        .values({
          session_id: sessionId,
          target_uri: clonedState.targetUri,
          lifecycle_status: clonedState.lifecycleStatus,
          version: clonedState.version,
          created_at_ms: clonedState.timestamps.created,
          updated_at_ms: clonedState.timestamps.lastUpdated,
          finding_count: findingCount,
          pending_recommendation_count: clonedState.pendingRecommendations.length,
          execution_failure_count: clonedState.executionFailures.length,
          state_json: clonedState
        })
        .onConflictDoNothing()
        .returning({ sessionId: v2_assessment_sessions.session_id });

      if (result.length === 0) {
        const rows = await this.db
          .select({ version: v2_assessment_sessions.version })
          .from(v2_assessment_sessions)
          .where(eq(v2_assessment_sessions.session_id, sessionId));
        
        const actualVersion = rows.length > 0 ? rows[0].version : -1;
        throw new StaleStateError(sessionId, 0, actualVersion, `Stale state: expected version 0 but found ${actualVersion}`);
      }
    } else if (input.expectedVersion !== undefined) {
      // Update existing
      const result = await this.db.update(v2_assessment_sessions)
        .set({
          target_uri: clonedState.targetUri,
          lifecycle_status: clonedState.lifecycleStatus,
          version: clonedState.version,
          created_at_ms: clonedState.timestamps.created,
          updated_at_ms: clonedState.timestamps.lastUpdated,
          finding_count: findingCount,
          pending_recommendation_count: clonedState.pendingRecommendations.length,
          execution_failure_count: clonedState.executionFailures.length,
          state_json: clonedState
        })
        .where(
          and(
            eq(v2_assessment_sessions.session_id, sessionId),
            eq(v2_assessment_sessions.version, input.expectedVersion)
          )
        )
        .returning({ sessionId: v2_assessment_sessions.session_id });
      
      if (result.length === 0) {
        const rows = await this.db
          .select({ version: v2_assessment_sessions.version })
          .from(v2_assessment_sessions)
          .where(eq(v2_assessment_sessions.session_id, sessionId));
        
        if (rows.length === 0) {
          throw new StaleStateError(sessionId, input.expectedVersion, 0, `Stale state: expected version ${input.expectedVersion} but session does not exist`);
        }
        throw new StaleStateError(sessionId, input.expectedVersion, rows[0].version, `Stale state: expected version ${input.expectedVersion} but found ${rows[0].version}`);
      }
    } else {
      // Upsert (expectedVersion undefined)
      await this.db.insert(v2_assessment_sessions)
        .values({
          session_id: sessionId,
          target_uri: clonedState.targetUri,
          lifecycle_status: clonedState.lifecycleStatus,
          version: clonedState.version,
          created_at_ms: clonedState.timestamps.created,
          updated_at_ms: clonedState.timestamps.lastUpdated,
          finding_count: findingCount,
          pending_recommendation_count: clonedState.pendingRecommendations.length,
          execution_failure_count: clonedState.executionFailures.length,
          state_json: clonedState
        })
        .onConflictDoUpdate({
          target: v2_assessment_sessions.session_id,
          set: {
            target_uri: clonedState.targetUri,
            lifecycle_status: clonedState.lifecycleStatus,
            version: clonedState.version,
            created_at_ms: clonedState.timestamps.created,
            updated_at_ms: clonedState.timestamps.lastUpdated,
            finding_count: findingCount,
            pending_recommendation_count: clonedState.pendingRecommendations.length,
            execution_failure_count: clonedState.executionFailures.length,
            state_json: clonedState
          }
        });
    }
  }

  public async loadAssessmentState(sessionId: string): Promise<AssessmentState | undefined> {
    const rows = await this.db
      .select({ state_json: v2_assessment_sessions.state_json })
      .from(v2_assessment_sessions)
      .where(eq(v2_assessment_sessions.session_id, sessionId));
      
    if (rows.length === 0) return undefined;
    
    return clone(rows[0].state_json);
  }

  public async listSessions(filter?: AssessmentSessionFilter): Promise<AssessmentSessionSummary[]> {
    let query = this.db
      .select({
        sessionId: v2_assessment_sessions.session_id,
        targetUri: v2_assessment_sessions.target_uri,
        lifecycleStatus: v2_assessment_sessions.lifecycle_status,
        version: v2_assessment_sessions.version,
        createdAt: v2_assessment_sessions.created_at_ms,
        updatedAt: v2_assessment_sessions.updated_at_ms,
        findingCount: v2_assessment_sessions.finding_count,
        pendingRecommendationCount: v2_assessment_sessions.pending_recommendation_count,
        executionFailureCount: v2_assessment_sessions.execution_failure_count
      })
      .from(v2_assessment_sessions)
      .$dynamic();

    const conditions = [];

    if (filter) {
      if (filter.targetUri) {
        conditions.push(eq(v2_assessment_sessions.target_uri, filter.targetUri));
      }
      if (filter.lifecycleStatus) {
        conditions.push(eq(v2_assessment_sessions.lifecycle_status, filter.lifecycleStatus));
      }
      if (filter.createdAfter !== undefined) {
        conditions.push(sql`${v2_assessment_sessions.created_at_ms} > ${filter.createdAfter}`);
      }
      if (filter.createdBefore !== undefined) {
        conditions.push(sql`${v2_assessment_sessions.created_at_ms} < ${filter.createdBefore}`);
      }
      if (filter.updatedAfter !== undefined) {
        conditions.push(sql`${v2_assessment_sessions.updated_at_ms} > ${filter.updatedAfter}`);
      }
      if (filter.updatedBefore !== undefined) {
        conditions.push(sql`${v2_assessment_sessions.updated_at_ms} < ${filter.updatedBefore}`);
      }
    }

    if (conditions.length > 0) {
      query = query.where(and(...conditions));
    }

    query = query.orderBy(asc(v2_assessment_sessions.created_at_ms), asc(v2_assessment_sessions.session_id));

    if (filter?.limit !== undefined) {
      query = query.limit(filter.limit);
    }
    if (filter?.offset !== undefined) {
      query = query.offset(filter.offset);
    }

    const rows = await query;

    return rows.map((r: any) => ({
      sessionId: r.sessionId,
      targetUri: r.targetUri,
      lifecycleStatus: r.lifecycleStatus,
      version: r.version,
      createdAt: Number(r.createdAt),
      updatedAt: Number(r.updatedAt),
      findingCount: r.findingCount,
      pendingRecommendationCount: r.pendingRecommendationCount,
      executionFailureCount: r.executionFailureCount
    }));
  }

  public async appendEvidence(input: AppendEvidenceInput): Promise<void> {
    const payload = cloneAndValidate(input.evidence);
    
    // In EvidenceCollection, there is no ID at the root, so we just generate one for the row
    const rowId = crypto.randomUUID();

    await this.db.insert(v2_evidence_records).values({
      id: rowId,
      session_id: input.sessionId,
      capability: input.capability,
      recorded_at_ms: input.recordedAt,
      source_approved_request_record_id: input.sourceApprovedRequestRecordId ?? null,
      finding_count: payload.findings.length,
      evidence_json: payload
    });
  }

  public async appendAuditEntry(input: AppendAuditEntryInput): Promise<void> {
    const payload = cloneAndValidate(input.entry);
    const rowId = payload.id || crypto.randomUUID();

    await this.db.insert(v2_audit_entries).values({
      id: rowId,
      session_id: input.sessionId,
      recommendation_id: payload.recommendationId ?? null,
      decision: payload.decision?.status ?? null,
      recorded_at_ms: input.recordedAt,
      entry_json: payload
    });
  }

  public async appendApprovedRequest(input: AppendApprovedRequestInput): Promise<void> {
    const payload = cloneAndValidate(input.record);
    const rowId = payload.id || crypto.randomUUID();

    await this.db.insert(v2_approved_request_records).values({
      id: rowId,
      session_id: input.sessionId,
      recommendation_id: payload.recommendationId,
      capability: payload.capability,
      target_uri: payload.targetUri,
      operator_id: payload.operatorId,
      source_recommendation_id: payload.sourceRecommendationId ?? null,
      approved_at_ms: input.recordedAt,
      request_summary_json: payload.requestSummary ?? {},
      record_json: payload
    });
  }

  public async appendExecutionFailure(input: AppendExecutionFailureInput): Promise<void> {
    const payload = cloneAndValidate(input.record);
    const rowId = payload.id || crypto.randomUUID();

    await this.db.insert(v2_execution_failure_records).values({
      id: rowId,
      session_id: input.sessionId,
      capability: payload.capability,
      target_uri: payload.targetUri,
      failed_at_ms: input.recordedAt,
      recoverable: payload.recoverable,
      source_recommendation_id: payload.sourceRecommendationId ?? null,
      lifecycle_status_at_failure: payload.lifecycleStatusAtFailure,
      error_message: payload.errorMessage,
      record_json: payload
    });
  }

  public async listEvidence(sessionId: string): Promise<EvidenceCollection[]> {
    const rows = await this.db
      .select({ evidence_json: v2_evidence_records.evidence_json })
      .from(v2_evidence_records)
      .where(eq(v2_evidence_records.session_id, sessionId))
      .orderBy(asc(v2_evidence_records.insertion_order));
    
    return rows.map((r: any) => clone(r.evidence_json));
  }

  public async listAuditEntries(sessionId: string): Promise<AuditEntry[]> {
    const rows = await this.db
      .select({ entry_json: v2_audit_entries.entry_json })
      .from(v2_audit_entries)
      .where(eq(v2_audit_entries.session_id, sessionId))
      .orderBy(asc(v2_audit_entries.insertion_order));
    
    return rows.map((r: any) => clone(r.entry_json));
  }

  public async listApprovedRequests(sessionId: string): Promise<ApprovedRequestRecord[]> {
    const rows = await this.db
      .select({ record_json: v2_approved_request_records.record_json })
      .from(v2_approved_request_records)
      .where(eq(v2_approved_request_records.session_id, sessionId))
      .orderBy(asc(v2_approved_request_records.insertion_order));
    
    return rows.map((r: any) => clone(r.record_json));
  }

  public async listExecutionFailures(sessionId: string): Promise<ExecutionFailureRecord[]> {
    const rows = await this.db
      .select({ record_json: v2_execution_failure_records.record_json })
      .from(v2_execution_failure_records)
      .where(eq(v2_execution_failure_records.session_id, sessionId))
      .orderBy(asc(v2_execution_failure_records.insertion_order));
    
    return rows.map((r: any) => clone(r.record_json));
  }
}
