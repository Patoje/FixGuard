import { 
  pgTable, 
  text, 
  integer, 
  bigint, 
  jsonb, 
  boolean,
  index,
  serial,
  timestamp
} from 'drizzle-orm/pg-core';
import type { 
  AssessmentState, 
  ApprovedRequestRecord, 
  ExecutionFailureRecord 
} from '../../runtime/AssessmentState';
import type { EvidenceCollection } from '../../core/Evidence';
import type { AuditEntry } from '../../approval/ApprovalContracts';
import type { PersistedActiveReconRunRecord } from '../../recon/active/ActiveReconOriginRunPersistenceContracts';

export const v2_active_recon_run_records = pgTable('v2_active_recon_run_records', {
  run_id: text('run_id').primaryKey(),
  record_version: text('record_version').notNull(),
  record_kind: text('record_kind').notNull(),
  subject_kind: text('subject_kind').notNull(),
  normalized_origin: text('normalized_origin'),
  status: text('status').notNull(),
  record_json: jsonb('record_json').$type<PersistedActiveReconRunRecord>().notNull(),
  created_at: timestamp('created_at', { withTimezone: true }).notNull(),
  updated_at: timestamp('updated_at', { withTimezone: true }).notNull(),
}, (table) => ({
  recordKindIdx: index('idx_v2_arr_record_kind').on(table.record_kind),
  normalizedOriginIdx: index('idx_v2_arr_normalized_origin').on(table.normalized_origin),
  statusIdx: index('idx_v2_arr_status').on(table.status),
}));

export type V2ActiveReconRunRecordRow = typeof v2_active_recon_run_records.$inferSelect;
export type NewV2ActiveReconRunRecordRow = typeof v2_active_recon_run_records.$inferInsert;

export const v2_assessment_sessions = pgTable('v2_assessment_sessions', {
  session_id: text('session_id').primaryKey(),
  target_uri: text('target_uri').notNull(),
  lifecycle_status: text('lifecycle_status').notNull(),
  version: integer('version').notNull(),
  created_at_ms: bigint('created_at_ms', { mode: 'number' }).notNull(),
  updated_at_ms: bigint('updated_at_ms', { mode: 'number' }).notNull(),
  finding_count: integer('finding_count').notNull().default(0),
  pending_recommendation_count: integer('pending_recommendation_count').notNull().default(0),
  execution_failure_count: integer('execution_failure_count').notNull().default(0),
  state_json: jsonb('state_json').$type<AssessmentState>().notNull()
}, (table) => ({
  targetUriIdx: index('idx_v2_sessions_target_uri').on(table.target_uri),
  lifecycleStatusIdx: index('idx_v2_sessions_lifecycle_status').on(table.lifecycle_status),
  createdAtMsIdx: index('idx_v2_sessions_created_at_ms').on(table.created_at_ms),
  updatedAtMsIdx: index('idx_v2_sessions_updated_at_ms').on(table.updated_at_ms),
  targetUriLifecycleIdx: index('idx_v2_sessions_target_uri_lifecycle').on(table.target_uri, table.lifecycle_status)
}));

export type V2AssessmentSessionRow = typeof v2_assessment_sessions.$inferSelect;
export type NewV2AssessmentSessionRow = typeof v2_assessment_sessions.$inferInsert;

export const v2_evidence_records = pgTable('v2_evidence_records', {
  id: text('id').primaryKey(),
  session_id: text('session_id').notNull().references(() => v2_assessment_sessions.session_id, { onDelete: 'cascade' }),
  capability: text('capability').notNull(),
  recorded_at_ms: bigint('recorded_at_ms', { mode: 'number' }).notNull(),
  source_approved_request_record_id: text('source_approved_request_record_id'),
  finding_count: integer('finding_count').notNull().default(0),
  insertion_order: serial('insertion_order').notNull(),
  evidence_json: jsonb('evidence_json').$type<EvidenceCollection>().notNull()
}, (table) => ({
  sessionIdIdx: index('idx_v2_evidence_session_id').on(table.session_id),
  sessionInsertionOrderIdx: index('idx_v2_evidence_session_insertion_order').on(table.session_id, table.insertion_order),
  sessionRecordedAtIdx: index('idx_v2_evidence_session_recorded_at').on(table.session_id, table.recorded_at_ms),
  sessionCapabilityIdx: index('idx_v2_evidence_session_capability').on(table.session_id, table.capability)
}));

export type V2EvidenceRecordRow = typeof v2_evidence_records.$inferSelect;
export type NewV2EvidenceRecordRow = typeof v2_evidence_records.$inferInsert;

export const v2_audit_entries = pgTable('v2_audit_entries', {
  id: text('id').primaryKey(),
  session_id: text('session_id').notNull().references(() => v2_assessment_sessions.session_id, { onDelete: 'cascade' }),
  recommendation_id: text('recommendation_id'),
  decision: text('decision'),
  recorded_at_ms: bigint('recorded_at_ms', { mode: 'number' }).notNull(),
  insertion_order: serial('insertion_order').notNull(),
  entry_json: jsonb('entry_json').$type<AuditEntry>().notNull()
}, (table) => ({
  sessionIdIdx: index('idx_v2_audit_session_id').on(table.session_id),
  sessionInsertionOrderIdx: index('idx_v2_audit_session_insertion_order').on(table.session_id, table.insertion_order),
  sessionRecordedAtIdx: index('idx_v2_audit_session_recorded_at').on(table.session_id, table.recorded_at_ms)
}));

export type V2AuditEntryRow = typeof v2_audit_entries.$inferSelect;
export type NewV2AuditEntryRow = typeof v2_audit_entries.$inferInsert;

export const v2_approved_request_records = pgTable('v2_approved_request_records', {
  id: text('id').primaryKey(),
  session_id: text('session_id').notNull().references(() => v2_assessment_sessions.session_id, { onDelete: 'cascade' }),
  recommendation_id: text('recommendation_id').notNull(),
  capability: text('capability').notNull(),
  target_uri: text('target_uri').notNull(),
  operator_id: text('operator_id').notNull(),
  source_recommendation_id: text('source_recommendation_id'),
  approved_at_ms: bigint('approved_at_ms', { mode: 'number' }).notNull(),
  request_summary_json: jsonb('request_summary_json').notNull(),
  insertion_order: serial('insertion_order').notNull(),
  record_json: jsonb('record_json').$type<ApprovedRequestRecord>().notNull()
}, (table) => ({
  sessionIdIdx: index('idx_v2_approved_session_id').on(table.session_id),
  sessionInsertionOrderIdx: index('idx_v2_approved_session_insertion_order').on(table.session_id, table.insertion_order),
  sessionApprovedAtIdx: index('idx_v2_approved_session_approved_at').on(table.session_id, table.approved_at_ms),
  sessionCapabilityIdx: index('idx_v2_approved_session_capability').on(table.session_id, table.capability)
}));

export type V2ApprovedRequestRecordRow = typeof v2_approved_request_records.$inferSelect;
export type NewV2ApprovedRequestRecordRow = typeof v2_approved_request_records.$inferInsert;

export const v2_execution_failure_records = pgTable('v2_execution_failure_records', {
  id: text('id').primaryKey(),
  session_id: text('session_id').notNull().references(() => v2_assessment_sessions.session_id, { onDelete: 'cascade' }),
  capability: text('capability').notNull(),
  target_uri: text('target_uri').notNull(),
  failed_at_ms: bigint('failed_at_ms', { mode: 'number' }).notNull(),
  recoverable: boolean('recoverable').notNull(),
  source_recommendation_id: text('source_recommendation_id'),
  lifecycle_status_at_failure: text('lifecycle_status_at_failure').notNull(),
  error_message: text('error_message').notNull(),
  insertion_order: serial('insertion_order').notNull(),
  record_json: jsonb('record_json').$type<ExecutionFailureRecord>().notNull()
}, (table) => ({
  sessionIdIdx: index('idx_v2_failure_session_id').on(table.session_id),
  sessionInsertionOrderIdx: index('idx_v2_failure_session_insertion_order').on(table.session_id, table.insertion_order),
  sessionFailedAtIdx: index('idx_v2_failure_session_failed_at').on(table.session_id, table.failed_at_ms),
  sessionCapabilityIdx: index('idx_v2_failure_session_capability').on(table.session_id, table.capability),
  sessionRecoverableIdx: index('idx_v2_failure_session_recoverable').on(table.session_id, table.recoverable)
}));

export type V2ExecutionFailureRecordRow = typeof v2_execution_failure_records.$inferSelect;
export type NewV2ExecutionFailureRecordRow = typeof v2_execution_failure_records.$inferInsert;
