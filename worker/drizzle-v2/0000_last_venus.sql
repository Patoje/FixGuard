CREATE TABLE "v2_approved_request_records" (
	"id" text PRIMARY KEY NOT NULL,
	"session_id" text NOT NULL,
	"recommendation_id" text NOT NULL,
	"capability" text NOT NULL,
	"target_uri" text NOT NULL,
	"operator_id" text NOT NULL,
	"source_recommendation_id" text,
	"approved_at_ms" bigint NOT NULL,
	"request_summary_json" jsonb NOT NULL,
	"insertion_order" serial NOT NULL,
	"record_json" jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "v2_assessment_sessions" (
	"session_id" text PRIMARY KEY NOT NULL,
	"target_uri" text NOT NULL,
	"lifecycle_status" text NOT NULL,
	"version" integer NOT NULL,
	"created_at_ms" bigint NOT NULL,
	"updated_at_ms" bigint NOT NULL,
	"finding_count" integer DEFAULT 0 NOT NULL,
	"pending_recommendation_count" integer DEFAULT 0 NOT NULL,
	"execution_failure_count" integer DEFAULT 0 NOT NULL,
	"state_json" jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "v2_audit_entries" (
	"id" text PRIMARY KEY NOT NULL,
	"session_id" text NOT NULL,
	"recommendation_id" text,
	"decision" text,
	"recorded_at_ms" bigint NOT NULL,
	"insertion_order" serial NOT NULL,
	"entry_json" jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "v2_evidence_records" (
	"id" text PRIMARY KEY NOT NULL,
	"session_id" text NOT NULL,
	"capability" text NOT NULL,
	"recorded_at_ms" bigint NOT NULL,
	"source_approved_request_record_id" text,
	"finding_count" integer DEFAULT 0 NOT NULL,
	"insertion_order" serial NOT NULL,
	"evidence_json" jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "v2_execution_failure_records" (
	"id" text PRIMARY KEY NOT NULL,
	"session_id" text NOT NULL,
	"capability" text NOT NULL,
	"target_uri" text NOT NULL,
	"failed_at_ms" bigint NOT NULL,
	"recoverable" boolean NOT NULL,
	"source_recommendation_id" text,
	"lifecycle_status_at_failure" text NOT NULL,
	"error_message" text NOT NULL,
	"insertion_order" serial NOT NULL,
	"record_json" jsonb NOT NULL
);
--> statement-breakpoint
ALTER TABLE "v2_approved_request_records" ADD CONSTRAINT "v2_approved_request_records_session_id_v2_assessment_sessions_session_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."v2_assessment_sessions"("session_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "v2_audit_entries" ADD CONSTRAINT "v2_audit_entries_session_id_v2_assessment_sessions_session_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."v2_assessment_sessions"("session_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "v2_evidence_records" ADD CONSTRAINT "v2_evidence_records_session_id_v2_assessment_sessions_session_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."v2_assessment_sessions"("session_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "v2_execution_failure_records" ADD CONSTRAINT "v2_execution_failure_records_session_id_v2_assessment_sessions_session_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."v2_assessment_sessions"("session_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_v2_approved_session_id" ON "v2_approved_request_records" USING btree ("session_id");--> statement-breakpoint
CREATE INDEX "idx_v2_approved_session_insertion_order" ON "v2_approved_request_records" USING btree ("session_id","insertion_order");--> statement-breakpoint
CREATE INDEX "idx_v2_approved_session_approved_at" ON "v2_approved_request_records" USING btree ("session_id","approved_at_ms");--> statement-breakpoint
CREATE INDEX "idx_v2_approved_session_capability" ON "v2_approved_request_records" USING btree ("session_id","capability");--> statement-breakpoint
CREATE INDEX "idx_v2_sessions_target_uri" ON "v2_assessment_sessions" USING btree ("target_uri");--> statement-breakpoint
CREATE INDEX "idx_v2_sessions_lifecycle_status" ON "v2_assessment_sessions" USING btree ("lifecycle_status");--> statement-breakpoint
CREATE INDEX "idx_v2_sessions_created_at_ms" ON "v2_assessment_sessions" USING btree ("created_at_ms");--> statement-breakpoint
CREATE INDEX "idx_v2_sessions_updated_at_ms" ON "v2_assessment_sessions" USING btree ("updated_at_ms");--> statement-breakpoint
CREATE INDEX "idx_v2_sessions_target_uri_lifecycle" ON "v2_assessment_sessions" USING btree ("target_uri","lifecycle_status");--> statement-breakpoint
CREATE INDEX "idx_v2_audit_session_id" ON "v2_audit_entries" USING btree ("session_id");--> statement-breakpoint
CREATE INDEX "idx_v2_audit_session_insertion_order" ON "v2_audit_entries" USING btree ("session_id","insertion_order");--> statement-breakpoint
CREATE INDEX "idx_v2_audit_session_recorded_at" ON "v2_audit_entries" USING btree ("session_id","recorded_at_ms");--> statement-breakpoint
CREATE INDEX "idx_v2_evidence_session_id" ON "v2_evidence_records" USING btree ("session_id");--> statement-breakpoint
CREATE INDEX "idx_v2_evidence_session_insertion_order" ON "v2_evidence_records" USING btree ("session_id","insertion_order");--> statement-breakpoint
CREATE INDEX "idx_v2_evidence_session_recorded_at" ON "v2_evidence_records" USING btree ("session_id","recorded_at_ms");--> statement-breakpoint
CREATE INDEX "idx_v2_evidence_session_capability" ON "v2_evidence_records" USING btree ("session_id","capability");--> statement-breakpoint
CREATE INDEX "idx_v2_failure_session_id" ON "v2_execution_failure_records" USING btree ("session_id");--> statement-breakpoint
CREATE INDEX "idx_v2_failure_session_insertion_order" ON "v2_execution_failure_records" USING btree ("session_id","insertion_order");--> statement-breakpoint
CREATE INDEX "idx_v2_failure_session_failed_at" ON "v2_execution_failure_records" USING btree ("session_id","failed_at_ms");--> statement-breakpoint
CREATE INDEX "idx_v2_failure_session_capability" ON "v2_execution_failure_records" USING btree ("session_id","capability");--> statement-breakpoint
CREATE INDEX "idx_v2_failure_session_recoverable" ON "v2_execution_failure_records" USING btree ("session_id","recoverable");