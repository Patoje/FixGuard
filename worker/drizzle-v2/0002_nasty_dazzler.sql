CREATE TABLE "v2_formal_finding_candidates" (
	"candidate_id" text PRIMARY KEY NOT NULL,
	"session_id" text NOT NULL,
	"scan_id" text NOT NULL,
	"draft_id" text NOT NULL,
	"source_selection_id" text NOT NULL,
	"reviewer_id" text NOT NULL,
	"triage_decision_id" text NOT NULL,
	"selected_evidence_count" integer NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"candidate_json" jsonb NOT NULL,
	CONSTRAINT "v2_formal_finding_candidates_draft_id_unique" UNIQUE("draft_id")
);
--> statement-breakpoint
CREATE TABLE "v2_reviewed_evidence_records" (
	"store_record_id" text PRIMARY KEY NOT NULL,
	"session_id" text NOT NULL,
	"scan_id" text NOT NULL,
	"evidence_id" text NOT NULL,
	"indicator_id" text NOT NULL,
	"evidence_type" text NOT NULL,
	"strength" text NOT NULL,
	"actor_id" text NOT NULL,
	"validation_id" text NOT NULL,
	"saved_at" timestamp with time zone NOT NULL,
	"record_json" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "v2_reviewed_evidence_records_evidence_id_unique" UNIQUE("evidence_id")
);
--> statement-breakpoint
ALTER TABLE "v2_formal_finding_candidates" ADD CONSTRAINT "v2_formal_finding_candidates_session_id_v2_assessment_sessions_session_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."v2_assessment_sessions"("session_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "v2_reviewed_evidence_records" ADD CONSTRAINT "v2_reviewed_evidence_records_session_id_v2_assessment_sessions_session_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."v2_assessment_sessions"("session_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_v2_ffc_session_id" ON "v2_formal_finding_candidates" USING btree ("session_id");--> statement-breakpoint
CREATE INDEX "idx_v2_ffc_scan_id" ON "v2_formal_finding_candidates" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "idx_v2_ffc_draft_id" ON "v2_formal_finding_candidates" USING btree ("draft_id");--> statement-breakpoint
CREATE INDEX "idx_v2_ffc_reviewer_id" ON "v2_formal_finding_candidates" USING btree ("reviewer_id");--> statement-breakpoint
CREATE INDEX "idx_v2_ffc_created_at" ON "v2_formal_finding_candidates" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_v2_ffc_scan_created_at" ON "v2_formal_finding_candidates" USING btree ("scan_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_v2_rer_session_id" ON "v2_reviewed_evidence_records" USING btree ("session_id");--> statement-breakpoint
CREATE INDEX "idx_v2_rer_scan_id" ON "v2_reviewed_evidence_records" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "idx_v2_rer_evidence_id" ON "v2_reviewed_evidence_records" USING btree ("evidence_id");--> statement-breakpoint
CREATE INDEX "idx_v2_rer_indicator_id" ON "v2_reviewed_evidence_records" USING btree ("indicator_id");--> statement-breakpoint
CREATE INDEX "idx_v2_rer_actor_id" ON "v2_reviewed_evidence_records" USING btree ("actor_id");--> statement-breakpoint
CREATE INDEX "idx_v2_rer_saved_at" ON "v2_reviewed_evidence_records" USING btree ("saved_at");--> statement-breakpoint
CREATE INDEX "idx_v2_rer_scan_evidence_type" ON "v2_reviewed_evidence_records" USING btree ("scan_id","evidence_type");