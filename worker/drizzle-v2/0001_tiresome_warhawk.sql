CREATE TABLE "v2_active_recon_run_records" (
	"run_id" text PRIMARY KEY NOT NULL,
	"record_version" text NOT NULL,
	"record_kind" text NOT NULL,
	"subject_kind" text NOT NULL,
	"normalized_origin" text,
	"status" text NOT NULL,
	"record_json" jsonb NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE INDEX "idx_v2_arr_record_kind" ON "v2_active_recon_run_records" USING btree ("record_kind");--> statement-breakpoint
CREATE INDEX "idx_v2_arr_normalized_origin" ON "v2_active_recon_run_records" USING btree ("normalized_origin");--> statement-breakpoint
CREATE INDEX "idx_v2_arr_status" ON "v2_active_recon_run_records" USING btree ("status");