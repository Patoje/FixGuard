CREATE TABLE "v2_orchestrated_assessments" (
	"assessment_id" text PRIMARY KEY NOT NULL,
	"scan_id" text NOT NULL,
	"target_domain" text NOT NULL,
	"status" text NOT NULL,
	"contract_version" text NOT NULL,
	"actor_id" text NOT NULL,
	"authorization_grant_id" text NOT NULL,
	"authorization_decision_id" text NOT NULL,
	"has_attack_surface_graph" boolean DEFAULT false NOT NULL,
	"graph_id" text,
	"started_at" timestamp with time zone NOT NULL,
	"completed_at" timestamp with time zone,
	"updated_at" timestamp with time zone NOT NULL,
	"record_json" jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "v2_attack_surface_graphs" (
	"graph_id" text PRIMARY KEY NOT NULL,
	"assessment_id" text NOT NULL,
	"scan_id" text NOT NULL,
	"target_host" text NOT NULL,
	"contract_version" text NOT NULL,
	"built_at" timestamp with time zone NOT NULL,
	"node_count" integer NOT NULL,
	"edge_count" integer NOT NULL,
	"observed_node_count" integer NOT NULL,
	"inferred_node_count" integer NOT NULL,
	"verified_node_count" integer NOT NULL,
	"refuted_node_count" integer NOT NULL,
	"actor_id" text NOT NULL,
	"authorization_grant_id" text NOT NULL,
	"authorization_decision_id" text NOT NULL,
	"graph_json" jsonb NOT NULL,
	"updated_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "v2_attack_surface_graphs" ADD CONSTRAINT "v2_attack_surface_graphs_assessment_id_v2_orchestrated_assessments_assessment_id_fk" FOREIGN KEY ("assessment_id") REFERENCES "public"."v2_orchestrated_assessments"("assessment_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_v2_oa_scan_id" ON "v2_orchestrated_assessments" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "idx_v2_oa_status" ON "v2_orchestrated_assessments" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_v2_oa_target_domain" ON "v2_orchestrated_assessments" USING btree ("target_domain");--> statement-breakpoint
CREATE INDEX "idx_v2_oa_updated_at" ON "v2_orchestrated_assessments" USING btree ("updated_at");--> statement-breakpoint
CREATE INDEX "idx_v2_oa_graph_id" ON "v2_orchestrated_assessments" USING btree ("graph_id");--> statement-breakpoint
CREATE INDEX "idx_v2_asg_assessment_id" ON "v2_attack_surface_graphs" USING btree ("assessment_id");--> statement-breakpoint
CREATE INDEX "idx_v2_asg_scan_id" ON "v2_attack_surface_graphs" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "idx_v2_asg_target_host" ON "v2_attack_surface_graphs" USING btree ("target_host");--> statement-breakpoint
CREATE INDEX "idx_v2_asg_updated_at" ON "v2_attack_surface_graphs" USING btree ("updated_at");
