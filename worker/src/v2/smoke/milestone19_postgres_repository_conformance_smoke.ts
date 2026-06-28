import { neon } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-http';
import { migrate } from 'drizzle-orm/neon-http/migrator';
import { sql } from 'drizzle-orm';
import { PostgresAssessmentRepository } from '../storage/postgres/PostgresAssessmentRepository';
import { runAssessmentRepositoryConformanceSuite } from '../storage/testing/AssessmentRepositoryConformanceSuite';
import type { AssessmentState } from '../runtime/AssessmentState';
import { fileURLToPath } from 'node:url';

const migrationsFolder = fileURLToPath(
  new URL('../../../drizzle-v2', import.meta.url)
);

async function runSmoke() {
  const url = process.env.FIXGUARD_PG_TEST_URL;

  if (!url) {
    console.log("Skipping Milestone 19 Postgres conformance smoke: FIXGUARD_PG_TEST_URL is not set.");
    process.exit(0);
  }

  if (process.env.FIXGUARD_PG_TEST_ALLOW_DESTRUCTIVE !== "1") {
    console.log("Skipping/refusing Milestone 19 Postgres conformance smoke: FIXGUARD_PG_TEST_ALLOW_DESTRUCTIVE=1 is required.");
    process.exit(0);
  }

  console.log("[*] Connecting to Neon database...");
  const sqlClient = neon(url);
  const db = drizzle(sqlClient);

  console.log("[*] Running V2 migrations...");
  await migrate(db, {
    migrationsFolder,
    migrationsSchema: "drizzle_v2",
    migrationsTable: "__drizzle_migrations_v2",
  });

  const truncate = async () => {
    await db.execute(sql`
      TRUNCATE 
        v2_execution_failure_records,
        v2_approved_request_records,
        v2_audit_entries,
        v2_evidence_records,
        v2_assessment_sessions
      RESTART IDENTITY CASCADE;
    `);
  };

  const repo = new PostgresAssessmentRepository(db);

  await runAssessmentRepositoryConformanceSuite(
    "PostgresAssessmentRepository", 
    () => repo, 
    {
      beforeEachCase: async () => {
        await truncate();
      },
      seedParentSession: async (sessionId: string) => {
        const state: AssessmentState = {
          sessionId,
          targetUri: 'https://example.com',
          lifecycleStatus: 'initialized',
          evidenceCollections: [],
          currentProfile: null,
          pendingRecommendations: [],
          approvedRequestRecords: [],
          executionFailures: [],
          auditEntries: [],
          errors: [],
          timestamps: {
            created: 1000,
            lastUpdated: 1000
          },
          version: 0
        };
        await repo.saveAssessmentState({ state, expectedVersion: 0 });
      }
    }
  );

  console.log("--- Milestone 19 Postgres repository conformance smoke passed ---");
}

runSmoke().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
