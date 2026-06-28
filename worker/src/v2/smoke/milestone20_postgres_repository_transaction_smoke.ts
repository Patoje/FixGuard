import { drizzle } from 'drizzle-orm/neon-serverless';
import { Pool, neonConfig } from '@neondatabase/serverless';
import { migrate } from 'drizzle-orm/neon-serverless/migrator';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { sql } from 'drizzle-orm';
import { PostgresAssessmentRepository } from '../storage/postgres/PostgresAssessmentRepository';
import { runAssessmentRepositoryTransactionConformanceSuite } from '../storage/testing/AssessmentRepositoryTransactionConformanceSuite';
import type { AssessmentState } from '../runtime/AssessmentState';

async function runSmoke() {
  const dbUrl = process.env.FIXGUARD_PG_TEST_URL;
  if (!dbUrl) {
    console.log('--- Postgres Transaction Smoke Skipped ---');
    console.log('Reason: FIXGUARD_PG_TEST_URL is not set.');
    return;
  }

  const allowDestructive = process.env.FIXGUARD_PG_TEST_ALLOW_DESTRUCTIVE === '1';
  if (!allowDestructive) {
    console.error('--- Postgres Transaction Smoke Refused ---');
    console.error('Reason: FIXGUARD_PG_TEST_URL is set, but FIXGUARD_PG_TEST_ALLOW_DESTRUCTIVE=1 is missing.');
    console.error('Safety guard: Real database URL provided without explicit destructive consent.');
    process.exit(1);
  }

  if (typeof WebSocket !== 'undefined') {
    neonConfig.webSocketConstructor = WebSocket;
  }

  console.log('[*] Connected to Postgres (neon-serverless)');
  const pool = new Pool({ connectionString: dbUrl });
  const db = drizzle(pool);

  try {
    const migrationsFolder = fileURLToPath(new URL('../../../drizzle-v2', import.meta.url));

    console.log(`[*] Running V2 migrations from ${migrationsFolder}...`);
    await migrate(db, {
      migrationsFolder,
      migrationsSchema: 'drizzle_v2',
      migrationsTable: '__drizzle_migrations_v2'
    });
    console.log('[+] Migrations complete.');

    const truncate = async () => {
      // Aggressively truncate only V2 tables
      await db.execute(sql`
        TRUNCATE TABLE 
          v2_execution_failure_records,
          v2_approved_request_records,
          v2_audit_entries,
          v2_evidence_records,
          v2_assessment_sessions
        RESTART IDENTITY CASCADE;
      `);
    };

    const repo = new PostgresAssessmentRepository(db);

    await runAssessmentRepositoryTransactionConformanceSuite(
      "PostgresAssessmentRepository",
      async () => repo,
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
            timestamps: { created: Date.now(), lastUpdated: Date.now() },
            version: 1
          };
          await repo.saveAssessmentState({ state, expectedVersion: 0 });
        }
      }
    );

    console.log('--- Postgres Transaction Smoke Completed Successfully ---');
  } finally {
    await pool.end();
  }
}

runSmoke().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
