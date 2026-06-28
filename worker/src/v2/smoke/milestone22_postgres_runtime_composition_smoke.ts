import assert from 'node:assert';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/neon-serverless';
import { Pool } from '@neondatabase/serverless';
import { createPostgresBackedV2RuntimeFromEnv } from '../runtime/composition/PostgresV2RuntimeComposition';
import { createStubOrchestrator } from './StubToolRegistry';
import type { V2RuntimeComposition } from '../runtime/composition/PostgresV2RuntimeComposition';

async function runSmoke() {
  console.log('--- V2 Postgres Runtime Composition Smoke Test ---');

  const repoType = process.env.FIXGUARD_V2_RUNTIME_REPOSITORY;
  const isEnabled = process.env.FIXGUARD_V2_ENABLE_POSTGRES_RUNTIME;
  const databaseUrl = process.env.FIXGUARD_V2_DATABASE_URL;
  const allowDestructive = process.env.FIXGUARD_V2_RUNTIME_COMPOSITION_ALLOW_DESTRUCTIVE;
  const confirmTestBranch = process.env.FIXGUARD_V2_RUNTIME_COMPOSITION_CONFIRM_TEST_BRANCH;

  if (repoType !== 'postgres' || isEnabled !== '1' || !databaseUrl) {
    console.log('[*] Missing required env vars (FIXGUARD_V2_RUNTIME_REPOSITORY=postgres, FIXGUARD_V2_ENABLE_POSTGRES_RUNTIME=1, FIXGUARD_V2_DATABASE_URL).');
    console.log('[+] Skipping test cleanly.');
    return;
  }

  if (allowDestructive !== '1') {
    console.log('[*] Destructive guard FIXGUARD_V2_RUNTIME_COMPOSITION_ALLOW_DESTRUCTIVE=1 is missing.');
    console.log('[+] Refusing to run destructive Postgres composition smoke test.');
    return;
  }

  if (confirmTestBranch !== '1') {
    console.log('[*] Test branch confirmation FIXGUARD_V2_RUNTIME_COMPOSITION_CONFIRM_TEST_BRANCH=1 is missing.');
    console.log('[+] Refusing to run destructive Postgres composition smoke test. Explicit human confirmation is required.');
    return;
  }

  console.log('[*] Env checks passed. Starting Postgres runtime composition test...');
  
  const pool = new Pool({ connectionString: databaseUrl });
  const db = drizzle(pool);

  let composition1: V2RuntimeComposition | undefined;
  let composition2: V2RuntimeComposition | undefined;

  try {
    console.log('[*] Cleaning V2 tables...');
    await db.execute(sql`TRUNCATE TABLE v2_execution_failure_records CASCADE`);
    await db.execute(sql`TRUNCATE TABLE v2_approved_request_records CASCADE`);
    await db.execute(sql`TRUNCATE TABLE v2_audit_entries CASCADE`);
    await db.execute(sql`TRUNCATE TABLE v2_evidence_records CASCADE`);
    await db.execute(sql`TRUNCATE TABLE v2_assessment_sessions CASCADE`);

    // Note: we inject the stub orchestrator to keep execution deterministic and safe
    composition1 = await createPostgresBackedV2RuntimeFromEnv(createStubOrchestrator());
    const runtime1 = composition1.runtime;
    console.log('[*] Created first Postgres-backed runtime.');

    const session = await runtime1.createSession('https://test-composition.com');
    const sessionId = session.getState().sessionId;
    console.log(`[*] Session created: ${sessionId}`);

    await runtime1.startInitialRecon(sessionId);
    console.log('[*] startInitialRecon executed and persisted through first runtime.');
    
    console.log('[*] Closing first composition to prove independent persistence...');
    await composition1.close();
    composition1 = undefined; // Ensure we don't use it again

    console.log('[*] Creating second fresh Postgres-backed runtime...');
    composition2 = await createPostgresBackedV2RuntimeFromEnv(createStubOrchestrator());
    const runtime2 = composition2.runtime;

    console.log('[*] Loading session from second runtime...');
    const reloadedSession = await runtime2.loadSession(sessionId);
    assert(reloadedSession, 'Failed to reload session from Postgres in second runtime');
    
    // Assert the persisted snapshot fields
    const reloadedState = reloadedSession.getState();
    assert.strictEqual(reloadedState.lifecycleStatus, 'profile_updated', 'Lifecycle status did not persist correctly');
    assert.strictEqual(reloadedState.version, 3, 'Version did not persist correctly');
    
    // Independent Proof of Append-Only Row Persistence
    // We query the database directly to ensure appendEvidence() successfully inserted a distinct row,
    // proving persistence outside of just the AssessmentState snapshot.
    console.log('[*] Verifying independent append-only table persistence via direct DB query...');
    const result = await db.execute(
      sql`SELECT evidence_json FROM v2_evidence_records WHERE session_id = ${sessionId}`
    );
    assert.strictEqual(result.rows.length, 1, 'Expected exactly one evidence row in v2_evidence_records');
    
    const row = result.rows[0];
    const evidenceJson = typeof row.evidence_json === 'string' ? JSON.parse(row.evidence_json) : row.evidence_json;
    assert.strictEqual(evidenceJson.findings[0].type, 'subdomain_discovery', 'Independent DB row did not contain expected finding type');

    console.log('[+] Independent Postgres persistence and reload proven successfully (Snapshot + Append-only table).');
    console.log('[+] Postgres runtime composition smoke test passed successfully.');

  } catch (error) {
    console.error('[-] Fatal error during composition test:', error);
    process.exitCode = 1;
  } finally {
    console.log('[*] Closing compositions...');
    if (composition1) await composition1.close();
    if (composition2) await composition2.close();
    await pool.end(); // Also close our direct smoke-test pool
  }
}

runSmoke().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
