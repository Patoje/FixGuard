import assert from 'node:assert';
import process from 'node:process';
import { drizzle } from 'drizzle-orm/neon-serverless';
import { Pool, neonConfig } from '@neondatabase/serverless';
import { migrate } from 'drizzle-orm/neon-serverless/migrator';
import { fileURLToPath } from 'node:url';
import { sql } from 'drizzle-orm';
import { v2_active_recon_run_records } from '../storage/postgres/schema.js';
import { PostgresActiveReconRunRepository } from '../recon/active/PostgresActiveReconRunRepository.js';

const mockSafeRecord: any = {
  recordVersion: 'active-recon-origin-run-record/v0',
  recordKind: 'active-recon.origin-run',
  runId: 'm41_pg_smoke_safe_1',
  subject: {
    kind: 'origin',
    normalizedOrigin: 'https://example.com'
  },
  status: 'completed',
  counts: {
    requested: 1, planned: 1, completed: 1, blocked: 0, candidate: 0, failed: 0
  },
  items: [
    {
      itemVersion: 'active-recon-document-probe-item/v0',
      family: 'document',
      safeProbeIndex: 'idx',
      safeKind: 'unknown',
      status: 'completed',
      target: { normalizedOrigin: 'https://example.com' },
      observations: []
    }
  ],
  observations: [],
  runErrors: [],
  classification: { finding: false, evidence: false, vulnerability: false, riskClaim: false },
  provenance: { sourceBoundary: 'M39', sourceContractVersion: 'active-recon-origin-run/v0', persistedBy: 'M40' },
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString()
};

async function runTests() {
  const testUrl = process.env.FIXGUARD_PG_TEST_URL;
  const flag = process.env.FIXGUARD_V2_POSTGRES_ACTIVE_RECON_RUN_PERSISTENCE;
  const confirm = process.env.FIXGUARD_V2_POSTGRES_ACTIVE_RECON_CONFIRM;

  if (!testUrl && !flag && !confirm) {
    console.log('--- Postgres Active Recon Persistence Smoke Skipped ---');
    console.log('Reason: All DB env vars absent.');
    process.exit(0);
  }

  if (!testUrl || flag !== '1' || confirm !== 'I_CONFIRM_POSTGRES_ACTIVE_RECON_PERSISTENCE_TEST') {
    console.error('--- Postgres Active Recon Persistence Smoke Refused ---');
    console.error('Reason: Partial environment or wrong confirmation string.');
    process.exit(1);
  }

  if (typeof WebSocket !== 'undefined') {
    neonConfig.webSocketConstructor = WebSocket;
  }

  console.log('[*] Connected to Postgres.');
  const pool = new Pool({ connectionString: testUrl });
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

    // Cleanup before tests
    await db.execute(sql`DELETE FROM v2_active_recon_run_records WHERE run_id LIKE 'm41_pg_smoke_%'`);

    const repository = new PostgresActiveReconRunRepository(db);

    // 1. Safe insert
    console.log('[*] Testing safe record insert...');
    const saved = await repository.saveRun(mockSafeRecord);
    assert.deepStrictEqual(saved, mockSafeRecord);
    console.log('[+] Safe validated record inserts successfully.');

    // 2. Duplicate reject
    console.log('[*] Testing duplicate save...');
    await assert.rejects(
      repository.saveRun(mockSafeRecord),
      /Duplicate runId/
    );
    console.log('[+] Duplicate save rejects.');

    // 3. Get by runId
    console.log('[*] Testing getRun...');
    const loaded = await repository.getRun(mockSafeRecord.runId);
    assert.deepStrictEqual(loaded, mockSafeRecord);
    console.log('[+] getRun works and retrieved record equals persisted safe shape.');

    // 4. List filters
    console.log('[*] Testing listRuns filters...');
    const list1 = await repository.listRuns({ recordKind: 'active-recon.origin-run' });
    assert(list1.find(r => r.runId === mockSafeRecord.runId));
    console.log('[+] list by recordKind works.');

    const list2 = await repository.listRuns({ normalizedOrigin: 'https://example.com' });
    assert(list2.find(r => r.runId === mockSafeRecord.runId));
    console.log('[+] list by normalizedOrigin works.');

    const list3 = await repository.listRuns({ status: 'completed' });
    assert(list3.find(r => r.runId === mockSafeRecord.runId));
    console.log('[+] list by status works.');

    // 5. Check `record_json` lacks unsafe keys/claims
    console.log('[*] Testing raw record_json in DB...');
    const rawRows = await db.select().from(v2_active_recon_run_records).where(sql`run_id = ${mockSafeRecord.runId}`);
    const rawJsonStr = JSON.stringify(rawRows[0].record_json);
    const forbidden = [
      'targetUrl', 'raw', 'headers', 'body', 'request', 'response', 'payload', 
      'cookie', 'authorization', 'password', 'api_key', 'token', 'secret', 
      'severity', 'impact', 'exploit', '"finding":true'
    ];
    for (const f of forbidden) {
      assert(!rawJsonStr.includes(`"${f}"`), `Found forbidden string in DB: ${f}`);
    }
    console.log('[+] record_json lacks unsafe keys/claims and true classification claims.');

    // 6. Failed run persists safely
    const failedRecord = {
      ...mockSafeRecord,
      runId: 'm41_pg_smoke_failed_1',
      status: 'failed',
      runErrors: [{ code: 'adapter_missing', message: 'Safe message' }]
    };
    await repository.saveRun(failedRecord);
    console.log('[+] failed run/runErrors persist safely.');

    // 7. Invalid unsafe record rejects before insert
    const unsafeRecord = {
      ...mockSafeRecord,
      runId: 'm41_pg_smoke_unsafe_1',
      observations: [{ targetUrl: 'unsafe' }]
    };
    await assert.rejects(repository.saveRun(unsafeRecord), /contains unsafe key targetUrl/);
    console.log('[+] invalid unsafe record rejects before insert.');

    // 8. Invalid error code rejects before insert
    const invalidErrorRecord = {
      ...mockSafeRecord,
      runId: 'm41_pg_smoke_unsafe_2',
      runErrors: [{ code: 'evil_code', message: 'msg' }]
    };
    await assert.rejects(repository.saveRun(invalidErrorRecord), /Invalid error code/);
    console.log('[+] invalid error code rejects before insert.');

    // 9. Unsupported family rejects before insert
    const unsupportedFamilyRecord = {
      ...mockSafeRecord,
      runId: 'm41_pg_smoke_unsafe_3',
      items: [{ ...mockSafeRecord.items[0], family: 'scanner' }]
    };
    await assert.rejects(repository.saveRun(unsupportedFamilyRecord), /unsupported item family/);
    console.log('[+] unsupported family rejects before insert.');

    // 10. Corrupt/unsafe DB-loaded record_json rejects on read
    console.log('[*] Testing DB read validation...');
    await db.insert(v2_active_recon_run_records).values({
      run_id: 'm41_pg_smoke_corrupt_1',
      record_version: mockSafeRecord.recordVersion,
      record_kind: mockSafeRecord.recordKind,
      subject_kind: mockSafeRecord.subject.kind,
      normalized_origin: mockSafeRecord.subject.normalizedOrigin,
      status: mockSafeRecord.status,
      record_json: { ...mockSafeRecord, runId: 'm41_pg_smoke_corrupt_1', classification: { finding: true, evidence: false, vulnerability: false, riskClaim: false } } as any,
      created_at: new Date(),
      updated_at: new Date(),
    });
    
    await assert.rejects(repository.getRun('m41_pg_smoke_corrupt_1'), /Unsafe active recon classification claim/);
    await assert.rejects(repository.listRuns({ normalizedOrigin: 'https://example.com' }), /Unsafe active recon classification claim/);
    console.log('[+] corrupt/unsafe DB-loaded record_json is not returned as safe.');

    // Cleanup after tests
    await db.execute(sql`DELETE FROM v2_active_recon_run_records WHERE run_id LIKE 'm41_pg_smoke_%'`);
    console.log('[+] cleanup touches only test-prefixed rows.');
    console.log('[+] no real adapters/network target/scanners/findings/evidence used.');

    console.log('--- Postgres Active Recon Persistence Smoke Completed Successfully ---');
  } finally {
    await pool.end();
  }
}

runTests().catch(err => {
  console.error(err);
  process.exit(1);
});
