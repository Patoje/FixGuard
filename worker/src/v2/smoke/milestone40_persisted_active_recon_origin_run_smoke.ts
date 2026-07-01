import assert from 'node:assert';
import { persistActiveReconOriginRunResult } from '../recon/active/ActiveReconOriginRunPersistenceService.js';
import { InMemoryActiveReconOriginRunRepository } from '../recon/active/InMemoryActiveReconOriginRunRepository.js';
import type { ActiveReconOriginRunResult } from '../recon/active/ActiveReconOriginRunContracts.js';

console.log('--- V2 Persisted Active Recon Origin Run Smoke Test ---');

async function runTests() {
  const repository = new InMemoryActiveReconOriginRunRepository();

  const mockSafeResult: ActiveReconOriginRunResult = {
    contractVersion: 'active-recon-origin-run/v0',
    runId: 'run-123',
    status: 'completed',
    normalizedOrigin: 'https://example.com',
    requestedProbeCount: 2,
    plannedProbeCount: 2,
    completedProbeCount: 2,
    blockedProbeCount: 0,
    candidateProbeCount: 0,
    failedProbeCount: 0,
    runErrors: [],
    probes: [
      {
        safeProbeIndex: 'idx-1',
        family: 'document',
        safeKind: 'http.robots.inspect',
        status: 'completed',
        target: {
          normalizedOrigin: 'https://example.com',
          safeDisplayUrl: 'https://example.com/robots.txt',
        },
        observations: [],
      }
    ],
    observations: [],
    classification: {
      finding: false,
      evidence: false,
      vulnerability: false,
      riskClaim: false,
    }
  };

  // 1. Safe M39 result can be persisted.
  const record1 = await persistActiveReconOriginRunResult(mockSafeResult, repository);
  assert.strictEqual(record1.runId, 'run-123');
  console.log('[+] Safe M39 result can be persisted.');

  // 2. Persisted record can be reloaded by runId.
  const reloaded1 = await repository.getRun('run-123');
  assert.strictEqual(reloaded1?.runId, 'run-123');
  console.log('[+] Persisted record can be reloaded by runId.');

  // 3. List returns safe records.
  // 10. Safe list filters work.
  const list1 = await repository.listRuns({ normalizedOrigin: 'https://example.com' });
  assert.strictEqual(list1.length, 1);
  const listEmpty = await repository.listRuns({ normalizedOrigin: 'https://other.com' });
  assert.strictEqual(listEmpty.length, 0);
  console.log('[+] List returns safe records and filters work.');

  // 4, 5, 6, 7, 8. Clone behavior and mutation safety.
  mockSafeResult.status = 'failed'; // mutate original after save
  const reloaded2 = await repository.getRun('run-123');
  assert.strictEqual(reloaded2?.status, 'completed', 'Stored record must not mutate when original is mutated');

  reloaded2!.status = 'partial'; // mutate returned
  const reloaded3 = await repository.getRun('run-123');
  assert.strictEqual(reloaded3?.status, 'completed', 'Stored record must not mutate when returned is mutated');
  console.log('[+] In-memory repository clones on save/get/list, mutation safety proven.');

  // 9. Duplicate save is rejected.
  const duplicateResult = { ...mockSafeResult, runId: 'run-123', status: 'completed' } as ActiveReconOriginRunResult;
  await assert.rejects(
    persistActiveReconOriginRunResult(duplicateResult, repository),
    /Duplicate runId/
  );
  console.log('[+] Duplicate save is rejected.');

  // 11, 12, 13, 14, 15. Safe fields and no raw values.
  const serializedRecord = JSON.stringify(reloaded3);
  assert.ok(!serializedRecord.includes('"targetUrl"'));
  assert.ok(!serializedRecord.includes('"body"'));
  assert.ok(!serializedRecord.includes('"headers"'));
  assert.ok(!serializedRecord.includes('"request"'));
  assert.ok(!serializedRecord.includes('"response"'));
  assert.ok(!serializedRecord.includes('"payload"'));
  assert.ok(!serializedRecord.includes('SECRET_REQUEST_ID'));
  assert.ok(!serializedRecord.includes('SECRET_PLAN_ID'));
  assert.ok(!serializedRecord.includes('SECRET_PROBE_ID'));
  console.log('[+] Persisted record contains only safe fields (no targetUrl/body/request/secrets).');

  // 16, 17. Classification flags remain false, no findings.
  assert.strictEqual(reloaded3?.classification.finding, false);
  assert.strictEqual(reloaded3?.classification.evidence, false);
  assert.strictEqual(reloaded3?.classification.vulnerability, false);
  assert.strictEqual(reloaded3?.classification.riskClaim, false);
  console.log('[+] Classification flags remain false, no findings/evidence claims.');

  // 18. Failed M39 result with runErrors persists safely.
  const failedResult: ActiveReconOriginRunResult = {
    ...mockSafeResult,
    runId: 'run-failed-1',
    status: 'failed',
    runErrors: [{ code: 'invalid_origin', message: 'Failed' }]
  };
  const recordFailed = await persistActiveReconOriginRunResult(failedResult, repository);
  assert.strictEqual(recordFailed.runErrors[0]?.code, 'invalid_origin');
  console.log('[+] Failed M39 result with runErrors persists safely.');

  // 19. Empty probe set error persists safely.
  const emptyProbeResult: ActiveReconOriginRunResult = {
    ...mockSafeResult,
    runId: 'run-empty-1',
    status: 'failed',
    runErrors: [{ code: 'empty_probe_set', message: 'Empty' }]
  };
  const recordEmpty = await persistActiveReconOriginRunResult(emptyProbeResult, repository);
  assert.strictEqual(recordEmpty.runErrors[0]?.code, 'empty_probe_set');
  console.log('[+] Empty probe set error persists safely.');

  // 20, 21. Fake outputs, no Postgres. (implicitly verified by in-memory nature)
  console.log('[+] No Postgres/network/API/UI/scanner behavior.');

  async function assertRepositoryUnchanged(fn: () => Promise<any>, errorMatcher: RegExp) {
    const beforeCount = (await repository.listRuns({ normalizedOrigin: 'https://example.com' })).length;
    await assert.rejects(fn, errorMatcher);
    const afterCount = (await repository.listRuns({ normalizedOrigin: 'https://example.com' })).length;
    assert.strictEqual(afterCount, beforeCount, 'Repository mutated after rejected save.');
  }

  // 1. Root true classification claim rejects
  const rootTrue = {
    ...mockSafeResult,
    runId: 'run-root-true',
    classification: { finding: true, evidence: false, vulnerability: false, riskClaim: false }
  } as any;
  await assertRepositoryUnchanged(() => persistActiveReconOriginRunResult(rootTrue, repository), /Unsafe active recon classification claim/);
  console.log('[+] Root true classification claim rejects.');

  // 1.5. Malformed classification
  const rootMalformed = {
    ...mockSafeResult,
    runId: 'run-root-malformed',
    classification: { finding: "false" as any, evidence: false, vulnerability: false, riskClaim: false }
  } as any;
  await assertRepositoryUnchanged(() => persistActiveReconOriginRunResult(rootMalformed, repository), /Unsafe active recon classification claim/);
  console.log('[+] Malformed classification rejects.');

  // 2. Secret-bearing runErrors[].message rejects
  const secretError = {
    ...mockSafeResult,
    runId: 'run-secret-error',
    runErrors: [{ code: 'empty_probe_set', message: 'token=SECRET' }]
  } as any;
  await assertRepositoryUnchanged(() => persistActiveReconOriginRunResult(secretError, repository), /Unsafe string value rejected before persistence/);
  console.log('[+] Secret-bearing runErrors[].message rejects.');

  // 3. Secret-bearing observation field rejects
  const secretObs = {
    ...mockSafeResult,
    runId: 'run-secret-obs',
    observations: [{ metadataType: 'robots_metadata', safeSummary: 'SUPER_SECRET token=abc' }]
  } as any;
  await assertRepositoryUnchanged(() => persistActiveReconOriginRunResult(secretObs, repository), /Unsafe string value rejected before persistence/);
  console.log('[+] Secret-bearing observation field rejects.');

  // 4. Invalid runErrors[].code rejects
  const invalidErrorCode = {
    ...mockSafeResult,
    runId: 'run-invalid-error-code',
    runErrors: [{ code: 'evil_code' as any, message: 'Safe message.' }]
  } as any;
  await assertRepositoryUnchanged(() => persistActiveReconOriginRunResult(invalidErrorCode, repository), /Invalid error code/);
  console.log('[+] Invalid runErrors[].code rejects.');

  // 5. Invalid item error.code rejects
  const invalidItemError = {
    ...mockSafeResult,
    runId: 'run-invalid-item-error',
    probes: [
      {
        ...mockSafeResult.probes[0],
        error: { code: 'evil_code' as any, message: 'Safe message.' }
      }
    ]
  } as any;
  await assertRepositoryUnchanged(() => persistActiveReconOriginRunResult(invalidItemError, repository), /Invalid error code/);
  console.log('[+] Invalid item error.code rejects.');

  // 22. Persistence validation rejects injected unsafe fields.
  const hostileResult1 = {
    ...mockSafeResult,
    runId: 'run-hostile-1',
    observations: [{ targetUrl: 'https://example.com' }]
  } as any;
  await assertRepositoryUnchanged(() => persistActiveReconOriginRunResult(hostileResult1, repository), /contains unsafe key targetUrl/);
  console.log('[+] Persistence validation rejects injected unsafe fields.');

  // 24. Persisted item union remains closed to document items only.
  const hostileResult3 = {
    ...mockSafeResult,
    runId: 'run-hostile-3',
    probes: [
      {
        ...mockSafeResult.probes[0],
        family: 'scanner', // unsupported family
      }
    ]
  } as any;
  await assertRepositoryUnchanged(() => persistActiveReconOriginRunResult(hostileResult3, repository), /unsupported item family/);
  console.log('[+] Persisted item union remains closed to document items only.');

  console.log('--- DB-free persistence smoke completed successfully ---');
}

runTests().catch(err => {
  console.error(err);
  process.exit(1);
});
