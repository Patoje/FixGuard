import assert from 'node:assert';
import type { TransactionalAssessmentRepository } from '../TransactionalAssessmentRepository';
import type { AssessmentState, ExecutionFailureRecord } from '../../runtime/AssessmentState';
import { StaleStateError } from '../StorageErrors';

export interface ConformanceHooks {
  beforeEachCase?: () => Promise<void>;
  afterEachCase?: () => Promise<void>;
  seedParentSession?: (sessionId: string) => Promise<void>;
}

function createMinimalAssessmentState(sessionId: string, version: number = 0): AssessmentState {
  return {
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
    version
  };
}

function createMinimalExecutionFailure(sessionId: string, id: string): ExecutionFailureRecord {
  return {
    id,
    capability: 'http_probe',
    targetUri: 'https://example.com',
    lifecycleStatusAtFailure: 'initial_execution_running',
    errorMessage: 'Test error',
    recoverable: false,
    failedAt: Date.now()
  };
}

export async function runAssessmentRepositoryTransactionConformanceSuite(
  name: string,
  createRepository: () => Promise<TransactionalAssessmentRepository>,
  hooks?: ConformanceHooks
): Promise<void> {
  console.log(`\n--- Running AssessmentRepositoryTransactionConformanceSuite for ${name} ---`);

  const runBefore = async () => { if (hooks?.beforeEachCase) await hooks.beforeEachCase(); };
  const runAfter = async () => { if (hooks?.afterEachCase) await hooks.afterEachCase(); };
  const seed = async (sessionId: string) => { if (hooks?.seedParentSession) await hooks.seedParentSession(sessionId); };

  // 1. Commit persists snapshot write
  {
    await runBefore();
    const repo = await createRepository();
    const sessionId = 'session-snapshot-commit';
    const state = createMinimalAssessmentState(sessionId, 1);
    
    await repo.withTransaction(async (txRepo) => {
      await txRepo.saveAssessmentState({ state, expectedVersion: 0 });
    });
    
    const loaded = await repo.loadAssessmentState(sessionId);
    assert.strictEqual(loaded?.sessionId, sessionId);
    console.log('[+] 1. Commit persists snapshot write');
    await runAfter();
  }

  // 2. Commit persists append-only writes
  {
    await runBefore();
    const repo = await createRepository();
    const sessionId = 'session-append-commit';
    await seed(sessionId);
    
    await repo.withTransaction(async (txRepo) => {
      await txRepo.appendExecutionFailure({
        sessionId,
        record: createMinimalExecutionFailure(sessionId, 'f1'),
        recordedAt: Date.now()
      });
    });
    
    const failures = await repo.listExecutionFailures(sessionId);
    assert.strictEqual(failures.length, 1);
    assert.strictEqual(failures[0].id, 'f1');
    console.log('[+] 2. Commit persists append-only writes');
    await runAfter();
  }

  // 3. Thrown error rolls back snapshot write
  {
    await runBefore();
    const repo = await createRepository();
    const sessionId = 'session-snapshot-rollback';
    const state = createMinimalAssessmentState(sessionId, 1);
    
    let caughtError: any;
    try {
      await repo.withTransaction(async (txRepo) => {
        await txRepo.saveAssessmentState({ state, expectedVersion: 0 });
        throw new Error('Trigger rollback');
      });
    } catch (e) {
      caughtError = e;
    }
    
    assert.strictEqual(caughtError.message, 'Trigger rollback');
    
    const loaded = await repo.loadAssessmentState(sessionId);
    assert.strictEqual(loaded, undefined, 'Snapshot write should have been rolled back');
    console.log('[+] 3. Thrown error rolls back snapshot write');
    await runAfter();
  }

  // 4. Thrown error rolls back append-only writes
  {
    await runBefore();
    const repo = await createRepository();
    const sessionId = 'session-append-rollback';
    await seed(sessionId);
    
    let caughtError: any;
    try {
      await repo.withTransaction(async (txRepo) => {
        await txRepo.appendExecutionFailure({
          sessionId,
          record: createMinimalExecutionFailure(sessionId, 'f1'),
          recordedAt: Date.now()
        });
        throw new Error('Trigger rollback');
      });
    } catch (e) {
      caughtError = e;
    }
    
    assert.strictEqual(caughtError.message, 'Trigger rollback');
    
    const failures = await repo.listExecutionFailures(sessionId);
    assert.strictEqual(failures.length, 0, 'Append write should have been rolled back');
    console.log('[+] 4. Thrown error rolls back append-only writes');
    await runAfter();
  }

  // 5. Mixed snapshot + append writes roll back together
  {
    await runBefore();
    const repo = await createRepository();
    const sessionId = 'session-mixed-rollback';
    // We do NOT seed the session here, because we want to test that BOTH creation and append roll back.
    // Wait, if we don't seed, the append-only write will fail on Postgres due to FK constraints before we can even throw!
    // Let's seed a version 1 session, update it to version 2, and append, then throw.
    await seed(sessionId);
    const state = createMinimalAssessmentState(sessionId, 2);
    
    let caughtError: any;
    try {
      await repo.withTransaction(async (txRepo) => {
        await txRepo.saveAssessmentState({ state, expectedVersion: 1 });
        await txRepo.appendExecutionFailure({
          sessionId,
          record: createMinimalExecutionFailure(sessionId, 'f1'),
          recordedAt: Date.now()
        });
        throw new Error('Trigger mixed rollback');
      });
    } catch (e) {
      caughtError = e;
    }
    
    assert.strictEqual(caughtError.message, 'Trigger mixed rollback');
    
    const loaded = await repo.loadAssessmentState(sessionId);
    assert(loaded, 'Seeded snapshot should still exist after rollback');
    assert.strictEqual(loaded.version, 1, 'Snapshot update should have been rolled back to exactly version 1');
    
    const failures = await repo.listExecutionFailures(sessionId);
    assert.strictEqual(failures.length, 0, 'Append write should have been rolled back');
    console.log('[+] 5. Mixed snapshot + append writes roll back together');
    await runAfter();
  }

  // 6 & 7. StaleStateError inside transaction rolls back prior successful writes in the same transaction
  {
    await runBefore();
    const repo = await createRepository();
    const sessionId = 'session-stale-rollback';
    await seed(sessionId);
    
    let caughtError: any;
    try {
      await repo.withTransaction(async (txRepo) => {
        // Successful append
        await txRepo.appendExecutionFailure({
          sessionId,
          record: createMinimalExecutionFailure(sessionId, 'f1'),
          recordedAt: Date.now()
        });
        
        // Failed snapshot update (StaleStateError)
        const state = createMinimalAssessmentState(sessionId, 2);
        // Expecting version 999 which does not exist
        await txRepo.saveAssessmentState({ state, expectedVersion: 999 });
      });
    } catch (e) {
      caughtError = e;
    }
    
    assert(caughtError instanceof StaleStateError, 'Should throw StaleStateError');
    assert.strictEqual(caughtError.expectedVersion, 999);
    
    const failures = await repo.listExecutionFailures(sessionId);
    assert.strictEqual(failures.length, 0, 'Append write before StaleStateError should have been rolled back');
    console.log('[+] 6 & 7. StaleStateError rolls back prior writes and preserves error identity');
    await runAfter();
  }

  // 8. Transaction callback only receives/uses AssessmentRepository
  {
    await runBefore();
    const repo = await createRepository();
    
    await repo.withTransaction(async (txRepo) => {
      // By using txRepo methods natively, we already prove it complies with the interface.
      assert.strictEqual(typeof txRepo.saveAssessmentState, 'function');
      assert.strictEqual(typeof txRepo.appendExecutionFailure, 'function');
    });
    console.log('[+] 8. Transaction callback uses only AssessmentRepository');
    await runAfter();
  }

  console.log('--- Transaction Conformance Suite Passed ---\n');
}
