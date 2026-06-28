import assert from 'node:assert';
import { V2AssessmentRuntime } from '../runtime/V2AssessmentRuntime';
import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository';
import { StaleStateError } from '../storage/StorageErrors';
import type { AssessmentState } from '../runtime/AssessmentState';
import { RuntimeLifecycleError } from '../runtime/RuntimeLifecycleError';
import { createStubOrchestrator } from './StubToolRegistry';

class FailingAppendRepository extends InMemoryAssessmentRepository {
  public failNextAppend = false;

  public async appendEvidence(input: any): Promise<void> {
    if (this.failNextAppend) {
      this.failNextAppend = false;
      throw new Error('Simulated append failure');
    }
    return super.appendEvidence(input);
  }
}

class NonTransactionalRepository extends InMemoryAssessmentRepository {
  // @ts-expect-error - removing property for test
  public withTransaction = undefined;
}

class StaleStateRepository extends InMemoryAssessmentRepository {
  public async saveAssessmentState(input: { state: AssessmentState; expectedVersion: number }): Promise<void> {
    // If it's not the initial creation, throw StaleStateError
    if (input.expectedVersion > 0) {
      throw new StaleStateError(input.state.sessionId, input.expectedVersion, 999, 'Simulated StaleStateError');
    }
    return super.saveAssessmentState(input);
  }
}

async function runSmoke() {
  console.log('--- V2 Runtime Transaction Smoke Test ---');

  // 1. Runtime detects and uses transactional repository capability (Commit success)
  {
    console.log('[*] Testing transactional success commit...');
    const repo = new InMemoryAssessmentRepository();
    const runtime = new V2AssessmentRuntime(repo, createStubOrchestrator());
    const session = await runtime.createSession('https://example.com');
    const sessionId = session.getState().sessionId;

    await runtime.startInitialRecon(sessionId);

    const loaded = await repo.loadAssessmentState(sessionId);
    assert(loaded);
    assert.strictEqual(loaded.lifecycleStatus, 'profile_updated');
    
    // Initial recon adds 1 evidence collection on success
    const evidence = await repo.listEvidence(sessionId);
    assert.strictEqual(evidence.length, 1);
    console.log('[+] Transactional success commit works.');
  }

  // 2. Snapshot changes roll back when an append fails
  {
    console.log('[*] Testing rollback on append failure...');
    const repo = new FailingAppendRepository();
    const runtime = new V2AssessmentRuntime(repo, createStubOrchestrator());
    const session = await runtime.createSession('https://example.com');
    const sessionId = session.getState().sessionId;
    
    // After createSession, the repo is at initial_execution_running? No, createSession is initialized.
    // wait, startInitialRecon sets to initial_execution_running, persists it non-transactionally!
    // Then orchestrator runs.
    // Then transaction appends evidence.
    
    repo.failNextAppend = true; // This will cause appendEvidence to throw during the transaction!
    
    try {
      await runtime.startInitialRecon(sessionId);
      assert.fail('Should have thrown');
    } catch (err: any) {
      assert.strictEqual(err.message, 'Simulated append failure');
    }

    const state = await repo.loadAssessmentState(sessionId);
    // Since the transaction failed, the snapshot write (profile_updated) rolled back.
    // However, the prior non-transactional write (initial_execution_running) succeeded.
    // So the repo version should be exactly what it was just before the transaction.
    assert.strictEqual(state!.lifecycleStatus, 'initial_execution_running');

    // Also verify active runtime session did not diverge!
    const activeState = runtime.getSession(sessionId)!.getState();
    assert.strictEqual(activeState.lifecycleStatus, 'initial_execution_running');
    assert.strictEqual(activeState.version, state!.version);
    console.log('[+] Rollback on append failure works and active session is consistent.');
  }

  // 3. StaleStateError propagates unchanged and rolls back prior runtime writes
  {
    console.log('[*] Testing StaleStateError propagation and rollback...');
    const repo = new StaleStateRepository();
    const runtime = new V2AssessmentRuntime(repo, createStubOrchestrator());
    const session = await runtime.createSession('https://example.com');
    const sessionId = session.getState().sessionId;
    const initialVersion = session.getState().version;

    try {
      await runtime.startInitialRecon(sessionId);
      assert.fail('Should have thrown StaleStateError');
    } catch (err: any) {
      assert(err instanceof StaleStateError, 'Error should be StaleStateError');
    }

    const state = await repo.loadAssessmentState(sessionId);
    assert.strictEqual(state!.version, initialVersion);
    
    // Also verify active runtime session did not diverge!
    const activeState = runtime.getSession(sessionId)!.getState();
    assert.strictEqual(activeState.version, initialVersion);
    console.log('[+] StaleStateError rollback works and active session is consistent.');
  }

  // 4. Lifecycle guard failures perform no persistence writes
  {
    console.log('[*] Testing lifecycle guard failures...');
    const repo = new InMemoryAssessmentRepository();
    const runtime = new V2AssessmentRuntime(repo, createStubOrchestrator());
    const session = await runtime.createSession('https://example.com');
    const sessionId = session.getState().sessionId;

    await runtime.startInitialRecon(sessionId);
    const versionAfterRecon = runtime.getSession(sessionId)!.getState().version;

    try {
      await runtime.startInitialRecon(sessionId);
      assert.fail('Should have thrown RuntimeLifecycleError');
    } catch (err: any) {
      assert(err instanceof RuntimeLifecycleError, 'Error should be RuntimeLifecycleError');
    }

    const state = await repo.loadAssessmentState(sessionId);
    assert.strictEqual(state!.version, versionAfterRecon, 'Version should not change on lifecycle error');
    
    const activeState = runtime.getSession(sessionId)!.getState();
    assert.strictEqual(activeState.version, versionAfterRecon);

    const failures = await repo.listExecutionFailures(sessionId);
    assert.strictEqual(failures.length, 0, 'No execution failure should be appended on lifecycle error');
    console.log('[+] Lifecycle guard failures preserve state without writes.');
  }

  // 5. Non-transactional fallback preserves current behavior
  {
    console.log('[*] Testing non-transactional fallback...');
    const repo = new NonTransactionalRepository();
    const runtime = new V2AssessmentRuntime(repo, createStubOrchestrator());
    const session = await runtime.createSession('https://example.com');
    const sessionId = session.getState().sessionId;

    await runtime.startInitialRecon(sessionId);

    const loaded = await repo.loadAssessmentState(sessionId);
    assert.strictEqual(loaded!.lifecycleStatus, 'profile_updated');
    const evidence = await repo.listEvidence(sessionId);
    assert.strictEqual(evidence.length, 1);
    console.log('[+] Non-transactional fallback works.');
  }

  console.log('--- M21 Runtime Transaction Smoke Passed ---');
}

runSmoke().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
