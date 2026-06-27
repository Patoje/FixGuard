import { V2AssessmentRuntime } from '../runtime/V2AssessmentRuntime';
import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository';
import { createStubOrchestrator } from './StubToolRegistry';
import { RuntimeLifecycleError } from '../runtime/RuntimeLifecycleError';

console.log('--- V2 Runtime Lifecycle Guards Smoke Test ---');

async function assertRejects(
  actionName: string, 
  action: () => Promise<any>, 
  repository: InMemoryAssessmentRepository,
  sessionId: string
) {
  // Capture snapshot and append counts BEFORE
  const stateBefore = await repository.loadAssessmentState(sessionId);
  if (!stateBefore) throw new Error(`Cannot assertRejects on missing session ${sessionId}`);
  const versionBefore = stateBefore.version;
  const evBefore = (await repository.listEvidence(sessionId)).length;
  const auBefore = (await repository.listAuditEntries(sessionId)).length;
  const apBefore = (await repository.listApprovedRequests(sessionId)).length;
  const failBefore = (await repository.listExecutionFailures(sessionId)).length;

  let threw = false;
  try {
    await action();
  } catch (err: any) {
    threw = true;
    if (!(err instanceof RuntimeLifecycleError)) {
      throw new Error(`Expected RuntimeLifecycleError for ${actionName}, got ${err?.name}: ${err?.message}`);
    }
  }

  if (!threw) {
    throw new Error(`Expected ${actionName} to be rejected by lifecycle guard, but it succeeded.`);
  }

  // Capture snapshot and append counts AFTER
  const stateAfter = await repository.loadAssessmentState(sessionId);
  if (stateAfter!.version !== versionBefore) throw new Error(`${actionName} incremented version despite rejection`);
  if ((await repository.listEvidence(sessionId)).length !== evBefore) throw new Error(`${actionName} appended evidence despite rejection`);
  if ((await repository.listAuditEntries(sessionId)).length !== auBefore) throw new Error(`${actionName} appended audit despite rejection`);
  if ((await repository.listApprovedRequests(sessionId)).length !== apBefore) throw new Error(`${actionName} appended approved request despite rejection`);
  if ((await repository.listExecutionFailures(sessionId)).length !== failBefore) throw new Error(`${actionName} appended execution failure despite rejection`);
  
  console.log(`[+] Correctly rejected ${actionName} with RuntimeLifecycleError and no side effects.`);
}

async function runSmoke() {
  const repository = new InMemoryAssessmentRepository();
  const runtime = new V2AssessmentRuntime(repository, createStubOrchestrator());
  const targetUri = 'https://example.com';

  console.log('[*] 1. Valid flow still works...');
  const session = await runtime.createSession(targetUri);
  const sessionId = session.getState().sessionId;

  await runtime.startInitialRecon(sessionId);
  let state = await runtime.runIntelligence(sessionId);
  const rec = state.pendingRecommendations[0];
  await runtime.approveRecommendation(sessionId, rec.id, 'operator');
  state = await runtime.runIntelligence(sessionId);
  if (state.lifecycleStatus !== 'completed') {
    await runtime.completeSession(sessionId);
  }
  
  console.log('[+] Valid flow completed successfully.');

  console.log('[*] 2. Completed session rejects mutations...');
  // It's completed now. Test all mutations:
  await assertRejects('startInitialRecon on completed', () => runtime.startInitialRecon(sessionId), repository, sessionId);
  await assertRejects('runIntelligence on completed', () => runtime.runIntelligence(sessionId), repository, sessionId);
  await assertRejects('approveRecommendation on completed', () => runtime.approveRecommendation(sessionId, rec.id, 'op'), repository, sessionId);
  await assertRejects('rejectRecommendation on completed', () => runtime.rejectRecommendation(sessionId, rec.id, 'op', 'reason'), repository, sessionId);
  await assertRejects('completeSession on completed', () => runtime.completeSession(sessionId), repository, sessionId);

  console.log('[*] 3. Failed session loaded from repository rejects mutations...');
  const failedSessionId = 'failed_session_1';
  // Note: repository.saveAssessmentState is used here ONLY to inject a fixture for testing load-time lifecycle guards.
  // It is not used to patch an active runtime session behind its back.
  await repository.saveAssessmentState({
    expectedVersion: 0,
    state: {
      ...session.getState(),
      sessionId: failedSessionId,
      lifecycleStatus: 'failed',
      version: 1
    }
  });
  const runtimeB = new V2AssessmentRuntime(repository, createStubOrchestrator());
  await runtimeB.loadSession(failedSessionId);
  await assertRejects('startInitialRecon on failed', () => runtimeB.startInitialRecon(failedSessionId), repository, failedSessionId);
  await assertRejects('runIntelligence on failed', () => runtimeB.runIntelligence(failedSessionId), repository, failedSessionId);
  await assertRejects('approveRecommendation on failed', () => runtimeB.approveRecommendation(failedSessionId, rec.id, 'op'), repository, failedSessionId);
  await assertRejects('rejectRecommendation on failed', () => runtimeB.rejectRecommendation(failedSessionId, rec.id, 'op', 'reason'), repository, failedSessionId);
  await assertRejects('completeSession on failed', () => runtimeB.completeSession(failedSessionId), repository, failedSessionId);

  console.log('[*] 4. Running-state snapshots loaded from repository reject mutations...');
  
  const runningStates = ['initial_execution_running', 'intelligence_running', 'approved_execution_running'] as const;
  let runIdx = 1;
  for (const rState of runningStates) {
    const runningSessionId = `running_session_${runIdx++}`;
    // Note: fixture injection only.
    await repository.saveAssessmentState({
      expectedVersion: 0,
      state: {
        ...session.getState(),
        sessionId: runningSessionId,
        lifecycleStatus: rState,
        version: 1
      }
    });
    await runtimeB.loadSession(runningSessionId);
    await assertRejects(`startInitialRecon on ${rState}`, () => runtimeB.startInitialRecon(runningSessionId), repository, runningSessionId);
    await assertRejects(`runIntelligence on ${rState}`, () => runtimeB.runIntelligence(runningSessionId), repository, runningSessionId);
    await assertRejects(`approveRecommendation on ${rState}`, () => runtimeB.approveRecommendation(runningSessionId, rec.id, 'op'), repository, runningSessionId);
    await assertRejects(`rejectRecommendation on ${rState}`, () => runtimeB.rejectRecommendation(runningSessionId, rec.id, 'op', 'reason'), repository, runningSessionId);
    await assertRejects(`completeSession on ${rState}`, () => runtimeB.completeSession(runningSessionId), repository, runningSessionId);
  }

  console.log('--- Smoke Test Completed Successfully ---');
}

runSmoke().catch(err => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
