import assert from 'node:assert';
import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository';
import { V2AssessmentRuntime } from '../runtime/V2AssessmentRuntime';
import { createStubOrchestrator } from './StubToolRegistry';

async function runSmoke() {
  console.log('--- V2 Recommendation Continuity Smoke Test ---');

  // 1. Setup DB-free repository
  const repository = new InMemoryAssessmentRepository();
  const orchestrator = createStubOrchestrator();
  
  // 2. Create first runtime instance
  const runtime1 = new V2AssessmentRuntime(repository, orchestrator);
  const sessionObj = await runtime1.createSession('https://test-continuity.com');
  const sessionId = sessionObj.getState().sessionId;
  console.log('[*] Session created in runtime1:', sessionId);

  // 3. Start Initial Recon
  await runtime1.startInitialRecon(sessionId);
  console.log('[+] Initial recon completed');

  // 4. Run Intelligence to generate pending recommendations
  let state = await runtime1.runIntelligence(sessionId);
  
  assert.strictEqual(state.pendingRecommendations.length, 1, 'Should have 1 pending recommendation');
  const recommendationId = state.pendingRecommendations[0].id;
  console.log(`[+] Intelligence produced pending recommendation: ${recommendationId}`);

  // 5. Create a fresh runtime instance (simulate worker reload / API request boundary)
  const runtime2 = new V2AssessmentRuntime(repository, orchestrator);
  
  // 6. Load session from repository snapshot
  const loadedSessionObj = await runtime2.loadSession(sessionId);
  assert.ok(loadedSessionObj, 'Session should load successfully in fresh runtime');
  
  const loadedState = loadedSessionObj.getState();
  // 7. Verify pending recommendation exists in loaded session
  assert.strictEqual(loadedState.pendingRecommendations.length, 1, 'Pending recommendation must survive reload');
  assert.strictEqual(loadedState.pendingRecommendations[0].id, recommendationId, 'Recommendation ID must match');
  console.log('[+] Pending recommendation successfully reloaded into fresh runtime');

  // 8. Test negative override cases (Executable key rejection)
  console.log('[*] Testing negative override cases...');
  const operatorId = 'operator-reload-test';

  const negativeCases = [
    { binary: 'nuclei' },
    { safe: { args: ['-u', 'https://example.test'] } },
    { command: 'whoami' },
    { env: { PATH: '/usr/bin' } },
    { shell: '/bin/bash' },
    { stdin: 'input' }
  ];

  for (const overrides of negativeCases) {
    let error: any;
    try {
      await runtime2.approveRecommendation(sessionId, recommendationId, operatorId, overrides);
    } catch (err: any) {
      error = err;
    }
    assert.ok(error, 'Expected approval to reject due to executable override key');
    assert.match(error.message, /Executable override key '.*' is forbidden/);
  }

  // 9. Verify rejection did not mutate state
  const rejectedState = runtime2.getSession(sessionId)!.getState();
  assert.strictEqual(rejectedState.pendingRecommendations.length, 1, 'Pending recommendation must survive rejected override');
  assert.strictEqual(rejectedState.approvedRequestRecords.length, 0, 'No ApprovedRequestRecord should be persisted');
  assert.strictEqual(rejectedState.auditEntries.length, 0, 'No audit entry should be added');
  assert.strictEqual(rejectedState.errors.length, 0, 'No ExecutionFailureRecord or session error should be created');
  assert.strictEqual(rejectedState.lifecycleStatus, 'awaiting_approval', 'Session lifecycle must not advance unexpectedly');
  console.log('[+] Executable override rejection works cleanly without mutating state');

  // 10. Approve recommendation in the fresh runtime (Happy Path)
  state = await runtime2.approveRecommendation(sessionId, recommendationId, operatorId);
  console.log('[+] Recommendation approved successfully after reload (Happy Path)');

  // 11. Verify removal from pending
  assert.strictEqual(state.pendingRecommendations.length, 0, 'Recommendation should be removed from pending after approval');

  // 12. Verify Safe ApprovedRequestRecord
  assert.strictEqual(state.approvedRequestRecords.length, 1, 'ApprovedRequestRecord should be persisted');
  const record = state.approvedRequestRecords[0];
  assert.strictEqual(record.recommendationId, recommendationId);
  assert.strictEqual(record.operatorId, operatorId);

  // 13. Verify NO EXECUTABLE PAYLOADS are exposed or persisted
  const anyRecord = record as any;
  const forbiddenKeys = ['binary', 'args', 'env', 'command', 'shell', 'stdin'];
  for (const key of forbiddenKeys) {
    assert.strictEqual(anyRecord[key], undefined, `ApprovedRequestRecord must NOT contain ${key}`);
    assert.strictEqual(anyRecord.requestSummary?.[key], undefined, `ApprovedRequestRecord.requestSummary must NOT contain ${key}`);
  }
  
  // 14. Verify no CapabilityRequest/ExecutionRequest in state
  const anyState = state as any;
  assert.strictEqual(anyState.capabilityRequest, undefined, 'State must not persist capability request');
  assert.strictEqual(anyState.executionRequest, undefined, 'State must not persist execution request');
  
  console.log('[+] Approved request record is clean. No executable fields persisted.');
  console.log('[SUCCESS] V2 Recommendation Continuity Smoke Test Passed.');
}

runSmoke().catch(err => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
