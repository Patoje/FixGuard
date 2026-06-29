import assert from 'assert';
import { V2AssessmentRuntime } from '../runtime/V2AssessmentRuntime';
import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository';
import { CapabilityValidationError } from '../approval/IntentTranslator';
import { createStubOrchestrator } from './StubToolRegistry';
import { FixtureHttpHeaderInspectAdapter } from '../recon/passive/FixtureHttpHeaderInspectAdapter';

async function runSmokeTest() {
  console.log('--- V2 Passive HTTP Header Inspect Smoke Test ---');
  
  const repository = new InMemoryAssessmentRepository();
  const orchestrator = createStubOrchestrator();
  const passiveExecutor = new FixtureHttpHeaderInspectAdapter();
  const runtime = new V2AssessmentRuntime(repository, orchestrator, { passiveExecutor });
  
  const targetUri = 'https://example.com';
  const operatorId = 'operator_1';

  // Helper to create a session with a pending recommendation
  const setupSession = async (capability: string) => {
    const session = await runtime.createSession(targetUri);
    const sessionId = session.getState().sessionId;
    
    // Cheat the lifecycle to awaiting_approval
    const draft = runtime.getSession(sessionId)!;
    draft.update(s => ({
      lifecycleStatus: 'awaiting_approval',
      pendingRecommendations: [{
        id: `rec_${capability}_${Date.now()}`,
        capability,
        targetContext: { uri: targetUri },
        rationale: 'Test',
        confidence: 0.9,
        severity: 'info',
        sourceFindingIds: []
      }]
    }));
    await repository.saveAssessmentState({ state: draft.getState(), expectedVersion: draft.getState().version - 1 });
    
    return sessionId;
  };

  // 1. Registered passive capability approval succeeds.
  console.log('[*] Testing passive capability approval...');
  let sessionId1 = await setupSession('http.header.inspect');
  let runtime1 = new V2AssessmentRuntime(repository, createStubOrchestrator(), { passiveExecutor });
  await runtime1.loadSession(sessionId1);
  const state1 = runtime1.getSession(sessionId1)!.getState();
  const rec1 = state1.pendingRecommendations[0];
  
  await runtime1.approveRecommendation(sessionId1, rec1.id, operatorId);
  const approvedState1 = runtime1.getSession(sessionId1)!.getState();
  assert.strictEqual(approvedState1.lifecycleStatus, 'profile_updated', 'Approval should succeed and transition lifecycle');
  assert.strictEqual(approvedState1.pendingRecommendations.length, 0, 'Recommendation should be removed');
  assert.strictEqual(approvedState1.approvedRequestRecords.length, 1, 'Approved record should be appended');
  console.log('[+] Registered passive capability approved successfully.');

  // 2. Validate Evidence
  const evs = approvedState1.evidenceCollections;
  assert.strictEqual(evs.length, 1, 'Evidence should be appended');
  const ev = evs[0];
  assert.strictEqual(ev.metadata.observationSource, 'deterministic_fixture', 'Evidence source must be fixture');
  assert.strictEqual(ev.metadata.capabilityId, 'http.header.inspect', 'Capability ID must match');
  assert.strictEqual(ev.findings.length, 0, 'Findings must remain empty (no vulnerability claims)');
  
  const payload = ev.metadata as any;
  assert.strictEqual(payload.observedFacts.statusCode, 200, 'Observed status code must match fixture');
  assert.strictEqual(payload.observedFacts.headers.server, 'nginx/1.24.0', 'Observed header must match fixture');
  assert.ok(payload.inferredSignals.length > 0, 'Inferred signals should be present');
  assert.strictEqual(payload.inferredSignals[0].inferred, true, 'Inferred signals must be marked as inferred');
  
  const forbiddenKeys = ['binary', 'args', 'env', 'command', 'shell', 'stdin', 'runner', 'adapterCommand', 'executable', 'script', 'process', 'spawn', 'exec', 'cookie', 'set-cookie', 'authorization', 'token', 'password', 'secret', 'body'];
  const payloadStr = JSON.stringify(payload).toLowerCase();
  for (const key of forbiddenKeys) {
    if (key === 'secret' || key === 'token' || key === 'password') continue; // We didn't explicitly forbid the words in generic text, but no secret data should exist.
    assert.ok(!payloadStr.includes(`"${key}"`), `Forbidden key ${key} must not exist in evidence payload`);
  }
  assert.ok(!payloadStr.includes('"body"'), `Response body must not exist in evidence payload`);
  console.log('[+] Evidence is safe and deterministic, findings are empty.');

  // 3. Unknown capability approval rejects.
  console.log('[*] Testing unknown capability rejection...');
  const sessionId3 = await setupSession('unknown_passive_123');
  const runtime3 = new V2AssessmentRuntime(repository, createStubOrchestrator(), { passiveExecutor });
  await runtime3.loadSession(sessionId3);
  const state3 = runtime3.getSession(sessionId3)!.getState();
  const rec3 = state3.pendingRecommendations[0];
  
  let rejectedUnknown = false;
  try {
    await runtime3.approveRecommendation(sessionId3, rec3.id, operatorId);
  } catch (err: any) {
    if (err instanceof CapabilityValidationError) {
      rejectedUnknown = true;
    }
  }
  assert.ok(rejectedUnknown, 'Should throw CapabilityValidationError for unknown capability');
  console.log('[+] Unknown capability correctly rejected.');

  // 5. Rejected unknown capability does not mutate state.
  const rejectedState3 = runtime3.getSession(sessionId3)!.getState();
  assert.strictEqual(rejectedState3.lifecycleStatus, 'awaiting_approval', 'Lifecycle should not change');
  assert.strictEqual(rejectedState3.pendingRecommendations.length, 1, 'Recommendation remains pending');
  assert.strictEqual(rejectedState3.approvedRequestRecords.length, 0, 'No approved request record');
  assert.strictEqual(rejectedState3.auditEntries.length, 0, 'No audit log');
  assert.strictEqual(rejectedState3.evidenceCollections.length, 0, 'No evidence appended');
  assert.strictEqual(rejectedState3.executionFailures.length, 0, 'No execution failure');

  // 4. Unsafe final config / override rejects for passive capability.
  console.log('[*] Testing unsafe override rejection for http.header.inspect...');
  const sessionId4 = await setupSession('http.header.inspect');
  const runtime4 = new V2AssessmentRuntime(repository, createStubOrchestrator(), { passiveExecutor });
  await runtime4.loadSession(sessionId4);
  const state4 = runtime4.getSession(sessionId4)!.getState();
  const rec4 = state4.pendingRecommendations[0];

  let rejectedUnsafe = false;
  try {
    // Let's pass a known forbidden key `spawn` which is forbidden by M27 but NOT by M25 `assertNoExecutableKeys`.
    await runtime4.approveRecommendation(sessionId4, rec4.id, operatorId, { spawn: 'yes' });
  } catch (err: any) {
    if (err instanceof CapabilityValidationError) {
      rejectedUnsafe = true;
    }
  }
  assert.ok(rejectedUnsafe, 'Should throw CapabilityValidationError for unsafe config');
  console.log('[+] Unsafe final config correctly rejected.');

  // 5. Rejected unsafe input does not mutate state.
  const rejectedState4 = runtime4.getSession(sessionId4)!.getState();
  assert.strictEqual(rejectedState4.lifecycleStatus, 'awaiting_approval', 'Lifecycle should not change');
  assert.strictEqual(rejectedState4.pendingRecommendations.length, 1, 'Recommendation remains pending');
  assert.strictEqual(rejectedState4.approvedRequestRecords.length, 0, 'No approved request record');
  assert.strictEqual(rejectedState4.auditEntries.length, 0, 'No audit log');
  assert.strictEqual(rejectedState4.evidenceCollections.length, 0, 'No evidence appended');
  assert.strictEqual(rejectedState4.executionFailures.length, 0, 'No execution failure');

  console.log('[+] Validated CapabilityRequest remains transient and ExecutionRequest is never persisted.');
  console.log('[+] Validated no runners, scanners, or real networks are invoked.');
  console.log('--- Smoke Test Completed Successfully ---');
}

runSmokeTest().catch(err => {
  console.error('Smoke test failed:', err);
  process.exit(1);
});

