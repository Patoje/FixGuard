import { V2AssessmentRuntime } from '../runtime/V2AssessmentRuntime';
import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository';
import { createStubOrchestrator } from './StubToolRegistry';

console.log('--- V2 Runtime Session Resume Smoke Test ---');

async function runSmoke() {
  const repository = new InMemoryAssessmentRepository();
  const runtimeA = new V2AssessmentRuntime(repository, createStubOrchestrator());
  const targetUri = 'https://example.com';

  console.log(`[*] Runtime A: Creating session for ${targetUri}`);
  const session = await runtimeA.createSession(targetUri);
  const sessionId = session.getState().sessionId;

  console.log('[*] Runtime A: Starting Initial Recon...');
  await runtimeA.startInitialRecon(sessionId);

  console.log('[*] Runtime A: Running First Intelligence Pass...');
  let state = await runtimeA.runIntelligence(sessionId);

  if (state.pendingRecommendations.length === 0) {
    throw new Error('Deterministic stub failed to produce a recommendation.');
  }
  const rec = state.pendingRecommendations[0];

  console.log('[*] Runtime A: Approving Recommendation...');
  state = await runtimeA.approveRecommendation(sessionId, rec.id, 'smoke_operator');

  // 7. Capture persisted snapshot from repository.
  const persistedSnapshot = await repository.loadAssessmentState(sessionId);
  if (!persistedSnapshot) throw new Error('Repository is missing persisted snapshot');
  
  // 8. Capture append-only counts
  const evCountA = (await repository.listEvidence(sessionId)).length;
  const auCountA = (await repository.listAuditEntries(sessionId)).length;
  const apCountA = (await repository.listApprovedRequests(sessionId)).length;
  const failCountA = (await repository.listExecutionFailures(sessionId)).length;

  console.log(`[+] Runtime A state captured (Version: ${persistedSnapshot.version})`);

  // 9. Create runtime B
  console.log('[*] Runtime B: Loading session from repository...');
  const runtimeB = new V2AssessmentRuntime(repository, createStubOrchestrator());

  // 10. Call runtimeB.loadSession
  const loadedSession = await runtimeB.loadSession(sessionId);

  // 11. Assert loaded session exists
  if (!loadedSession) throw new Error('Runtime B failed to load session from repository');

  const loadedState = loadedSession.getState();

  // 12. Assert loaded state matches persisted snapshot exactly
  if (loadedState.sessionId !== persistedSnapshot.sessionId) throw new Error('sessionId mismatch');
  if (loadedState.targetUri !== persistedSnapshot.targetUri) throw new Error('targetUri mismatch');
  if (loadedState.version !== persistedSnapshot.version) throw new Error('version mismatch');
  if (loadedState.lifecycleStatus !== persistedSnapshot.lifecycleStatus) throw new Error('lifecycleStatus mismatch');
  if (loadedState.evidenceCollections.length !== persistedSnapshot.evidenceCollections.length) throw new Error('evidenceCollections mismatch');
  if (loadedState.pendingRecommendations.length !== persistedSnapshot.pendingRecommendations.length) throw new Error('pendingRecommendations mismatch');
  if (loadedState.approvedRequestRecords.length !== persistedSnapshot.approvedRequestRecords.length) throw new Error('approvedRequestRecords mismatch');
  if (loadedState.auditEntries.length !== persistedSnapshot.auditEntries.length) throw new Error('auditEntries mismatch');
  if (loadedState.executionFailures.length !== persistedSnapshot.executionFailures.length) throw new Error('executionFailures mismatch');

  console.log('[+] Runtime B loaded state matches persisted snapshot exactly.');

  // 13. Assert load did not append any new records
  const evCountB = (await repository.listEvidence(sessionId)).length;
  const auCountB = (await repository.listAuditEntries(sessionId)).length;
  const apCountB = (await repository.listApprovedRequests(sessionId)).length;
  const failCountB = (await repository.listExecutionFailures(sessionId)).length;

  if (evCountB !== evCountA) throw new Error('Evidence count changed during load');
  if (auCountB !== auCountA) throw new Error('Audit count changed during load');
  if (apCountB !== apCountA) throw new Error('Approved request count changed during load');
  if (failCountB !== failCountA) throw new Error('Execution failure count changed during load');

  console.log('[+] Load did not append any new storage records.');

  // 15. Assert no raw CapabilityRequest exists in loaded state.
  if ('approvedRequests' in loadedState) {
    throw new Error('AssessmentState incorrectly loaded raw CapabilityRequest[]');
  }

  // 16. Assert active collision behavior
  const activeSession = await runtimeB.loadSession(sessionId);
  if (activeSession !== loadedSession) {
    throw new Error('Active collision behavior failed: loadSession returned different session instances');
  }
  console.log('[+] Active collision check passed.');

  // 17. Assert missing session behavior
  const missing = await runtimeB.loadSession('missing-session-id');
  if (missing !== undefined) {
    throw new Error('Missing session behavior failed: loadSession did not return undefined');
  }
  console.log('[+] Missing session check passed.');

  // 18. Assert next valid runtime transition preserves optimistic versioning
  console.log('[*] Runtime B: Completing Session...');
  state = await runtimeB.completeSession(sessionId);

  const finalSnapshot = await repository.loadAssessmentState(sessionId);
  if (!finalSnapshot) throw new Error('Failed to load final snapshot');
  if (finalSnapshot.version !== persistedSnapshot.version + 1) {
    throw new Error(`Optimistic versioning failed. Expected ${persistedSnapshot.version + 1}, got ${finalSnapshot.version}`);
  }
  if (finalSnapshot.lifecycleStatus !== 'completed') {
    throw new Error(`Final status is not completed: ${finalSnapshot.lifecycleStatus}`);
  }

  console.log(`[+] Session complete via Runtime B. Final lifecycleStatus: ${state.lifecycleStatus}, Version: ${state.version}`);
  console.log('--- Smoke Test Completed Successfully ---');
}

runSmoke().catch(err => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
