/**
 * Milestone 12 — Runtime Storage Integration Smoke Test
 *
 * Deterministically exercises the full runtime-storage integration loop:
 *   createSession ? startInitialRecon ? runIntelligence ? approveRecommendation
 *   ? runIntelligence (second pass) ? completeSession
 *
 * Uses an explicit InMemoryAssessmentRepository passed to the runtime so all
 * repository state can be inspected directly. Uses a deterministic
 * StubOrchestrator injected via constructor so the test never relies on real
 * tool binaries.
 *
 * No sleeps. No private reflection. No direct save state calls on repository
 * from this file. No approval-path skipping.
 */
import { V2AssessmentRuntime } from '../runtime/V2AssessmentRuntime';
import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository';
import { createStubOrchestrator } from './StubToolRegistry';

console.log('--- V2 Runtime + Storage Milestone 12 Smoke Test ---');

async function runSmoke() {
  const repository = new InMemoryAssessmentRepository();
  const runtime = new V2AssessmentRuntime(repository, createStubOrchestrator());
  const targetUri = 'https://example.com';

  console.log(`[*] Creating session for ${targetUri}`);
  const session = await runtime.createSession(targetUri);
  const sessionId = session.getState().sessionId;

  // 1. Repository must have persisted the initial state
  let savedState = await repository.loadAssessmentState(sessionId);
  if (!savedState) throw new Error('Failed to load initial state from repository');
  console.log(`[+] Loaded initial state from repo. Version: ${savedState.version}`);

  console.log('[*] Starting Initial Recon...');
  let state = await runtime.startInitialRecon(sessionId);

  if (state.lifecycleStatus === 'failed') {
    console.error('[!] Session failed during initial recon:', state.errors);
    process.exit(1);
  }

  // 2. Repository must have evidence after recon
  let evList = await repository.listEvidence(sessionId);
  if (evList.length < 1) throw new Error('Repository is missing evidence after initial recon');
  console.log(`[+] Repository has ${evList.length} evidence record(s) after initial recon`);

  console.log('[*] Running First Intelligence Pass...');
  state = await runtime.runIntelligence(sessionId);

  // 3. Must have a recommendation — stub always produces subdomain_discovery finding
  //    which triggers the SubdomainHttpProbeRule recommendation.
  if (state.pendingRecommendations.length === 0) {
    throw new Error('Deterministic stub failed to produce a recommendation. Cannot test approval path.');
  }

  const rec = state.pendingRecommendations[0];
  console.log(`[+] Intelligence produced recommendation: ${rec.id} (${rec.capability})`);

  // 4. Repository must reflect the pending recommendation
  savedState = await repository.loadAssessmentState(sessionId);
  if (!savedState || savedState.pendingRecommendations.length === 0) {
    throw new Error('Repository state is missing pending recommendation after runIntelligence');
  }

  console.log('[*] Approving Recommendation via Runtime...');
  state = await runtime.approveRecommendation(sessionId, rec.id, 'smoke_operator');

  // 5. Repository state must be updated after approval
  savedState = await repository.loadAssessmentState(sessionId);
  if (!savedState) throw new Error('Failed to load state after approval');

  // 6. Repository must have at least one approved request record
  const apList = await repository.listApprovedRequests(sessionId);
  if (apList.length < 1) throw new Error('Repository is missing approved request records after approval');

  // 7. Repository must have at least one audit entry from the approval
  const auList = await repository.listAuditEntries(sessionId);
  if (auList.length < 1) throw new Error('Repository is missing audit entries after approval');

  // 8. Repository must have evidence from the approved execution (http_probe stub)
  evList = await repository.listEvidence(sessionId);
  if (evList.length < 2) throw new Error('Repository is missing evidence from approved execution path');

  console.log('[+] Repository has Evidence, ApprovedRequest, and AuditEntry records after approval');

  // 9. No raw CapabilityRequest must be stored
  if ('approvedRequests' in savedState!) {
    throw new Error('AssessmentState incorrectly stored raw CapabilityRequest[]');
  }
  const summary = (await repository.listSessions())[0];
  if ('approvedRequests' in summary || 'CapabilityRequest' in summary) {
    throw new Error('Storage adapter leaked executable state into summary');
  }

  console.log('[*] Running Second Intelligence Pass...');
  state = await runtime.runIntelligence(sessionId);

  if (!state.currentProfile || !state.currentProfile.metadata.httpServices ||
      Object.keys(state.currentProfile.metadata.httpServices).length === 0) {
    console.error('[!] Expected TargetProfile to be enriched with HTTP service metadata.');
    process.exit(1);
  }
  console.log('[+] TargetProfile enriched with HTTP service metadata');

  console.log('[*] Completing Session...');
  state = await runtime.completeSession(sessionId);

  // 10. Repository-loaded final state must be completed
  savedState = await repository.loadAssessmentState(sessionId);
  if (savedState?.lifecycleStatus !== 'completed') {
    throw new Error(`Repository final state is not completed: ${savedState?.lifecycleStatus}`);
  }

  console.log(`[+] Session complete. Final lifecycleStatus: ${state.lifecycleStatus}`);
  console.log('--- Smoke Test Completed Successfully ---');
}

runSmoke().catch(err => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
