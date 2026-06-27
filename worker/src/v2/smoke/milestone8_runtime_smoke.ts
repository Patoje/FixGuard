/**
 * Milestone 8 - V2 Runtime End-to-End Smoke Test
 *
 * Uses a deterministic StubOrchestrator injected via the runtime constructor so
 * the test is independent of real tool binaries (subfinder / httpx). The stub
 * travels through the real MinimalOrchestrator ? Intelligence ? Approval path;
 * only execution is deterministic.
 *
 * Mechanical async changes only - no private reflection, no repository patching,
 * no state mutation behind the runtime persistence boundary.
 */
import { V2AssessmentRuntime } from '../runtime/V2AssessmentRuntime';
import { createStubOrchestrator } from './StubToolRegistry';

console.log('--- V2 Runtime End-to-End Smoke Test ---');

async function runSmoke() {
  const runtime = new V2AssessmentRuntime(undefined, createStubOrchestrator());

  const targetUri = 'https://example.com';
  console.log(`[*] Creating session for ${targetUri}`);
  const session = await runtime.createSession(targetUri);
  const sessionId = session.getState().sessionId;

  console.log('[*] Starting Initial Recon...');
  let state = await runtime.startInitialRecon(sessionId);

  if (state.lifecycleStatus === 'failed') {
    console.error('[!] Session failed during initial recon:', state.errors);
    process.exit(1);
  }

  if (state.executionFailures.length > 0) {
    console.error('[!] Runtime recorded execution failures during initial recon.');
    console.error(state.executionFailures);
    process.exit(1);
  }

  console.log('[*] Running First Intelligence Pass...');
  state = await runtime.runIntelligence(sessionId);

  if (state.pendingRecommendations.length === 0) {
    console.error('[!] Expected at least one recommendation, got 0.');
    process.exit(1);
  }

  const rec = state.pendingRecommendations[0];
  console.log(`[+] Intelligence produced recommendation: ${rec.id} for capability ${rec.capability}`);

  if (state.lifecycleStatus !== 'awaiting_approval') {
    console.error(`[!] Expected lifecycleStatus to be 'awaiting_approval', got ${state.lifecycleStatus}`);
    process.exit(1);
  }

  console.log('[*] Approving Recommendation via Runtime...');
  state = await runtime.approveRecommendation(sessionId, rec.id, 'smoke_operator');

  const approvedRecord = state.approvedRequestRecords.find(r => r.recommendationId === rec.id);
  if (!approvedRecord) {
    console.error('[!] Expected approvedRequestRecord to be present in state.');
    process.exit(1);
  }
  console.log(`[+] Approved request recorded for ${approvedRecord.capability} targeting ${approvedRecord.targetUri}`);

  if ('approvedRequests' in state) {
    throw new Error('AssessmentState must not store raw CapabilityRequest[]');
  }

  if (state.evidenceCollections.length < 2) {
    console.error('[!] Expected second evidence collection from approved execution (http_probe).');
    process.exit(1);
  }

  const httpEvidence = state.evidenceCollections[state.evidenceCollections.length - 1];
  console.log(`[+] Approved execution returned ${httpEvidence.findings.length} finding(s)`);

  console.log('[*] Running Second Intelligence Pass...');
  state = await runtime.runIntelligence(sessionId);

  const profile = state.currentProfile;
  if (!profile || !profile.metadata.httpServices || Object.keys(profile.metadata.httpServices).length === 0) {
    console.error('[!] Expected TargetProfile to be enriched with HTTP service metadata.');
    process.exit(1);
  }
  console.log('[+] TargetProfile enriched with HTTP service metadata');

  if (state.lifecycleStatus !== 'completed') {
    console.log('[*] Completing Session...');
    state = await runtime.completeSession(sessionId);
  }

  console.log(`[+] Session complete. Final lifecycleStatus: ${state.lifecycleStatus}`);
  console.log('--- Smoke Test Completed Successfully ---');
}

runSmoke().catch(err => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
