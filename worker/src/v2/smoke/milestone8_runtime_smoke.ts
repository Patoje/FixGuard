import { V2AssessmentRuntime } from '../runtime/V2AssessmentRuntime';
import { spawnSync } from 'child_process';
import type { Finding, EvidenceCollection } from '../core/Evidence';

console.log('--- V2 Runtime End-to-End Smoke Test ---');

// 1. Preflight checks
function checkTool(name: string, flag: string) {
  try {
    const res = spawnSync(name, [flag], { shell: false });
    if (res.error || res.status !== 0) {
      console.error(`[!] Preflight failed: ${name} is missing.`);
      process.exit(1);
    }
    console.log(`[+] Preflight: ${name} found`);
  } catch (e) {
    console.error(`[!] Preflight failed: ${name} is missing.`);
    process.exit(1);
  }
}
console.log('[*] Running Preflight Tool Checks...');
checkTool('subfinder', '-version');
checkTool('httpx', '-version');

async function runSmoke() {
  const runtime = new V2AssessmentRuntime();
  const targetUri = 'https://example.com';
  
  console.log(`[*] Creating session for ${targetUri}`);
  const session = runtime.createSession(targetUri);
  const sessionId = session.getState().sessionId;

  console.log('[*] Starting Initial Recon...');
  let state = await runtime.startInitialRecon(sessionId);

  // The deterministic fallback is only for successful zero-finding recon results in the smoke harness.
  // It must not hide missing tools, thrown execution failures, or runtime-recorded execution failures.
  if (state.lifecycleStatus === 'failed') {
    console.error('[!] Session failed during initial recon:', state.errors);
    process.exit(1);
  }

  if (state.executionFailures.length > 0) {
    console.error('[!] Runtime recorded execution failures during initial recon. Cannot safely inject fallback.');
    console.error(state.executionFailures);
    process.exit(1);
  }

  // Check if subdomain discovery had findings, if not, inject deterministic fallback trigger
  // Only for smoke testing purposes to trigger http_probe recommendation
  const initialEvidence = state.evidenceCollections[0];
  if (initialEvidence && initialEvidence.findings.length === 0) {
    console.log('[!] Subdomain discovery returned zero findings; injecting deterministic fallback trigger...');
    const fallbackFinding: Finding = {
      id: `mock_${Date.now()}`,
      type: 'subdomain_discovery',
      severity: 'info',
      title: 'Discovered Subdomain',
      description: 'Found via deterministic fallback',
      target: 'api.example.com',
      evidence: 'api.example.com',
      confidence: 1.0,
      metadata: {}
    };
    const fallbackEvidence: EvidenceCollection = {
      findings: [fallbackFinding],
      metadata: { runtimeMs: 0 }
    };
    session.update(s => ({
      evidenceCollections: [fallbackEvidence] // Replace the empty evidence for the smoke
    }));
  }

  console.log('[*] Running First Intelligence Pass...');
  state = runtime.runIntelligence(sessionId);
  
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

  // Note: we injected the fallback earlier, so evidenceCollections[0] is the fallback. evidenceCollections[1] is the http_probe result.
  if (state.evidenceCollections.length < 2) {
    console.error('[!] Expected second evidence collection from http_probe.');
    process.exit(1);
  }

  const httpEvidence = state.evidenceCollections[state.evidenceCollections.length - 1];
  console.log(`[+] http_probe returned ${httpEvidence.findings.length} live host(s)`);

  console.log('[*] Running Second Intelligence Pass...');
  state = runtime.runIntelligence(sessionId);

  const profile = state.currentProfile;
  if (!profile || !profile.metadata.httpServices || Object.keys(profile.metadata.httpServices).length === 0) {
    console.error('[!] Expected TargetProfile to be enriched with HTTP service metadata.');
    process.exit(1);
  }

  console.log('[+] TargetProfile enriched with HTTP service metadata');

  console.log('[*] Completing Session...');
  state = runtime.completeSession(sessionId);

  console.log(`[+] Session complete. Final lifecycleStatus: ${state.lifecycleStatus}`);
  console.log('--- Smoke Test Completed Successfully ---');
}

runSmoke().catch(err => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
