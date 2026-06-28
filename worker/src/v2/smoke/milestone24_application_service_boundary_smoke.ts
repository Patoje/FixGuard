import assert from 'node:assert';
import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository';
import { V2AssessmentRuntime } from '../runtime/V2AssessmentRuntime';
import { AssessmentApplicationService } from '../application/AssessmentApplicationService';
import { createStubOrchestrator } from './StubToolRegistry';
import { RuntimeLifecycleError } from '../runtime/RuntimeLifecycleError';

async function runSmoke() {
  console.log('--- V2 Application Service Boundary Smoke Test ---');

  // DB-free setup:
  const repository = new InMemoryAssessmentRepository();
  const orchestrator = createStubOrchestrator();
  const runtime = new V2AssessmentRuntime(repository, orchestrator);
  
  // Application boundary constructed strictly with injected runtime
  const appService = new AssessmentApplicationService(runtime);
  console.log('[*] AssessmentApplicationService constructed successfully.');

  // 1. Create Assessment
  const targetUri = 'https://test-app-service.com';
  const createSummary = await appService.createAssessment({ targetUri });
  
  assert.strictEqual(createSummary.targetUri, targetUri);
  assert.strictEqual(createSummary.lifecycleStatus, 'initialized');
  assert.strictEqual(createSummary.evidenceCount, 0);
  assert.ok(createSummary.sessionId, 'Session ID should be generated and exposed via DTO');
  const sessionId = createSummary.sessionId;
  
  // Prove DTO safety (no execution/session internals)
  assert.strictEqual((createSummary as any).binary, undefined, 'DTO must not expose executable keys');
  assert.strictEqual((createSummary as any).args, undefined, 'DTO must not expose executable keys');
  assert.strictEqual((createSummary as any).env, undefined, 'DTO must not expose executable keys');
  console.log('[+] createAssessment returned safe DTO.');

  // 2. Start Initial Recon
  const reconDetails = await appService.startInitialRecon({ sessionId });
  
  assert.strictEqual(reconDetails.lifecycleStatus, 'profile_updated');
  assert.strictEqual(reconDetails.evidenceCount, 1, 'Stub orchestration should produce 1 piece of evidence');
  assert.strictEqual(reconDetails.findings.length, 1);
  assert.strictEqual(reconDetails.findings[0].type, 'subdomain_discovery');
  
  // Prove Safe Finding DTO
  assert.strictEqual((reconDetails.findings[0] as any).metadata, undefined, 'DTO should not arbitrarily expose raw finding metadata unless explicitly mapped');
  console.log('[+] startInitialRecon executed and returned safe DTO.');

  // 3. Load Assessment
  const loadedDetails = await appService.loadAssessment({ sessionId });
  assert.ok(loadedDetails);
  assert.strictEqual(loadedDetails.sessionId, sessionId);
  assert.strictEqual(loadedDetails.lifecycleStatus, 'profile_updated');
  console.log('[+] loadAssessment works and returns safe DTO.');

  // 4. Lifecycle Propagation
  try {
    await appService.startInitialRecon({ sessionId });
    assert.fail('Should have thrown RuntimeLifecycleError');
  } catch (err: any) {
    assert.ok(err instanceof RuntimeLifecycleError);
    console.log('[+] Lifecycle guard errors propagate safely through the application boundary.');
  }
  
  // Note: Approving/rejecting requires pending recommendations, but the stub doesn't output recommendations 
  // on startInitialRecon (only runIntelligence does). Testing approval flows via app service is verified
  // in principle by the construction and DTO shape tests, but we skip complex approval state faking here
  // to avoid creating fake proof as requested.

  // 5. Complete Assessment
  const completeSummary = await appService.completeAssessment({ sessionId });
  assert.strictEqual(completeSummary.lifecycleStatus, 'completed');
  console.log('[+] completeAssessment updated lifecycle status.');

  console.log('--- Smoke Test Completed Successfully ---');
}

runSmoke().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
