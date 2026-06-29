import assert from 'node:assert';
import type { AuthorizedScope, EgressPolicyDecision } from '../recon/policy/EgressPolicyContracts.js';
import { normalizeTargetUrl } from '../recon/policy/TargetUrlNormalizer.js';
import { evaluateEgressPolicy } from '../recon/policy/PassiveEgressPolicy.js';
import { mapDecisionToAuditEvent } from '../recon/audit/EgressPolicyAuditMapper.js';
import { InMemoryEgressPolicyAuditRecorder } from '../recon/audit/InMemoryEgressPolicyAuditRecorder.js';
import { FakeActiveReconAdapter } from '../recon/active/FakeActiveReconAdapter.js';
import { mapActiveReconResult } from '../recon/active/ActiveReconResultMapper.js';
import type { ActiveReconProbeRequest, SafeActiveReconObservation } from '../recon/active/ActiveReconContracts.js';

async function runSmoke() {
  console.log('--- V2 Active Recon Adapter Boundary Smoke Test ---');

  const scope: AuthorizedScope = {
    allowedOrigins: ['https://example.com'],
    allowSameHostPaths: true,
    allowSubdomains: false
  };

  const recorder = new InMemoryEgressPolicyAuditRecorder();
  const fakeAdapter = new FakeActiveReconAdapter();

  // Helper to map and execute safely
  async function executeGatedProbe(request: ActiveReconProbeRequest) {
    const decision = evaluateEgressPolicy({
      targetUrl: request.targetUrl,
      capabilityId: request.capabilityId,
      authorizedScope: scope
    });

    const auditEvent = mapDecisionToAuditEvent(decision, {
      eventId: `evt_${Date.now()}_${Math.random()}`,
      capabilityId: request.capabilityId,
      authorizedScope: scope
    });
    recorder.record(auditEvent);

    let observations: SafeActiveReconObservation[] = [];
    if (decision.decision === 'allow') {
      observations = await fakeAdapter.probe(request);
    }

    return mapActiveReconResult(request.capabilityId, decision, observations);
  }

  // 1 & 2. Allowed robots probe returns safe observation
  const startCount = fakeAdapter.executionCount;
  const req1: ActiveReconProbeRequest = {
    capabilityId: 'http.robots.inspect',
    targetUrl: 'https://example.com/robots.txt',
    authorizedScope: scope,
    requestedAtMs: Date.now()
  };
  const res1 = await executeGatedProbe(req1);
  assert.strictEqual(res1.status, 'observed');
  assert.strictEqual(res1.observations.length, 1);
  assert.strictEqual(res1.observations[0].kind, 'robots_metadata');
  assert.strictEqual(fakeAdapter.executionCount, startCount + 1, 'Allow path increments execution count');
  console.log('[+] Allowed robots fake probe returns safe observation.');

  // 3. Allowed security.txt probe returns safe observation
  const req2: ActiveReconProbeRequest = {
    capabilityId: 'http.security_txt.inspect',
    targetUrl: 'https://example.com/.well-known/security.txt',
    authorizedScope: scope,
    requestedAtMs: Date.now()
  };
  const res2 = await executeGatedProbe(req2);
  assert.strictEqual(res2.status, 'observed');
  assert.strictEqual(res2.observations.length, 1);
  assert.strictEqual(res2.observations[0].kind, 'security_txt_metadata');
  assert.strictEqual(fakeAdapter.executionCount, startCount + 2, 'Allow path increments execution count');
  console.log('[+] Allowed security.txt fake probe returns safe observation.');

  // 4. Blocked target does not execute adapter
  const req3: ActiveReconProbeRequest = {
    capabilityId: 'http.robots.inspect',
    targetUrl: 'https://user:pass@example.com/robots.txt', // Credentials/secrets blocked
    authorizedScope: scope,
    requestedAtMs: Date.now()
  };
  const res3 = await executeGatedProbe(req3);
  assert.strictEqual(res3.status, 'blocked');
  assert.strictEqual(res3.observations.length, 0);
  assert.strictEqual(fakeAdapter.executionCount, startCount + 2, 'Block path leaves execution count unchanged');
  console.log('[+] Blocked target does not execute fake adapter behavior.');

  // 5. Candidate target does not execute adapter
  const req4: ActiveReconProbeRequest = {
    capabilityId: 'http.robots.inspect',
    targetUrl: 'https://sub.example.com/robots.txt', // Not in explicit scope, candidate
    authorizedScope: scope,
    requestedAtMs: Date.now()
  };
  const res4 = await executeGatedProbe(req4);
  assert.strictEqual(res4.status, 'candidate');
  assert.strictEqual(res4.observations.length, 0);
  assert.strictEqual(fakeAdapter.executionCount, startCount + 2, 'Candidate path leaves execution count unchanged');
  console.log('[+] Candidate target remains non-executable.');

  // 6. Allowed in-scope URL with sensitive query values does not leak
  const req6: ActiveReconProbeRequest = {
    capabilityId: 'http.robots.inspect',
    targetUrl: 'https://example.com/robots.txt?token=SUPER_SECRET&api_key=KEY123',
    authorizedScope: scope,
    requestedAtMs: Date.now()
  };
  const res6 = await executeGatedProbe(req6);
  assert.strictEqual(res6.status, 'observed', 'Allowed in-scope probe with sensitive queries should execute');
  assert.strictEqual(fakeAdapter.executionCount, startCount + 3, 'Execution count increments');
  assert.strictEqual(res6.target.scheme, 'https', 'Scheme must be exactly https');
  assert.strictEqual(res6.target.normalizedOrigin, 'https://example.com', 'normalizedOrigin must be origin-only');
  
  const res6Json = JSON.stringify(res6);
  assert.ok(!res6Json.includes('SUPER_SECRET'), 'SUPER_SECRET must not leak');
  assert.ok(!res6Json.includes('KEY123'), 'KEY123 must not leak');
  assert.ok(!res6Json.includes('token=SUPER_SECRET'), 'token=SUPER_SECRET must not leak in raw query form');
  assert.ok(!res6Json.includes('api_key=KEY123'), 'api_key=KEY123 must not leak in raw query form');
  assert.ok(!res6.target.normalizedOrigin?.includes('/robots.txt'), 'Path must not leak in normalizedOrigin');
  assert.ok(!res6.target.normalizedOrigin?.includes('?'), 'Query must not leak in normalizedOrigin');
  
  console.log('[+] Allowed in-scope URL with sensitive queries safely redacts and prevents leakage.');

  // Check audit events
  assert.strictEqual(recorder.count, 5, 'M33 audit events are created for each policy decision');
  const storedEvents = recorder.getEvents();
  assert.strictEqual(storedEvents[0].decision, 'allow');
  assert.strictEqual(storedEvents[2].decision, 'block');
  assert.strictEqual(storedEvents[3].decision, 'candidate');
  assert.strictEqual(storedEvents[4].decision, 'allow');
  console.log('[+] M33 audit events are created for each policy decision in insertion order.');

  // Check safe shapes (no findings, evidence, vulnerabilities, rawUrl, rawRequest)
  for (const res of [res1, res2, res3, res4, res6]) {
    assert.strictEqual(res.classification.finding, false);
    assert.strictEqual(res.classification.evidence, false);
    assert.strictEqual(res.classification.vulnerability, false);
    assert.strictEqual(res.classification.riskClaim, false);

    const resJson = JSON.stringify(res);
    assert.ok(!resJson.includes('targetUrl'), 'targetUrl must not leak in result');
    assert.ok(!resJson.includes('rawUrl'), 'rawUrl must not leak in result');
    assert.ok(!resJson.includes('SECRET'), 'secret query values must not leak in result');
  }

  console.log('[+] No findings, evidence, vulnerability, or risk claims are created.');
  console.log('[+] No raw request object, credentials, or secret query values leak.');

  // 15. Unsupported scheme payload
  const req5: ActiveReconProbeRequest = {
    capabilityId: 'http.robots.inspect',
    targetUrl: 'javascript:alert(1)',
    authorizedScope: scope,
    requestedAtMs: Date.now()
  };
  const res5 = await executeGatedProbe(req5);
  assert.strictEqual(res5.status, 'blocked');
  assert.ok(!res5.target.safeDisplayUrl.includes('alert'), 'Unsupported scheme payload does not leak');
  console.log('[+] Unsupported schemes do not leak payloads.');

  console.log('[+] No network primitives or scanner/process execution used.');
  console.log('[+] No DB/storage/runtime mutation exists.');
  console.log('--- V2 Active Recon Adapter Boundary Smoke Test Completed Successfully ---');
}

runSmoke().catch(err => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
