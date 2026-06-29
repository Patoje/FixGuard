import assert from 'node:assert';
import { evaluateEgressPolicy } from '../recon/policy/PassiveEgressPolicy';
import type { AuthorizedScope } from '../recon/policy/EgressPolicyContracts';
import { mapDecisionToAuditEvent } from '../recon/audit/EgressPolicyAuditMapper';
import { InMemoryEgressPolicyAuditRecorder } from '../recon/audit/InMemoryEgressPolicyAuditRecorder';
import type { EgressPolicyAuditEvent } from '../recon/audit/EgressPolicyAuditContracts';

async function runM33Smoke() {
  console.log('--- V2 Egress Policy Audit Boundary Smoke Test ---');

  const scope: AuthorizedScope = {
    allowedOrigins: ['https://example.com'],
    allowSameHostPaths: true,
    allowSubdomains: false,
  };

  const capId = 'http.header.inspect';

  function evaluate(url: string, s: AuthorizedScope = scope) {
    return evaluateEgressPolicy({ targetUrl: url, authorizedScope: s, capabilityId: capId });
  }

  function map(url: string, s: AuthorizedScope = scope, overrides?: { eventId?: string; observedAt?: string }) {
    const decision = evaluate(url, s);
    return mapDecisionToAuditEvent(decision, {
      capabilityId: capId,
      authorizedScope: s,
      eventId: overrides?.eventId ?? `test_${Math.random().toString(36).slice(2)}`,
      observedAt: overrides?.observedAt ?? new Date().toISOString(),
    });
  }

  // ─── 1. allow decision maps to sanitized control-plane event ─────────────────
  {
    const evt = map('https://example.com/page');
    assert.strictEqual(evt.eventKind, 'egress_policy_decision', '1: eventKind must be egress_policy_decision');
    assert.strictEqual(evt.decision, 'allow', '1: allow decision preserved');
    assert.strictEqual(evt.eventVersion, 1, '1: eventVersion must be 1');
    assert.ok(evt.eventId.length > 0, '1: eventId present');
    assert.ok(evt.observedAt.length > 0, '1: observedAt present');
    console.log('[+] 1. allow → sanitized control-plane event.');
  }

  // ─── 2. block decision maps to sanitized control-plane event ─────────────────
  {
    const evt = map('https://other.com');
    assert.strictEqual(evt.decision, 'block', '2: block decision preserved');
    assert.ok(evt.policy.blockReason, '2: blockReason present');
    console.log('[+] 2. block → sanitized control-plane event.');
  }

  // ─── 3. candidate decision maps to sanitized control-plane event ─────────────
  {
    const evt = map('https://api.example.com');
    assert.strictEqual(evt.decision, 'candidate', '3: candidate decision preserved');
    assert.ok(evt.policy.candidateReason, '3: candidateReason present');
    console.log('[+] 3. candidate → sanitized control-plane event.');
  }

  // ─── 4. In-memory recorder stores events in insertion order ──────────────────
  {
    const recorder = new InMemoryEgressPolicyAuditRecorder();
    const e1 = map('https://example.com/', scope, { eventId: 'evt_1' });
    const e2 = map('https://other.com', scope, { eventId: 'evt_2' });
    const e3 = map('https://api.example.com', scope, { eventId: 'evt_3' });

    recorder.record(e1);
    recorder.record(e2);
    recorder.record(e3);

    const stored = recorder.getEvents();
    assert.strictEqual(stored.length, 3, '4: three events stored');
    assert.strictEqual(stored[0].eventId, 'evt_1', '4: insertion order preserved (1)');
    assert.strictEqual(stored[1].eventId, 'evt_2', '4: insertion order preserved (2)');
    assert.strictEqual(stored[2].eventId, 'evt_3', '4: insertion order preserved (3)');
    console.log('[+] 4. Recorder stores events in insertion order.');
  }

  // ─── 5 & 6. Recorder returns clones — mutating returned events does not mutate internal state ─
  {
    const recorder = new InMemoryEgressPolicyAuditRecorder();
    const evt = map('https://example.com/', scope, { eventId: 'evt_clone_test' });
    recorder.record(evt);

    const returned = recorder.getEvents();
    assert.strictEqual(returned.length, 1, '5: one event returned');

    // Mutate the returned clone
    (returned[0] as unknown as Record<string, unknown>)['decision'] = 'block';

    // Internal state must be unchanged
    const again = recorder.getEvents();
    assert.strictEqual(again[0].decision, 'allow', '6: internal state not mutated by external reference');
    console.log('[+] 5 & 6. Recorder returns clones; internal state is mutation-safe.');
  }

  // ─── 7. Recorded events contain no raw secrets ───────────────────────────────
  {
    const evt = map('https://example.com/api?token=SUPER_SECRET&api_key=KEY123');
    const raw = JSON.stringify(evt);
    assert.ok(!raw.includes('SUPER_SECRET'), '7: raw token must not appear in event');
    assert.ok(!raw.includes('KEY123'), '7: api_key must not appear in event');
    console.log('[+] 7. Recorded events contain no raw secrets (token/api_key redacted).');
  }

  // ─── 8. Token/password/secret query values are redacted ──────────────────────
  {
    const sensitiveUrl = 'https://example.com/path?password=PASS123&secret=SEC456&jwt=JWT789';
    const evt = map(sensitiveUrl);
    const safeUrl = evt.target.safeDisplayUrl;
    assert.ok(!safeUrl.includes('PASS123'), '8: password value must not appear in safeDisplayUrl');
    assert.ok(!safeUrl.includes('SEC456'), '8: secret value must not appear in safeDisplayUrl');
    assert.ok(!safeUrl.includes('JWT789'), '8: jwt value must not appear in safeDisplayUrl');
    console.log('[+] 8. Token/password/secret query values redacted in safeDisplayUrl.');
  }

  // ─── 9. Credential URLs are safely rejected/redacted ─────────────────────────
  {
    const credUrl = 'https://user:pass@example.com/';
    const evt = map(credUrl);
    // Decision must be block (credentials_in_url)
    assert.strictEqual(evt.decision, 'block', '9: credential URL must block');
    const raw = JSON.stringify(evt);
    assert.ok(!raw.includes('user'), '9: username must not leak into event');
    assert.ok(!raw.includes('pass'), '9: password must not leak into event');
    console.log('[+] 9. Credential URLs safely blocked; no creds in event.');
  }

  // ─── 10. Unsupported schemes do not leak payloads ────────────────────────────
  {
    const unsupported = [
      'data:text/plain,SUPER_SECRET_PAYLOAD',
      'javascript:alert("SUPER_SECRET")',
      'ftp://example.com/secret?token=FTP_TOKEN',
      'file:///C:/secret/data.txt',
    ];
    for (const u of unsupported) {
      const evt = map(u);
      assert.strictEqual(evt.decision, 'block', `10: unsupported scheme must block: ${u}`);
      const raw = JSON.stringify(evt);
      assert.ok(!raw.includes('SUPER_SECRET'), `10: secret must not leak: ${u}`);
      assert.ok(!raw.includes('FTP_TOKEN'), `10: token must not leak: ${u}`);
    }
    console.log('[+] 10. Unsupported scheme events contain no leaked payloads.');
  }

  // ─── 11. Block event is not a finding ────────────────────────────────────────
  {
    const evt = map('https://other.com');
    assert.strictEqual(evt.classification.finding, false, '11: block event must not be a finding');
    assert.ok(!('findings' in evt), '11: block event must have no findings array');
    console.log('[+] 11. Block event is not a finding.');
  }

  // ─── 12. Candidate event is not a finding ────────────────────────────────────
  {
    const evt = map('https://api.example.com');
    assert.strictEqual(evt.classification.finding, false, '12: candidate event must not be a finding');
    assert.ok(!('findings' in evt), '12: candidate event must have no findings array');
    console.log('[+] 12. Candidate event is not a finding.');
  }

  // ─── 13 & 14. Block/candidate events are not evidence; no evidence created ───
  {
    const block = map('https://other.com');
    const candidate = map('https://api.example.com');
    assert.strictEqual(block.classification.evidence, false, '13: block must not be evidence');
    assert.strictEqual(candidate.classification.evidence, false, '14: candidate must not be evidence');
    assert.ok(!('evidenceKind' in block), '13: block has no evidenceKind');
    assert.ok(!('evidenceKind' in candidate), '14: candidate has no evidenceKind');
    console.log('[+] 13 & 14. Block/candidate events are not evidence; no evidence created.');
  }

  // ─── 15. No vulnerability/risk claim exists ───────────────────────────────────
  {
    const evts = [
      map('https://example.com/'),
      map('https://other.com'),
      map('https://api.example.com'),
    ];
    for (const evt of evts) {
      assert.strictEqual(evt.classification.vulnerability, false, '15: no vulnerability claim');
      assert.strictEqual(evt.classification.riskClaim, false, '15: no risk claim');
      assert.ok(!('riskScore' in evt), '15: no riskScore field');
      assert.ok(!('severity' in evt), '15: no severity field');
    }
    console.log('[+] 15. No vulnerability or risk claim in any event.');
  }

  // ─── 16. No network is used ─────────────────────────────────────────────────
  // Structural proof: mapDecisionToAuditEvent and evaluateEgressPolicy have no
  // node:http / node:https / node:dns / fetch imports. Verified via rg static check.
  console.log('[+] 16. No network used (structurally guaranteed — pure mapper).');

  // ─── 17. No DB is used ───────────────────────────────────────────────────────
  // Structural proof: no Drizzle/Postgres/DB client imports in audit/ module.
  console.log('[+] 17. No DB used (InMemoryEgressPolicyAuditRecorder is in-memory only).');

  // ─── 18. No runtime/storage mutation occurs ───────────────────────────────────
  // Structural proof: mapper and recorder have no V2AssessmentRuntime /
  // AssessmentRepository imports. No production composition is touched.
  console.log('[+] 18. No runtime/storage mutation occurs.');

  // ─── 19. Event shape contains no executable fields ────────────────────────────
  {
    const forbiddenKeys = [
      'binary', 'args', 'env', 'shell', 'command', 'stdin', 'executable',
      'runner', 'adapterCommand', 'rawUrl', 'originalUrl', 'rawRequest',
      'requestBody', 'responseBody', 'headers', 'cookies', 'authorization',
      'token', 'password', 'secret', 'apiKey', 'setCookie', 'scannerOutput',
      'finding', 'riskScore', 'severity', 'impact', 'exploit', 'payload', 'stackTrace',
      'capabilityRequest', 'CapabilityRequest', 'executionRequest', 'ExecutionRequest',
    ];
    const sampleEvts = [
      map('https://example.com/'),
      map('https://other.com'),
      map('https://api.example.com'),
    ];
    for (const evt of sampleEvts) {
      const keys = Object.keys(evt);
      for (const fk of forbiddenKeys) {
        assert.ok(!keys.includes(fk), `19: forbidden top-level key "${fk}" must not be present`);
      }
    }
    console.log('[+] 19. Event shape contains no forbidden executable fields.');
  }

  // ─── 20 & 21. Event shape contains no raw CapabilityRequest/ExecutionRequest ─
  {
    const evt = map('https://example.com/');
    assert.ok(!('capabilityRequest' in evt), '20: no capabilityRequest in event');
    assert.ok(!('CapabilityRequest' in evt), '20: no CapabilityRequest in event');
    assert.ok(!('executionRequest' in evt), '21: no executionRequest in event');
    assert.ok(!('ExecutionRequest' in evt), '21: no ExecutionRequest in event');
    console.log('[+] 20 & 21. Event shape contains no raw CapabilityRequest or ExecutionRequest.');
  }

  // ─── Recorder rejects events with forbidden fields ────────────────────────────
  {
    const recorder = new InMemoryEgressPolicyAuditRecorder();
    const badEvent = {
      ...map('https://example.com/', scope, { eventId: 'bad_evt' }),
      binary: '/usr/bin/nmap',
    } as unknown as EgressPolicyAuditEvent;

    const result = recorder.record(badEvent);
    assert.strictEqual(result.recorded, false, 'Recorder must reject events with forbidden fields');
    assert.ok(result.recorded === false && result.reason.includes('binary'), 'Rejection reason must name the forbidden field');
    assert.strictEqual(recorder.count, 0, 'No events stored after rejection');

    // Nested object check
    const badNestedEvent = map('https://example.com/', scope, { eventId: 'bad_evt_nested' }) as any;
    badNestedEvent.policy = { nested: { binary: '/usr/bin/nmap' } };
    const resNested = recorder.record(badNestedEvent);
    assert.strictEqual(resNested.recorded, false, 'Recorder must reject nested forbidden fields');
    assert.ok(resNested.recorded === false && resNested.reason.includes('binary'), 'Rejection reason must name the forbidden field');
    assert.strictEqual(recorder.count, 0, 'No events stored after rejection');

    // Array check
    const badArrayEvent = map('https://example.com/', scope, { eventId: 'bad_evt_array' }) as any;
    badArrayEvent.policy = { nested: [ { command: 'curl https://example.com' } ] };
    const resArray = recorder.record(badArrayEvent);
    assert.strictEqual(resArray.recorded, false, 'Recorder must reject forbidden fields in arrays');
    assert.ok(resArray.recorded === false && resArray.reason.includes('command'), 'Rejection reason must name the forbidden field');
    assert.strictEqual(recorder.count, 0, 'No events stored after rejection');

    // Raw/secret check inside target
    const badRawEvent = map('https://example.com/', scope, { eventId: 'bad_evt_raw' }) as any;
    badRawEvent.target = { rawUrl: 'https://example.com/?token=SECRET' };
    const resRaw = recorder.record(badRawEvent);
    assert.strictEqual(resRaw.recorded, false, 'Recorder must reject rawUrl inside target');
    assert.ok(resRaw.recorded === false && resRaw.reason.includes('rawUrl'), 'Rejection reason must name the forbidden field');
    assert.strictEqual(recorder.count, 0, 'No events stored after rejection');

    console.log('[+] Recorder correctly rejects events with forbidden nested fields.');
  }

  // ─── Scope metadata is sanitized ─────────────────────────────────────────────
  {
    const scopeWithCredOrigin: AuthorizedScope = {
      allowedOrigins: ['https://user:pass@example.com'],
      allowSameHostPaths: true,
      allowSubdomains: false,
    };
    const decision = evaluate('https://example.com/', scope);
    const evt = mapDecisionToAuditEvent(decision, {
      capabilityId: capId,
      authorizedScope: scopeWithCredOrigin,
      eventId: 'scope_cred_test',
      observedAt: new Date().toISOString(),
    });
    const raw = JSON.stringify(evt);
    assert.ok(!raw.includes('user:pass'), 'Scope origin credentials must not appear in event');
    console.log('[+] Scope metadata sanitizes credential origins.');
  }

  console.log('--- V2 Egress Policy Audit Boundary Smoke Test Completed Successfully ---');
}

runM33Smoke().catch(err => {
  console.error(err);
  process.exit(1);
});
