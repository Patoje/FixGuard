/**
 * Etapa 2 · F2 — HypothesisScheduler smoke
 */
import assert from 'node:assert/strict';
import {
  HypothesisSchedulerService,
  resolveHypothesisPreconditions,
} from '../hypothesis-scheduler/HypothesisSchedulerService.js';

function main(): void {
  console.log('=== F2 HypothesisScheduler smoke ===');

  {
    const pre = resolveHypothesisPreconditions({
      hypothesisKind: 'auth_boundary_differential',
      identityCount: 0,
      hasJwtIdentity: false,
    });
    assert.equal(pre.satisfied, false);
    assert.equal(pre.blockReason, 'missing_byot_identities');
    const ok = resolveHypothesisPreconditions({
      hypothesisKind: 'auth_boundary_differential',
      identityCount: 1,
      hasJwtIdentity: false,
    });
    assert.equal(ok.satisfied, true);
    console.log('[+] auth_boundary_differential A+anon preconditions OK');
  }

  {
    const pre = resolveHypothesisPreconditions({
      hypothesisKind: 'idor_differential',
      identityCount: 0,
      hasJwtIdentity: false,
    });
    assert.equal(pre.satisfied, false);
    assert.equal(pre.blockReason, 'missing_byot_identities');
    assert.ok(pre.subHypothesisTitle);
    console.log('[+] PreconditionResolver missing BYOT OK');
  }

  {
    const pre = resolveHypothesisPreconditions({
      hypothesisKind: 'idor_differential',
      identityCount: 2,
      hasJwtIdentity: false,
    });
    assert.equal(pre.satisfied, true);
    assert.equal(pre.blockReason, 'none');
    console.log('[+] PreconditionResolver BYOT satisfied OK');
  }

  {
    const service = new HypothesisSchedulerService();
    const result = service.schedule({
      assessmentId: 'asmt_f2_001',
      scanId: 'scn_f2_001',
      identityCount: 0,
      hasJwtIdentity: false,
      stackHints: { hasSpa: true, hasVercel: true, hasNextJs: true },
      asgNodeKinds: ['endpoint', 'application'],
      findings: [
        {
          id: 'fnd_idor_1',
          type: 'BROKEN_ACCESS_CONTROL',
          metadataKind: 'broken_access_control_metadata',
        },
        {
          id: 'fnd_headers_1',
          type: 'SECURITY_MISCONFIGURATION',
          metadataKind: 'missing_security_headers_metadata',
        },
      ],
    });
    assert.ok(result.hypotheses.length >= 2);
    const idor = result.hypotheses.find((h) => h.hypothesisKind === 'idor_differential');
    assert.ok(idor);
    assert.equal(idor!.blocked, true);
    assert.equal(idor!.blockReason, 'missing_byot_identities');
    assert.ok(idor!.subHypothesis);
    const headers = result.hypotheses.find((h) => h.hypothesisKind === 'header_hardening_gap');
    assert.ok(headers);
    assert.equal(headers!.blocked, true);
    assert.ok(headers!.score < 30);
    const spa = result.hypotheses.find((h) => h.hypothesisKind === 'spa_surface_probe');
    assert.ok(spa);
    assert.equal(spa!.blocked, true);
    assert.equal(spa!.blockReason, 'stack_policy_deprioritized');
    assert.ok(result.rulesApplied.includes('rule_finding_idor_differential'));
    console.log('[+] Scheduler ranking + block reasons OK');
  }

  {
    const service = new HypothesisSchedulerService();
    const result = service.schedule({
      assessmentId: 'asmt_f2_002',
      scanId: 'scn_f2_002',
      identityCount: 2,
      hasJwtIdentity: true,
      findings: [
        {
          id: 'fnd_idor_2',
          type: 'BROKEN_ACCESS_CONTROL',
          metadataKind: 'broken_access_control_metadata',
        },
      ],
    });
    const idor = result.hypotheses.find((h) => h.sourceFindingIds.includes('fnd_idor_2'));
    assert.ok(idor);
    assert.equal(idor!.blocked, false);
    assert.ok(idor!.score >= 90);
    console.log('[+] Unblocked IDOR with BYOT OK');
  }

  {
    const service = new HypothesisSchedulerService();
    const result = service.schedule({
      assessmentId: 'asmt_f2_003',
      scanId: 'scn_f2_003',
      identityCount: 1,
      hasJwtIdentity: false,
      hasObservedParameter: false,
      asgNodeKinds: ['endpoint'],
      findings: [],
    });
    const boundary = result.hypotheses.find((h) => h.hypothesisKind === 'auth_boundary_differential');
    assert.ok(boundary);
    assert.equal(boundary!.blocked, false);
    assert.equal(boundary!.suggestedCapability, 'auth_boundary_differential');
    assert.equal(boundary!.sourceFindingIds.length, 0);
    const idor = result.hypotheses.find((h) => h.hypothesisKind === 'idor_differential');
    assert.ok(idor);
    assert.equal(idor!.blocked, true);
    assert.equal(idor!.blockReason, 'missing_byot_identities');
    const bypass = result.hypotheses.find((h) => h.hypothesisKind === 'auth_bypass');
    assert.ok(bypass);
    assert.equal(bypass!.blocked, false);
    const jwt = result.hypotheses.find((h) => h.hypothesisKind === 'jwt_confusion');
    assert.ok(jwt);
    assert.equal(jwt!.blocked, true);
    assert.equal(jwt!.blockReason, 'missing_jwt_identity');
    const sql = result.hypotheses.find((h) => h.hypothesisKind === 'sql_oracle');
    assert.ok(sql);
    assert.equal(sql!.blocked, true);
    assert.equal(sql!.suggestedCapability, undefined);
    assert.equal(sql!.blockReason, 'missing_parameter');
    console.log('[+] One identity emits auth boundary; IDOR stays blocked; SQL/JWT/bypass are hypotheses');
  }

  console.log('=== F2 HypothesisScheduler smoke: ALL PASSED ===');
}

try {
  main();
} catch (err: unknown) {
  console.error(err);
  process.exit(1);
}
