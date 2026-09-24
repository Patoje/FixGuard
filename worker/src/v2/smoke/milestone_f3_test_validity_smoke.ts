/**
 * Etapa 2 · F3 foundation — DefenseObservation + TestValidity smoke
 *
 * Verifies:
 * 1. Passive WAF/CDN/bot/rate-limit observations from HTTP facets
 * 2. interference_check: probe blocked + control OK → interfered
 * 3. Both blocked → inconclusive
 * 4. Clean response → valid + allowsVerificationMutation
 * 5. interfered ≠ safe: canMutateVerificationState is false
 * 6. AttackRecommendation soft-penalizes spray caps when blocking defenses present
 * 7. Reason-code bridge tags Cloudflare/challenge as interfered
 */

import assert from 'node:assert/strict';
import { observeDefensesFromHttpResponse, isBlockingDefense } from '../test-validity/DefenseObservationService.js';
import {
  canMutateVerificationState,
  evaluateTestValidity,
  evaluateTestValidityFromReasonCode,
} from '../test-validity/TestValidityService.js';
import { TEST_VALIDITY_CONTRACT_VERSION } from '../test-validity/TestValidityContracts.js';
import { AttackRecommendationService } from '../attack-recommendation/AttackRecommendationService.js';
import type { Finding } from '../core/Evidence.js';
import type { AttackCapabilityKind } from '../attack-planning/AttackPlanContracts.js';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function assertTrue(condition: boolean, message: string): void {
  if (!condition) fail(message);
}

async function testPassiveWafObservation(): Promise<void> {
  const defenses = observeDefensesFromHttpResponse({
    statusCode: 403,
    headerNames: ['cf-ray', 'server'],
    headerValues: { 'cf-ray': 'abc', server: 'cloudflare' },
    bodyExcerpt: 'Just a moment... cf-browser-verification',
    targetHost: 'app.example.com',
  });
  assertTrue(defenses.length >= 1, 'expected at least one defense observation');
  assertTrue(
    defenses.some((d) => d.controlKind === 'waf' || d.controlKind === 'bot'),
    'expected waf or bot control'
  );
  assertTrue(
    defenses.every((d) => d.contractVersion === TEST_VALIDITY_CONTRACT_VERSION),
    'contract version mismatch'
  );
  assertTrue(defenses.some(isBlockingDefense), 'expected blocking defense');
  console.log(`[+] Test 1: passive WAF/bot observation (${defenses.length} obs)`);
}

async function testInterferenceCheck(): Promise<void> {
  const evaluation = evaluateTestValidity({
    probe: {
      statusCode: 403,
      bodyExcerpt: 'Vercel Security Checkpoint',
      targetHost: 'teclaaa.vercel.app',
    },
    control: {
      statusCode: 200,
      bodyExcerpt: '{"ok":true}',
      targetHost: 'teclaaa.vercel.app',
    },
    observedAt: '2026-09-24T18:00:00.000Z',
  });
  assert.equal(evaluation.verdict, 'interfered');
  assert.equal(evaluation.allowsVerificationMutation, false);
  assertTrue(!canMutateVerificationState(evaluation), 'must not mutate on interfered');
  assertTrue(
    evaluation.defenses.some((d) => d.signalSource === 'control_differential'),
    'expected control_differential defense'
  );
  console.log('[+] Test 2: interference_check → interfered (mutation denied)');
}

async function testBothBlockedInconclusive(): Promise<void> {
  const evaluation = evaluateTestValidity({
    probe: { statusCode: 403, bodyExcerpt: 'Attention Required' },
    control: { statusCode: 403, bodyExcerpt: 'Attention Required' },
  });
  assert.equal(evaluation.verdict, 'inconclusive');
  assert.equal(evaluation.allowsVerificationMutation, false);
  console.log('[+] Test 3: both blocked → inconclusive');
}

async function testValidMeasurement(): Promise<void> {
  const evaluation = evaluateTestValidity({
    probe: {
      statusCode: 200,
      bodyExcerpt: '{"id":1,"name":"alice"}',
      headerNames: ['content-type'],
    },
  });
  assert.equal(evaluation.verdict, 'valid');
  assert.equal(evaluation.allowsVerificationMutation, true);
  assertTrue(canMutateVerificationState(evaluation), 'valid must allow mutation');
  console.log('[+] Test 4: clean response → valid');
}

async function testReasonCodeBridge(): Promise<void> {
  const evaluation = evaluateTestValidityFromReasonCode('cloudflare_challenge_blocked');
  assert.equal(evaluation.verdict, 'interfered');
  assertTrue(!canMutateVerificationState(evaluation), 'reason bridge must deny mutation');
  console.log('[+] Test 5: reason-code bridge → interfered');
}

async function testRecommendationSoftPenalty(): Promise<void> {
  const finding: Finding = {
    id: 'fnd_xss_1',
    type: 'CROSS_SITE_SCRIPTING',
    severity: 'medium',
    title: 'Reflected parameter',
    description: 'canary reflected',
    target: 'https://app.example.com/search?q=1',
    evidence: 'observed',
    confidence: 0.8,
    verificationState: 'observed_anomaly',
    metadata: {
      kind: 'input_validation_flaw_metadata',
      category: 'PARAMETER_REFLECTION',
      candidateId: 'cand_xss',
      evidenceRecordId: 'evr_xss',
      lineage: {},
      parameterName: 'q',
      reflectedCanary: 'fgcanary',
    },
  };

  const registered = new Set<AttackCapabilityKind>([
    'nuclei_xss_scan',
    'idor_read_differential',
  ]);

  const defenses = observeDefensesFromHttpResponse({
    statusCode: 403,
    headerValues: { 'cf-ray': 'xyz', server: 'cloudflare' },
    bodyExcerpt: 'Just a moment',
  });

  const service = new AttackRecommendationService();
  const without = service.recommend({
    assessmentId: 'asmt_tv_1',
    scanId: 'scn_tv_1',
    finding,
    preconditions: {
      identityCount: 0,
      hasJwtIdentity: false,
      hasCredentialedCorsSignal: false,
      hasObservedParameter: true,
      hasCredentialReference: false,
    },
    registeredCapabilities: registered,
    lineage: {
      assessmentId: 'asmt_tv_1',
      scanId: 'scn_tv_1',
      authorizationGrantId: 'grn_tv_1',
      authorizationDecisionId: 'dec_tv_1',
      actorId: 'usr_tv',
    },
    stackHints: { hasPhpLegacy: true },
  });

  const withDef = service.recommend({
    assessmentId: 'asmt_tv_1',
    scanId: 'scn_tv_1',
    finding,
    preconditions: {
      identityCount: 0,
      hasJwtIdentity: false,
      hasCredentialedCorsSignal: false,
      hasObservedParameter: true,
      hasCredentialReference: false,
    },
    registeredCapabilities: registered,
    lineage: {
      assessmentId: 'asmt_tv_1',
      scanId: 'scn_tv_1',
      authorizationGrantId: 'grn_tv_1',
      authorizationDecisionId: 'dec_tv_1',
      actorId: 'usr_tv',
    },
    stackHints: { hasPhpLegacy: true },
    defenseObservations: defenses,
  });

  const nucleiWithout = without.recommendations.find(
    (r) => r.capabilityKind === 'nuclei_xss_scan'
  );
  const nucleiWith = withDef.recommendations.find(
    (r) => r.capabilityKind === 'nuclei_xss_scan'
  );
  assertTrue(!!nucleiWithout && !!nucleiWith, 'nuclei recommendation missing');
  assertTrue(
    nucleiWith!.score < nucleiWithout!.score,
    `expected soft penalty (${nucleiWith!.score} < ${nucleiWithout!.score})`
  );
  assertTrue(
    withDef.rulesApplied.includes('rule_defense_observation_soft_penalty'),
    'expected defense soft-penalty rule'
  );
  console.log(
    `[+] Test 6: recommendation soft-penalty nuclei ${nucleiWithout!.score} → ${nucleiWith!.score}`
  );
}

async function main(): Promise<void> {
  console.log('=== FixGuard V2: DefenseObservation + TestValidity (F3 foundation) ===');
  await testPassiveWafObservation();
  await testInterferenceCheck();
  await testBothBlockedInconclusive();
  await testValidMeasurement();
  await testReasonCodeBridge();
  await testRecommendationSoftPenalty();
  console.log('=== ALL TESTS PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
