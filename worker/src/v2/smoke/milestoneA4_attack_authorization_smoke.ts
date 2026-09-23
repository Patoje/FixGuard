/**
 * Milestone A4 Smoke Suite — Attack Authorization Model (Graduated WeakSet Brands)
 *
 * Verifies:
 * 1. Valid authorizePlan → token passes isRuntimeAuthorizedForBlastRadius for its class
 * 2. Adversarial forgery / mismatch / prohibited classes fail closed
 */

import assert from 'node:assert/strict';
import {
  authorizePlan,
  isRuntimeAuthorizedForBlastRadius,
  AttackAuthorizationService,
} from '../attack-authorization/AttackAuthorizationService.js';
import {
  ATTACK_AUTHORIZATION_CONTRACT_VERSION,
  requiredAuthorizationLevelFor,
  type AttackAuthorizationToken,
} from '../attack-authorization/AttackAuthorizationContracts.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';
import { OrchestratedAssessmentController } from '../api/controllers/OrchestratedAssessmentController.js';
import type { Request, Response, NextFunction } from 'express';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function assertTrue(condition: boolean, message: string): void {
  if (!condition) fail(message);
}

function assertFalse(condition: boolean, message: string): void {
  if (condition) fail(message);
}

async function runSmokeTests(): Promise<void> {
  console.log('=== Milestone A4: Attack Authorization WeakSet Smoke Suite ===');

  const assessmentId = 'asm_smoke_a4_001';
  const planA = 'plan_smoke_a4_alpha';
  const planB = 'plan_smoke_a4_beta';
  const operatorId = 'act_smoke_a4_operator';
  const authorizedAt = '2026-09-23T18:30:00.000Z';

  // --- Test 1: Valid authorization brands correctly ---
  const established = authorizePlan(
    planA,
    assessmentId,
    'read_escalated',
    operatorId,
    authorizedAt
  );
  assertTrue(established.status === 'established', 'Valid authorizePlan must establish');
  if (established.status !== 'established') fail('unreachable');
  const token = established.token;

  assertTrue(
    isRuntimeAuthorizedForBlastRadius(token, 'read_escalated', planA, assessmentId),
    'Branded token must pass isRuntimeAuthorizedForBlastRadius for its class'
  );
  assert.equal(token.authorizationLevel, 'hitl_plan_approval');
  assert.equal(Object.prototype.toString.call(token), '[object AttackAuthorizationToken]');
  assert.equal(requiredAuthorizationLevelFor('persistence'), 'PROHIBITED');
  assert.equal(requiredAuthorizationLevelFor('destructive'), 'PROHIBITED');
  console.log('[+] Test 1: valid authorization brand OK');

  // --- Test 2: read_escalated token must NOT authorize sensitive_data_access (no cascade) ---
  assertFalse(
    isRuntimeAuthorizedForBlastRadius(token, 'sensitive_data_access', planA, assessmentId),
    'Higher/adjacent class must not cascade: read_escalated ≠ sensitive_data_access'
  );
  console.log('[+] Test 2: no-cascade class mismatch OK');

  // --- Test 3: plain object literal copy (no WeakSet brand) fails ---
  const plainCopy: AttackAuthorizationToken = {
    contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
    kind: 'attack_authorization_token',
    planId: planA,
    assessmentId,
    blastRadiusClass: 'read_escalated',
    authorizationLevel: 'hitl_plan_approval',
    authorizedBy: operatorId,
    authorizedAt,
    [Symbol.toStringTag]: 'AttackAuthorizationToken',
  };
  assertFalse(
    isRuntimeAuthorizedForBlastRadius(plainCopy, 'read_escalated', planA, assessmentId),
    'Plain object literal without WeakSet brand must fail closed'
  );
  console.log('[+] Test 3: plain literal forgery rejected OK');

  // --- Test 4: spread / JSON round-trip strips brand ---
  const spreadCopy = { ...token };
  assertFalse(
    isRuntimeAuthorizedForBlastRadius(spreadCopy, 'read_escalated', planA, assessmentId),
    'Spread copy must strip WeakSet brand'
  );

  const jsonRoundTrip = JSON.parse(JSON.stringify(token)) as unknown;
  assertFalse(
    isRuntimeAuthorizedForBlastRadius(jsonRoundTrip, 'read_escalated', planA, assessmentId),
    'JSON round-trip must strip WeakSet brand'
  );
  console.log('[+] Test 4: spread/JSON brand strip OK');

  // --- Test 5: Plan A token vs Plan B bindings fails ---
  assertFalse(
    isRuntimeAuthorizedForBlastRadius(token, 'read_escalated', planB, assessmentId),
    'Plan A token must not authorize Plan B bindings'
  );
  console.log('[+] Test 5: planId binding mismatch OK');

  // --- Test 6: persistence / destructive permanently prohibited ---
  const persistenceResult = authorizePlan(
    planA,
    assessmentId,
    'persistence',
    operatorId,
    authorizedAt
  );
  assertTrue(
    persistenceResult.status === 'failed' &&
      persistenceResult.reasonCode === 'blast_radius_class_prohibited',
    'persistence must reject unconditionally'
  );

  const destructiveResult = authorizePlan(
    planA,
    assessmentId,
    'destructive',
    operatorId,
    authorizedAt
  );
  assertTrue(
    destructiveResult.status === 'failed' &&
      destructiveResult.reasonCode === 'blast_radius_class_prohibited',
    'destructive must reject unconditionally'
  );

  assertFalse(
    isRuntimeAuthorizedForBlastRadius(token, 'persistence', planA, assessmentId),
    'requiredClass=persistence must always fail closed'
  );
  assertFalse(
    isRuntimeAuthorizedForBlastRadius(token, 'destructive', planA, assessmentId),
    'requiredClass=destructive must always fail closed'
  );
  console.log('[+] Test 6: prohibited classes rejected OK');

  // --- Test 7: self-authorization fields rejected ---
  const service = new AttackAuthorizationService();
  const selfAuth = service.establishAttackAuthorization({
    contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
    kind: 'establish_attack_authorization_request',
    planId: planA,
    assessmentId,
    blastRadiusClass: 'read_public',
    operatorId,
    confirmed: true,
  });
  assertTrue(
    selfAuth.status === 'failed',
    'confirmed:true self-authorization must be rejected'
  );
  console.log('[+] Test 7: self-authorization rejected OK');

  // --- Test 8: CompositionRoot + HTTP authorize path (hermetic) ---
  const root = V2CompositionRoot.createDefault();
  assertTrue(
    root.attackAuthorizationService instanceof AttackAuthorizationService,
    'CompositionRoot must expose AttackAuthorizationService'
  );

  const controller = new OrchestratedAssessmentController(
    root.orchestratedService,
    root.attackAuthorizationService
  );

  let statusCode = 0;
  let responseBody: unknown = null;
  const req = {
    params: { assessmentId, planId: planA },
    body: {
      operatorId,
      blastRadiusClass: 'read_authenticated',
      authorizedAt,
    },
  } as unknown as Request;
  const res = {
    status(code: number) {
      statusCode = code;
      return this;
    },
    json(payload: unknown) {
      responseBody = payload;
      return this;
    },
  } as unknown as Response;
  let nextErr: unknown = undefined;
  const next: NextFunction = (err?: unknown) => {
    nextErr = err;
  };

  await controller.authorizeAttackPlan(req, res, next);
  assertTrue(nextErr === undefined, `HTTP authorize must not error: ${String(nextErr)}`);
  assert.equal(statusCode, 201);
  const body = responseBody as { status: string; token: { blastRadiusClass: string } };
  assert.equal(body.status, 'established');
  assert.equal(body.token.blastRadiusClass, 'read_authenticated');

  // Prohibited via HTTP
  let prohibitedErr: unknown = undefined;
  const prohibitedReq = {
    params: { assessmentId, planId: planA },
    body: { operatorId, blastRadiusClass: 'destructive' },
  } as unknown as Request;
  const prohibitedRes = {
    status() {
      return this;
    },
    json() {
      return this;
    },
  } as unknown as Response;
  await controller.authorizeAttackPlan(prohibitedReq, prohibitedRes, (err?: unknown) => {
    prohibitedErr = err;
  });
  assertTrue(prohibitedErr !== undefined, 'HTTP authorize destructive must fail');
  console.log('[+] Test 8: composition + HTTP authorize path OK');

  console.log('=== Milestone A4: ALL CHECKS PASSED ===');
}

runSmokeTests().catch((err: unknown) => {
  console.error('FAIL: unhandled smoke error', err);
  process.exit(1);
});
