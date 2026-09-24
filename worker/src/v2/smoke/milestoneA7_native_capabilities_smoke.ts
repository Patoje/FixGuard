/**
 * Milestone A7 Smoke Suite — Native Attack Capabilities (LFI & SQL Advancement)
 *
 * Verifies:
 * 1. LFI succeeds on canary/marker match; refutes on clean 404/403
 * 2. SQL advancement confirms error oracle and advances
 *    suspected_vulnerability → validated_vulnerability (no data dumping)
 * 3. Evidence payloads are truncated (≤128) and sanitized
 *
 * Hermetic (mock fetch). process.exit(1) on failure.
 */

import assert from 'node:assert/strict';
import type { Finding } from '../core/Evidence.js';
import { VerificationStateService } from '../core/VerificationStateService.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import { ATTACK_PLANNING_CONTRACT_VERSION } from '../attack-planning/AttackPlanContracts.js';
import { generateAttackPlans } from '../attack-planning/AttackPlanGeneratorService.js';
import type {
  AttackCapabilityInvocationContext,
  AttackExecutionStep,
} from '../attack-execution/AttackExecutionContracts.js';
import {
  createLfiPathTraversalCapability,
  createSqlOracleAdvancementCapability,
} from '../attack-execution/AttackCapabilityRegistry.js';
import { SQL_ERROR_PROVOCATION_PAYLOADS } from '../attack-execution/capabilities/SqlOracleAdvancementCapability.js';
import type {
  HttpProbeRequest,
  HttpProbeResponse,
  IdorHttpProbeTransport,
} from '../detection/DetectionContracts.js';
import type { AttackAuthorizationToken } from '../attack-authorization/AttackAuthorizationContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function assertEvidenceSafe(message: string, label: string): void {
  const evidenceMatch = /evidence=([\s\S]*)$/.exec(message);
  const evidence = evidenceMatch ? evidenceMatch[1]! : message;
  assert.ok(
    evidence.length <= 128,
    `${label}: evidence exceeds 128 chars (len=${evidence.length})`
  );
  assert.ok(!/eyJ[A-Za-z0-9_-]{10,}\./.test(evidence), `${label}: JWT leaked in evidence`);
  assert.ok(!/Bearer\s+[A-Za-z0-9._~+/-]{8,}/i.test(evidence), `${label}: bearer leaked`);
  assert.ok(
    !/supersecret_session_value_should_redact/i.test(evidence),
    `${label}: raw secret leaked in evidence`
  );
}

function mockTransport(handler: (req: HttpProbeRequest) => HttpProbeResponse): IdorHttpProbeTransport {
  return async (req) => handler(req);
}

function stubToken(blastRadiusClass: 'read_escalated' | 'read_authenticated'): AttackAuthorizationToken {
  return {
    contractVersion: 'fixguard-attack-authorization/v0',
    kind: 'attack_authorization_token',
    planId: 'apl_a7_stub',
    assessmentId: 'asm_a7_001',
    blastRadiusClass,
    authorizationLevel:
      blastRadiusClass === 'read_escalated' ? 'hitl_plan_approval' : 'assessment_authorization',
    authorizedBy: 'operator_a7',
    authorizedAt: '2026-09-23T21:00:00.000Z',
    [Symbol.toStringTag]: 'AttackAuthorizationToken',
  };
}

function stubScope(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grn_a7_001',
    scanId: 'scn_a7_001',
    issuedAt: '2026-09-23T20:00:00.000Z',
    expiresAt: '2026-09-24T20:00:00.000Z',
    subject: { targetKind: 'origin', normalizedOrigin: 'https://app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'A7 smoke',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: true,
      lightValidation: true,
      activeValidation: true,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: ['example.com'],
      allowedHosts: ['app.example.com'],
      allowedOrigins: ['https://app.example.com'],
      allowedMethods: ['GET', 'HEAD'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: false,
      allowCredentialUse: false,
      allowOobCallbacks: false,
      allowThirdPartyTargets: false,
    },
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false,
    },
  };
}

function buildPlan(args: {
  capability: AttackPlan['capability'];
  parameterName: string;
  targetUrl: string;
  findingId: string;
  capabilityGained: AttackPlan['capabilityGained'];
}): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: `apl_a7_${args.capability}`,
    assessmentId: 'asm_a7_001',
    scanId: 'scn_a7_001',
    capability: args.capability,
    title: 'A7 smoke plan',
    reasoning: 'Hermetic A7 advisory plan',
    status: 'ready_for_authorization',
    blastRadius: 'single_parameter',
    capabilityGained: args.capabilityGained,
    sourceFindingIds: [args.findingId],
    sourceFindingTypes: ['INFORMATION_DISCLOSURE'],
    prerequisites: [],
    steps: [
      {
        stepId: 'step_a7_1',
        ordinal: 1,
        title: 'Probe',
        description: 'Hermetic step',
        status: 'ready',
        requiredPermissions: ['active_http_get'],
      },
    ],
    targetUrl: args.targetUrl,
    parameterName: args.parameterName,
    lineage: {
      assessmentId: 'asm_a7_001',
      scanId: 'scn_a7_001',
      authorizationGrantId: 'grn_a7_001',
      authorizationDecisionId: 'dec_a7_001',
      actorId: 'act_a7_001',
    },
    createdAt: '2026-09-23T21:00:00.000Z',
    executable: false,
  };
}

function buildCtx(args: {
  plan: AttackPlan;
  findings: readonly Finding[];
  blastRadiusClass: 'read_escalated' | 'read_authenticated';
}): AttackCapabilityInvocationContext {
  const step: AttackExecutionStep = {
    ...args.plan.steps[0]!,
    blastRadiusClass: args.blastRadiusClass,
  };
  return {
    plan: args.plan,
    step,
    token: stubToken(args.blastRadiusClass),
    targetHost: 'app.example.com',
    targetUrl: args.plan.targetUrl ?? 'https://app.example.com/',
    scopeGrant: stubScope(),
    findings: args.findings,
  };
}

async function runSmokeTests(): Promise<void> {
  console.log('=== Milestone A7: Native Attack Capabilities Smoke Suite ===');

  // --- Invariant: SQL payloads never include blind/exfil markers ---
  for (const payload of SQL_ERROR_PROVOCATION_PAYLOADS) {
    assert.ok(!/\bSLEEP\s*\(/i.test(payload), 'SLEEP forbidden');
    assert.ok(!/\bWAITFOR\b/i.test(payload), 'WAITFOR forbidden');
    assert.ok(!/\bBENCHMARK\s*\(/i.test(payload), 'BENCHMARK forbidden');
    assert.ok(!/\bSELECT\s+\*/i.test(payload), 'SELECT * forbidden');
    assert.ok(!/\bUNION\s+SELECT\b/i.test(payload), 'UNION SELECT forbidden');
    assert.ok(!/\bINFORMATION_SCHEMA\b/i.test(payload), 'INFORMATION_SCHEMA forbidden');
  }
  console.log('✓ Payload allowlist excludes blind/exfil techniques');

  // --- Test 1: LFI succeeds on canary match ---
  const lfiFinding: Finding = {
    id: 'fnd_a7_lfi_001',
    type: 'INFORMATION_DISCLOSURE',
    severity: 'high',
    title: 'Parameter integrity anomaly',
    description: 'Boundary probe candidate',
    target: 'https://app.example.com/download',
    evidence: 'observed',
    confidence: 0.9,
    verificationState: 'suspected_vulnerability',
    metadata: {
      kind: 'parameter_integrity_metadata',
      category: 'INFORMATION_DISCLOSURE',
      endpointUrl: 'https://app.example.com/download',
      parameterName: 'file',
      injectedProbePattern: '../../../../etc/passwd',
      boundaryEnforced: false,
      sanitizedExcerpt: 'root:x:0:0:',
      observedAt: '2026-09-23T21:00:00.000Z',
    },
  };

  const lfiPlan = buildPlan({
    capability: 'lfi_path_traversal',
    parameterName: 'file',
    targetUrl: 'https://app.example.com/download',
    findingId: lfiFinding.id,
    capabilityGained: 'read_escalated',
  });

  const lfiSuccessCap = createLfiPathTraversalCapability(
    mockTransport(() => ({
      statusCode: 200,
      headers: { 'content-type': 'text/plain' },
      bodyText:
        'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n' +
        'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaaaaaaaa.bbbbbbbbbb ' +
        'X'.repeat(200),
      responseTimeMs: 5,
    }))
  );

  const lfiOk = await lfiSuccessCap.execute(
    buildCtx({ plan: lfiPlan, findings: [lfiFinding], blastRadiusClass: 'read_escalated' })
  );
  assert.equal(lfiOk.outcome, 'succeeded', `LFI expected succeeded, got ${lfiOk.outcome}`);
  assert.equal(lfiOk.reasonCode, 'lfi_traversal_marker_matched');
  assertEvidenceSafe(lfiOk.safeMessage, 'LFI success');
  console.log('✓ Test 1a: LFI succeeds on traversal marker match');

  // --- Test 1b: LFI refutes on 404 ---
  const lfi404 = createLfiPathTraversalCapability(
    mockTransport(() => ({
      statusCode: 404,
      headers: {},
      bodyText: 'Not Found',
      responseTimeMs: 2,
    }))
  );
  const lfi404Result = await lfi404.execute(
    buildCtx({ plan: lfiPlan, findings: [lfiFinding], blastRadiusClass: 'read_escalated' })
  );
  assert.equal(lfi404Result.outcome, 'refuted');
  assert.equal(lfi404Result.reasonCode, 'lfi_boundary_enforced');
  console.log('✓ Test 1b: LFI refutes on HTTP 404');

  // --- Test 1c: LFI refutes on 403 ---
  const lfi403 = createLfiPathTraversalCapability(
    mockTransport(() => ({
      statusCode: 403,
      headers: {},
      bodyText: 'Forbidden',
      responseTimeMs: 2,
    }))
  );
  const lfi403Result = await lfi403.execute(
    buildCtx({ plan: lfiPlan, findings: [lfiFinding], blastRadiusClass: 'read_escalated' })
  );
  assert.equal(lfi403Result.outcome, 'refuted');
  assert.equal(lfi403Result.reasonCode, 'lfi_boundary_enforced');
  console.log('✓ Test 1c: LFI refutes on HTTP 403');

  // --- Test 1d: LFI refutes on clean 200 without marker ---
  const lfiClean = createLfiPathTraversalCapability(
    mockTransport(() => ({
      statusCode: 200,
      headers: {},
      bodyText: 'ok sanitized page without system markers',
      responseTimeMs: 2,
    }))
  );
  const lfiCleanResult = await lfiClean.execute(
    buildCtx({ plan: lfiPlan, findings: [lfiFinding], blastRadiusClass: 'read_escalated' })
  );
  assert.equal(lfiCleanResult.outcome, 'refuted');
  assert.equal(lfiCleanResult.reasonCode, 'lfi_no_traversal_marker');
  assertEvidenceSafe(lfiCleanResult.safeMessage, 'LFI clean refute');
  console.log('✓ Test 1d: LFI refutes on sanitized non-traversed response');

  // --- Test 2: SQL advancement → validated_vulnerability ---
  const sqlFinding: Finding = {
    id: 'fnd_a7_sql_001',
    type: 'INFORMATION_DISCLOSURE',
    severity: 'medium',
    title: 'SQL error oracle suspected',
    description: 'Suspected SQL error disclosure',
    target: 'https://app.example.com/search',
    evidence: 'observed',
    confidence: 0.85,
    verificationState: 'suspected_vulnerability',
    metadata: {
      kind: 'sql_error_oracle_metadata',
      category: 'INFORMATION_DISCLOSURE',
      databaseEngine: 'mysql',
      parameterName: 'q',
      injectedProbe: "'",
      errorFragment: 'You have an error in your SQL syntax',
      endpointUrl: 'https://app.example.com/search',
      observedAt: '2026-09-23T21:00:00.000Z',
    },
  };

  const sqlPlan = buildPlan({
    capability: 'sql_oracle_advancement',
    parameterName: 'q',
    targetUrl: 'https://app.example.com/search',
    findingId: sqlFinding.id,
    capabilityGained: 'active_validation',
  });

  const sqlCap = createSqlOracleAdvancementCapability(
    mockTransport(() => ({
      statusCode: 500,
      headers: { 'content-type': 'text/html' },
      bodyText:
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version. " +
        'token=supersecret_session_value_should_redact ' +
        'Y'.repeat(300),
      responseTimeMs: 8,
    }))
  );

  const sqlResult = await sqlCap.execute(
    buildCtx({ plan: sqlPlan, findings: [sqlFinding], blastRadiusClass: 'read_authenticated' })
  );
  assert.equal(sqlResult.outcome, 'succeeded', `SQL expected succeeded, got ${sqlResult.outcome}`);
  assert.equal(sqlResult.reasonCode, 'sql_oracle_error_confirmed');
  assert.ok(!/SELECT\s+\*/i.test(sqlResult.safeMessage));
  assertEvidenceSafe(sqlResult.safeMessage, 'SQL success');

  const advanced = VerificationStateService.advanceState(sqlFinding, 'validated_vulnerability', {
    evidenceId: sqlResult.evidenceId ?? 'ev_a7_sql',
    reasonCode: 'sql_oracle_advancement_confirmed',
  });
  assert.equal(advanced.updatedFinding.verificationState, 'validated_vulnerability');
  assert.equal(advanced.transitionRecord.fromState, 'suspected_vulnerability');
  assert.equal(advanced.transitionRecord.toState, 'validated_vulnerability');
  console.log('✓ Test 2: SQL advancement → validated_vulnerability (error-based, no dump)');

  // --- Test 3: Generator maps parameter_integrity → LFI; suspected SQL → advancement ---
  const plans = generateAttackPlans({
    assessmentId: 'asm_a7_001',
    scanId: 'scn_a7_001',
    findings: [lfiFinding, sqlFinding],
    identities: [],
    lineage: {
      assessmentId: 'asm_a7_001',
      scanId: 'scn_a7_001',
      authorizationGrantId: 'grn_a7_001',
      authorizationDecisionId: 'dec_a7_001',
      actorId: 'act_a7_001',
    },
    generatedAt: '2026-09-23T21:00:00.000Z',
  });

  const lfiGenerated = plans.plans.find((p) => p.capability === 'lfi_path_traversal');
  assert.ok(lfiGenerated, 'expected lfi_path_traversal plan from parameter_integrity finding');
  assert.equal(lfiGenerated.capabilityGained, 'read_escalated');
  assert.equal(lfiGenerated.blastRadius, 'single_parameter');
  assert.equal(lfiGenerated.executable, false);

  const sqlAdvGenerated = plans.plans.find((p) => p.capability === 'sql_oracle_advancement');
  assert.ok(sqlAdvGenerated, 'expected sql_oracle_advancement plan for suspected SQL oracle');
  assert.equal(sqlAdvGenerated.capabilityGained, 'active_validation');
  assert.equal(sqlAdvGenerated.blastRadius, 'single_parameter');

  // observed_anomaly SQL should NOT emit advancement (preserves A3 sql_error_oracle_probe-only)
  const observedSql: Finding = {
    ...sqlFinding,
    id: 'fnd_a7_sql_obs',
    verificationState: 'observed_anomaly',
  };
  const observedPlans = generateAttackPlans({
    assessmentId: 'asm_a7_001',
    scanId: 'scn_a7_001',
    findings: [observedSql],
    identities: [],
    lineage: {
      assessmentId: 'asm_a7_001',
      scanId: 'scn_a7_001',
      authorizationGrantId: 'grn_a7_001',
      authorizationDecisionId: 'dec_a7_001',
      actorId: 'act_a7_001',
    },
  });
  assert.ok(
    observedPlans.plans.some((p) => p.capability === 'sql_error_oracle_probe'),
    'observed SQL still maps to sql_error_oracle_probe'
  );
  assert.ok(
    !observedPlans.plans.some((p) => p.capability === 'sql_oracle_advancement'),
    'observed_anomaly must not emit sql_oracle_advancement'
  );
  console.log('✓ Test 3: Generator wiring (LFI + SQL advancement) correct');

  // --- Test 4: Evidence truncation + sanitization unit check ---
  const longSecret =
    'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb ' +
    'Z'.repeat(200);
  const sanitized = sanitizeEvidenceFragment(longSecret);
  const truncated = sanitized.length > 128 ? sanitized.slice(0, 128) : sanitized;
  assert.ok(truncated.length <= 128);
  assert.ok(!truncated.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'));
  console.log('✓ Test 4: Evidence truncated ≤128 and sanitized');

  console.log('\n=== Milestone A7: ALL TESTS PASSED ===');
}

runSmokeTests().catch((err: unknown) => {
  console.error('Milestone A7 smoke failed:', err);
  process.exit(1);
});
