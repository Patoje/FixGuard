/**
 * Milestone A9 Smoke Suite — Sqlmap Adapter & SQL Injection Verification
 *
 * Verifies:
 * 1. Whitelisted args → exact CLI (--batch --technique=E --level=1 --risk=1 --no-cast)
 * 2. Prohibited flags (--os-shell, --dump, …) fail-closed with zero process spawns
 * 3. Structured output → SqlmapResult (confirmed / refuted)
 * 4. Capability advances VerificationState to exploitability_confirmed on confirmed
 *
 * Hermetic (MockProcessRunner). process.exit(1) on failure.
 */

import assert from 'node:assert/strict';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { VerificationStateService } from '../core/VerificationStateService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import { ATTACK_PLANNING_CONTRACT_VERSION } from '../attack-planning/AttackPlanContracts.js';
import { generateAttackPlans } from '../attack-planning/AttackPlanGeneratorService.js';
import {
  AttackCapabilityRegistry,
  createSqlInjectionVerificationCapability,
} from '../attack-execution/AttackCapabilityRegistry.js';
import type {
  AttackCapabilityInvocationContext,
  AttackExecutionStep,
} from '../attack-execution/AttackExecutionContracts.js';
import type { AttackAuthorizationToken } from '../attack-authorization/AttackAuthorizationContracts.js';
import { SqlmapAdapter, parseSqlmapStructuredOutput } from '../attack-execution/tools/SqlmapAdapter.js';
import {
  SQLMAP_HARDCODED_SAFE_FLAGS,
  SQLMAP_PROHIBITED_FLAGS,
  SQLMAP_VERIFICATION_NON_CLAIMS,
  buildSafeSqlmapCliArgs,
  validateSqlmapCliArgs,
} from '../attack-execution/tools/SqlmapContracts.js';

class MockProcessRunner implements ProcessRunner {
  public calls: ExecutionRequest[] = [];
  public output: RawExecutionOutput = {
    stdout: '',
    stderr: '',
    exitCode: 0,
    durationMs: 40,
    timedOut: false,
  };

  async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    this.calls.push(request);
    return this.output;
  }
}

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grn_a9_001',
    scanId: 'scn_a9_001',
    issuedAt: '2026-09-23T20:00:00.000Z',
    expiresAt: '2026-09-24T20:00:00.000Z',
    subject: { targetKind: 'origin', normalizedOrigin: 'https://app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'A9 smoke',
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

function setupAuthorizedContext() {
  const scopeGrant = createScopeGrant();
  const establishResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asm_a9_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'dec_a9_001',
      authorizedActor: { actorId: 'operator_a9', actorType: 'human' },
      decision: 'authorized',
      decidedAt: '2026-09-23T21:00:00.000Z',
      scopeGrant,
    },
    '2026-09-23T21:00:00.000Z'
  );
  if (establishResult.status !== 'established') {
    throw new Error(`Failed to establish verified decision: ${establishResult.safeMessage}`);
  }
  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'asm_a9_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_a9_001',
    actorId: 'operator_a9',
  };
  return {
    verifiedAuthorizationDecision: establishResult.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
  };
}

function stubToken(): AttackAuthorizationToken {
  return {
    contractVersion: 'fixguard-attack-authorization/v0',
    kind: 'attack_authorization_token',
    planId: 'apl_a9_stub',
    assessmentId: 'asm_a9_001',
    blastRadiusClass: 'read_authenticated',
    authorizationLevel: 'assessment_authorization',
    authorizedBy: 'operator_a9',
    authorizedAt: '2026-09-23T21:00:00.000Z',
    [Symbol.toStringTag]: 'AttackAuthorizationToken',
  };
}

function buildPlan(findingId: string): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: 'apl_a9_sql_inj',
    assessmentId: 'asm_a9_001',
    scanId: 'scn_a9_001',
    capability: 'sql_injection_verification',
    title: 'A9 sqlmap verification smoke plan',
    reasoning: 'Hermetic A9 advisory plan',
    status: 'ready_for_authorization',
    blastRadius: 'single_parameter',
    capabilityGained: 'active_validation',
    sourceFindingIds: [findingId],
    sourceFindingTypes: ['INFORMATION_DISCLOSURE'],
    prerequisites: [],
    steps: [
      {
        stepId: 'step_a9_1',
        ordinal: 1,
        title: 'Sqlmap error-based verification',
        description: 'Hermetic step',
        status: 'ready',
        requiredPermissions: ['active_http_get', 'active_validation'],
      },
    ],
    targetUrl: 'https://app.example.com/search?q=test',
    parameterName: 'q',
    lineage: {
      assessmentId: 'asm_a9_001',
      scanId: 'scn_a9_001',
      authorizationGrantId: 'grn_a9_001',
      authorizationDecisionId: 'dec_a9_001',
      actorId: 'operator_a9',
    },
    createdAt: '2026-09-23T21:00:00.000Z',
    executable: false,
  };
}

function sqlFinding(state: Finding['verificationState']): Finding {
  return {
    id: 'fnd_a9_sql_001',
    type: 'INFORMATION_DISCLOSURE',
    severity: 'medium',
    title: 'SQL error oracle',
    description: 'Validated SQL error disclosure',
    target: 'https://app.example.com/search',
    evidence: 'observed',
    confidence: 0.9,
    verificationState: state,
    metadata: {
      kind: 'sql_error_oracle_metadata',
      category: 'INFORMATION_DISCLOSURE',
      databaseEngine: 'mysql',
      parameterName: 'q',
      injectedProbe: "'",
      errorFragment: 'You have an error in your SQL syntax',
      endpointUrl: 'https://app.example.com/search?q=test',
      observedAt: '2026-09-23T21:00:00.000Z',
    },
  };
}

async function runSmokeTests(): Promise<void> {
  console.log('=== Milestone A9: Sqlmap Adapter & SQL Injection Verification Smoke Suite ===');

  const auth = setupAuthorizedContext();
  const dnsResolver = async (): Promise<readonly string[]> => ['93.184.216.34'];

  // --- Test 1: Whitelisted args → exact safe CLI ---
  {
    const runner = new MockProcessRunner();
    runner.output = {
      stdout: 'all tested parameters do not appear to be injectable\n',
      stderr: '',
      exitCode: 0,
      durationMs: 30,
      timedOut: false,
    };
    const adapter = new SqlmapAdapter(runner, dnsResolver);
    const result = await adapter.verify({
      targetUrl: 'https://app.example.com/search?q=1',
      parameterName: 'q',
      dbmsHint: 'mysql',
      ...auth,
      timeoutMs: 30_000,
    });

    assert.equal(result.status, 'refuted', `expected refuted, got ${result.status}`);
    assert.equal(runner.calls.length, 1, 'exactly one sqlmap process spawn expected');
    const call = runner.calls[0]!;
    assert.equal(call.binary, 'sqlmap');
    assert.ok(call.args.includes('-u'));
    assert.ok(call.args.includes('https://app.example.com/search?q=1'));
    assert.ok(call.args.includes('-p'));
    assert.ok(call.args.includes('q'));
    assert.ok(call.args.includes('--dbms'));
    assert.ok(call.args.includes('mysql'));
    for (const flag of SQLMAP_HARDCODED_SAFE_FLAGS) {
      assert.ok(call.args.includes(flag), `missing hardcoded safe flag ${flag}`);
    }
    assert.ok(call.args.includes('--batch'));
    assert.ok(call.args.includes('--technique=E'));
    assert.ok(call.args.includes('--level=1'));
    assert.ok(call.args.includes('--risk=1'));
    assert.ok(call.args.includes('--no-cast'));
    // No non-E techniques
    assert.ok(!call.args.some((a) => /^--technique=/.test(a) && a !== '--technique=E'));
    for (const prohibited of SQLMAP_PROHIBITED_FLAGS) {
      assert.ok(!call.args.includes(prohibited), `safe CLI must not include ${prohibited}`);
    }
    assert.equal(result.technique, 'E');
    console.log('✓ Test 1: Whitelisted args produce exact safe CLI (--technique=E)');
  }

  // --- Test 2: Prohibited flags fail-closed, zero spawns ---
  {
    const prohibitedCases = ['--os-shell', '--dump', '--os-cmd', '--sql-query', '--dump-all'] as const;
    for (const flag of prohibitedCases) {
      const check = validateSqlmapCliArgs(['-u', 'https://app.example.com/', flag]);
      assert.equal(check.ok, false, `expected reject for ${flag}`);
      if (!check.ok) {
        assert.equal(check.reasonCode, 'prohibited_flag');
      }
    }

    // DTO field injection attempts (parameterName looking like a flag)
    const injection = buildSafeSqlmapCliArgs({
      targetUrl: 'https://app.example.com/search',
      parameterName: '--os-shell',
      dbmsHint: 'mysql',
    });
    assert.equal(injection.ok, false);
    assert.ok(
      injection.ok === false &&
        (injection.reasonCode === 'invalid_parameter_name' ||
          injection.reasonCode === 'parameter_flag_injection')
    );

    const dumpParam = buildSafeSqlmapCliArgs({
      targetUrl: 'https://app.example.com/search',
      parameterName: '--dump',
      dbmsHint: 'mysql',
    });
    assert.equal(dumpParam.ok, false);

    // Adapter path: polluted parameter → tool_error, zero spawns
    for (const badParam of ['--os-shell', '--dump'] as const) {
      const runner = new MockProcessRunner();
      const adapter = new SqlmapAdapter(runner, dnsResolver);
      const result = await adapter.verify({
        targetUrl: 'https://app.example.com/search?q=1',
        parameterName: badParam,
        dbmsHint: 'mysql',
        ...auth,
      });
      assert.equal(result.status, 'tool_error', `expected tool_error for ${badParam}`);
      assert.equal(runner.calls.length, 0, `zero spawns required for ${badParam}`);
    }

    console.log('✓ Test 2: Prohibited flags reject with zero process spawns');
  }

  // --- Test 3: Structured parse → SqlmapResult ---
  {
    const lineage = auth.lineage;
    const confirmed = parseSqlmapStructuredOutput({
      stdout: [
        "Parameter: q (GET)",
        "    Type: error-based",
        "    Title: MySQL >= 5.0 AND error-based",
        "[INFO] GET parameter 'q' is vulnerable",
        JSON.stringify({
          status: 'confirmed',
          injectable: true,
          parameter: 'q',
          technique: 'E',
        }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      timedOut: false,
      durationMs: 55,
      targetUrl: 'https://app.example.com/search?q=1',
      parameterName: 'q',
      dbmsHint: 'mysql',
      lineage,
    });
    assert.equal(confirmed.status, 'confirmed');
    assert.equal(confirmed.technique, 'E');
    assert.equal(confirmed.reasonCode, 'sql_injection_error_based_confirmed');
    assert.equal(confirmed.explicitNonClaims, SQLMAP_VERIFICATION_NON_CLAIMS);
    assert.ok(!confirmed.evidenceExcerpt.includes('--os-shell'));

    const refuted = parseSqlmapStructuredOutput({
      stdout: '[CRITICAL] all tested parameters do not appear to be injectable\n',
      stderr: '',
      exitCode: 0,
      timedOut: false,
      durationMs: 40,
      targetUrl: 'https://app.example.com/search?q=1',
      parameterName: 'q',
      dbmsHint: 'mysql',
      lineage,
    });
    assert.equal(refuted.status, 'refuted');

    const timedOut = parseSqlmapStructuredOutput({
      stdout: '',
      stderr: '',
      exitCode: 124,
      timedOut: true,
      durationMs: 60_000,
      targetUrl: 'https://app.example.com/search?q=1',
      parameterName: 'q',
      dbmsHint: 'mysql',
      lineage,
    });
    assert.equal(timedOut.status, 'timed_out');

    // Time-based signal must never confirm
    const forbidden = parseSqlmapStructuredOutput({
      stdout: "Type: time-based blind\nparameter 'q' is vulnerable\n",
      stderr: '',
      exitCode: 0,
      timedOut: false,
      durationMs: 20,
      targetUrl: 'https://app.example.com/search?q=1',
      parameterName: 'q',
      dbmsHint: 'mysql',
      lineage,
    });
    assert.equal(forbidden.status, 'tool_error');
    assert.equal(forbidden.reasonCode, 'forbidden_technique_signal');

    console.log('✓ Test 3: Structured parse → SqlmapResult (confirmed/refuted/timed_out)');
  }

  // --- Test 4: Capability advances to exploitability_confirmed ---
  {
    const finding = sqlFinding('validated_vulnerability');
    const cap = createSqlInjectionVerificationCapability({
      resultProvider: async () => ({
        status: 'confirmed',
        contractVersion: 'fixguard-sqlmap-verification/v0',
        targetUrl: 'https://app.example.com/search?q=test',
        parameterName: 'q',
        dbmsHint: 'mysql',
        technique: 'E',
        evidenceExcerpt: 'OBSERVED error-based injectable parameter q',
        reasonCode: 'sql_injection_error_based_confirmed',
        explicitNonClaims: SQLMAP_VERIFICATION_NON_CLAIMS,
        lineage: auth.lineage,
        durationMs: 12,
      }),
    });

    const registry = new AttackCapabilityRegistry([cap]);
    const port = registry.get('sql_injection_verification');
    assert.ok(port, 'sql_injection_verification must be registered');

    const plan = buildPlan(finding.id);
    const step: AttackExecutionStep = {
      ...plan.steps[0]!,
      blastRadiusClass: 'read_authenticated',
    };
    const ctx: AttackCapabilityInvocationContext = {
      plan,
      step,
      token: stubToken(),
      targetHost: 'app.example.com',
      targetUrl: plan.targetUrl ?? 'https://app.example.com/search',
      scopeGrant: auth.authorizedScopeGrant,
      findings: [finding],
    };

    const capResult = await port.execute(ctx);
    assert.equal(capResult.outcome, 'succeeded');
    assert.equal(capResult.reasonCode, 'sql_injection_error_based_confirmed');

    // Honest one-step advancement: validated_vulnerability → exploitability_confirmed
    const advanced = VerificationStateService.advanceState(finding, 'exploitability_confirmed', {
      evidenceId: capResult.evidenceId ?? 'ev_a9_sql',
      reasonCode: 'sql_injection_error_based_confirmed',
    });
    assert.equal(advanced.updatedFinding.verificationState, 'exploitability_confirmed');
    assert.equal(advanced.transitionRecord.fromState, 'validated_vulnerability');
    assert.equal(advanced.transitionRecord.toState, 'exploitability_confirmed');

    // Refuted → REFUTED marker
    const refuteCap = createSqlInjectionVerificationCapability({
      resultProvider: async () => ({
        status: 'refuted',
        contractVersion: 'fixguard-sqlmap-verification/v0',
        targetUrl: 'https://app.example.com/search?q=test',
        parameterName: 'q',
        dbmsHint: 'mysql',
        technique: 'E',
        evidenceExcerpt: 'not injectable',
        reasonCode: 'sql_injection_not_confirmed',
        explicitNonClaims: SQLMAP_VERIFICATION_NON_CLAIMS,
        lineage: auth.lineage,
      }),
    });
    const refuteResult = await refuteCap.execute(ctx);
    assert.equal(refuteResult.outcome, 'refuted');
    const refutedState = VerificationStateService.refuteState(finding, finding.verificationState, {
      evidenceId: 'ev_a9_refute',
      reasonCode: 'REFUTED',
    });
    assert.equal(refutedState.transitionRecord.reasonCode, 'REFUTED');

    // Generator wiring: validated SQL oracle → sql_injection_verification
    const plans = generateAttackPlans({
      assessmentId: 'asm_a9_001',
      scanId: 'scn_a9_001',
      findings: [finding],
      identities: [],
      lineage: auth.lineage,
      generatedAt: '2026-09-23T21:00:00.000Z',
    });
    const sqlInjPlan = plans.plans.find((p) => p.capability === 'sql_injection_verification');
    assert.ok(sqlInjPlan, 'expected sql_injection_verification plan from validated SQL oracle');
    assert.equal(sqlInjPlan.capabilityGained, 'active_validation');
    assert.equal(sqlInjPlan.blastRadius, 'single_parameter');
    assert.equal(sqlInjPlan.executable, false);

    // A7 layering: suspected must NOT emit A9 plan
    const suspectedPlans = generateAttackPlans({
      assessmentId: 'asm_a9_001',
      scanId: 'scn_a9_001',
      findings: [sqlFinding('suspected_vulnerability')],
      identities: [],
      lineage: auth.lineage,
      generatedAt: '2026-09-23T21:00:00.000Z',
    });
    assert.ok(
      !suspectedPlans.plans.some((p) => p.capability === 'sql_injection_verification'),
      'suspected_vulnerability must not emit sql_injection_verification'
    );
    assert.ok(
      suspectedPlans.plans.some((p) => p.capability === 'sql_oracle_advancement'),
      'suspected_vulnerability must still emit sql_oracle_advancement (A7)'
    );

    // Default registry includes sql_injection_verification
    const defaultRegistry = AttackCapabilityRegistry.createDefault();
    assert.ok(
      defaultRegistry.get('sql_injection_verification'),
      'default registry registers sql_injection_verification'
    );

    console.log('✓ Test 4: Capability → exploitability_confirmed + REFUTED + A7/A9 layering');
  }

  // --- Hermetic binary-absent fallback ---
  {
    const absentRunner: ProcessRunner = {
      async execute(): Promise<RawExecutionOutput> {
        throw new Error('Command not found: sqlmap. Ensure it is installed and in PATH.');
      },
    };
    const adapter = new SqlmapAdapter(absentRunner, dnsResolver);
    const result = await adapter.verify({
      targetUrl: 'https://app.example.com/search?q=1',
      parameterName: 'q',
      dbmsHint: 'mysql',
      ...auth,
    });
    assert.equal(result.status, 'tool_error');
    assert.equal(result.hermeticFallback, true);
    assert.notEqual(result.status, 'confirmed');
    console.log('✓ Hermetic fallback: binary absent → tool_error (no fabricated confirmed)');
  }

  console.log('\n=== Milestone A9: ALL TESTS PASSED ===');
}

runSmokeTests().catch((err: unknown) => {
  console.error('Milestone A9 smoke failed:', err);
  process.exit(1);
});
