/**
 * Milestone A8 Smoke Suite — Nuclei Adapter & XSS Scan Capability
 *
 * Verifies:
 * 1. Allowlisted categories → correct CLI args (-json -silent -no-interactsh -rate-limit 10 -timeout 10)
 * 2. Prohibited categories / path injection → preflight reject, zero processes spawned
 * 3. Output → NucleiObservation[] with epistemicStatus OBSERVED
 * 4. Capability via registry advances VerificationState one ordered step via evidence
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
  createNucleiXssScanCapability,
} from '../attack-execution/AttackCapabilityRegistry.js';
import type {
  AttackCapabilityInvocationContext,
  AttackExecutionStep,
} from '../attack-execution/AttackExecutionContracts.js';
import type { AttackAuthorizationToken } from '../attack-authorization/AttackAuthorizationContracts.js';
import { NucleiAdapter } from '../recon/adapters/NucleiAdapter.js';
import {
  NUCLEI_SCAN_NON_CLAIMS,
  validateNucleiTemplates,
} from '../recon/adapters/NucleiContracts.js';

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

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grn_a8_001',
    scanId: 'scn_a8_001',
    issuedAt: '2026-09-23T20:00:00.000Z',
    expiresAt: '2026-09-24T20:00:00.000Z',
    subject: { targetKind: 'origin', normalizedOrigin: 'https://app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'A8 smoke',
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
      assessmentId: 'asm_a8_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'dec_a8_001',
      authorizedActor: { actorId: 'operator_a8', actorType: 'human' },
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
    assessmentId: 'asm_a8_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_a8_001',
    actorId: 'operator_a8',
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
    planId: 'apl_a8_stub',
    assessmentId: 'asm_a8_001',
    blastRadiusClass: 'read_authenticated',
    authorizationLevel: 'assessment_authorization',
    authorizedBy: 'operator_a8',
    authorizedAt: '2026-09-23T21:00:00.000Z',
    [Symbol.toStringTag]: 'AttackAuthorizationToken',
  };
}

function buildPlan(findingId: string): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: 'apl_a8_nuclei_xss',
    assessmentId: 'asm_a8_001',
    scanId: 'scn_a8_001',
    capability: 'nuclei_xss_scan',
    title: 'A8 nuclei XSS smoke plan',
    reasoning: 'Hermetic A8 advisory plan',
    status: 'ready_for_authorization',
    blastRadius: 'single_parameter',
    capabilityGained: 'active_validation',
    sourceFindingIds: [findingId],
    sourceFindingTypes: ['INPUT_VALIDATION_FLAW'],
    prerequisites: [],
    steps: [
      {
        stepId: 'step_a8_1',
        ordinal: 1,
        title: 'Nuclei XSS scan',
        description: 'Hermetic step',
        status: 'ready',
        requiredPermissions: ['active_http_get'],
      },
    ],
    targetUrl: 'https://app.example.com/echo?msg=test',
    parameterName: 'msg',
    lineage: {
      assessmentId: 'asm_a8_001',
      scanId: 'scn_a8_001',
      authorizationGrantId: 'grn_a8_001',
      authorizationDecisionId: 'dec_a8_001',
      actorId: 'operator_a8',
    },
    createdAt: '2026-09-23T21:00:00.000Z',
    executable: false,
  };
}

async function runSmokeTests(): Promise<void> {
  console.log('=== Milestone A8: Nuclei Adapter & XSS Scan Capability Smoke Suite ===');

  const auth = setupAuthorizedContext();
  const dnsResolver = async (): Promise<readonly string[]> => ['93.184.216.34'];

  // --- Test 1: Allowlisted categories → correct CLI args ---
  {
    const runner = new MockProcessRunner();
    runner.output = {
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 25,
      timedOut: false,
    };
    const adapter = new NucleiAdapter(runner, dnsResolver);
    const templates = [
      'http/fuzzing/xss-injection',
      'http/miscellaneous/http-missing-security-headers',
      'http/technologies/tech-detect',
      'http/exposures/configs/git-config',
    ] as const;

    const result = await adapter.scan({
      targetUrl: 'https://app.example.com/echo',
      templates,
      ...auth,
      timeoutMs: 30_000,
    });

    assert.equal(result.status, 'success', `expected success, got ${result.status}`);
    assert.equal(runner.calls.length, 1, 'exactly one nuclei process spawn expected');
    const call = runner.calls[0]!;
    assert.equal(call.binary, 'nuclei');
    assert.ok(call.args.includes('-json'));
    assert.ok(call.args.includes('-silent'));
    assert.ok(call.args.includes('-no-interactsh'));
    assert.ok(call.args.includes('-rate-limit'));
    assert.ok(call.args.includes('10'));
    assert.ok(call.args.includes('-timeout'));
    const timeoutIdx = call.args.indexOf('-timeout');
    assert.equal(call.args[timeoutIdx + 1], '10');
    assert.ok(call.args.includes('-u'));
    assert.ok(call.args.includes('https://app.example.com/echo'));
    for (const t of templates) {
      assert.ok(call.args.includes(t), `missing template arg ${t}`);
    }
    // No interactsh enablement
    assert.ok(!call.args.some((a) => a === '-interactsh' || a.startsWith('-interactsh-')));
    console.log('✓ Test 1: Allowlisted templates produce correct CLI args (no-interactsh)');
  }

  // --- Test 2: Prohibited categories / path injection → preflight, zero spawns ---
  {
    const prohibitedCases: Array<{ templates: string[]; reasonCode: string }> = [
      { templates: ['network/detection/something'], reasonCode: 'prohibited_template_category' },
      { templates: ['headless/chrome-xss'], reasonCode: 'prohibited_template_category' },
      { templates: ['javascript/custom'], reasonCode: 'prohibited_template_category' },
      { templates: ['workflows/full-scan'], reasonCode: 'prohibited_template_category' },
      { templates: ['dns/dns-rebinding'], reasonCode: 'prohibited_template_category' },
      { templates: ['file/permission'], reasonCode: 'prohibited_template_category' },
      { templates: ['code/rce-check'], reasonCode: 'prohibited_template_category' },
      { templates: ['http/fuzzing/xss-rce-chain'], reasonCode: 'prohibited_template_tag_rce' },
      { templates: ['http/exposures/../../etc/passwd'], reasonCode: 'unsafe_template_path' },
      { templates: ['/etc/nuclei/templates/xss'], reasonCode: 'unsafe_template_path' },
      { templates: ['http://evil.example/xss.yaml'], reasonCode: 'unsafe_template_path' },
    ];

    for (const tc of prohibitedCases) {
      const runner = new MockProcessRunner();
      const adapter = new NucleiAdapter(runner, dnsResolver);
      const result = await adapter.scan({
        targetUrl: 'https://app.example.com/echo',
        templates: tc.templates,
        ...auth,
      });
      assert.equal(
        result.status,
        'preflight_denied',
        `expected preflight_denied for ${tc.templates[0]}, got ${result.status}`
      );
      if (result.status === 'preflight_denied') {
        assert.equal(
          result.reasonCode,
          tc.reasonCode,
          `expected ${tc.reasonCode} for ${tc.templates[0]}, got ${result.reasonCode}`
        );
      }
      assert.equal(runner.calls.length, 0, `zero spawns required for ${tc.templates[0]}`);
    }

    // Direct validator unit check
    const rceCheck = validateNucleiTemplates(['http/technologies/rce-detect']);
    assert.equal(rceCheck.ok, false);
    console.log('✓ Test 2: Prohibited templates / path injection reject with zero spawns');
  }

  // --- Test 3: Output → NucleiObservation[] with OBSERVED ---
  {
    const runner = new MockProcessRunner();
    runner.output = {
      stdout: [
        JSON.stringify({
          'template-id': 'xss-reflected',
          'template-path': 'http/fuzzing/xss-reflected.yaml',
          'matched-at': 'https://app.example.com/echo?msg=1',
          host: 'app.example.com',
          'matcher-name': 'reflected-xss',
          info: {
            name: 'Reflected XSS',
            tags: ['xss', 'fuzz'],
          },
          'extracted-results': [
            'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb',
          ],
        }),
        JSON.stringify({
          'template-id': 'tech-nginx',
          'template-path': 'http/technologies/nginx-version.yaml',
          'matched-at': 'https://app.example.com/',
          host: 'app.example.com',
          info: { name: 'Nginx Detect', tags: ['tech'] },
        }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 55,
      timedOut: false,
    };

    const adapter = new NucleiAdapter(runner, dnsResolver);
    const result = await adapter.scan({
      targetUrl: 'https://app.example.com/echo',
      templates: ['http/fuzzing/xss-', 'http/technologies/'],
      ...auth,
    });

    assert.equal(result.status, 'success');
    if (result.status === 'success') {
      assert.ok(result.observations.length >= 2);
      for (const obs of result.observations) {
        assert.equal(obs.epistemicStatus, 'OBSERVED');
        assert.equal(obs.freshness, 'live');
        assert.equal(obs.sourceReliability, 'direct_observation');
        assert.ok(!obs.evidenceExcerpt.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'));
      }
      assert.equal(result.explicitNonClaims.confirmsVulnerabilities, false);
      assert.equal(result.explicitNonClaims, NUCLEI_SCAN_NON_CLAIMS);
    }
    console.log('✓ Test 3: Parsed NucleiObservation[] with epistemicStatus OBSERVED + sanitized');
  }

  // --- Test 4: Capability via registry advances VerificationState ---
  {
    const finding: Finding = {
      id: 'fnd_a8_xss_001',
      type: 'INPUT_VALIDATION_FLAW',
      severity: 'medium',
      title: 'Parameter reflection',
      description: 'Reflection anomaly',
      target: 'https://app.example.com/echo',
      evidence: 'observed',
      confidence: 0.8,
      verificationState: 'observed_anomaly',
      metadata: {
        kind: 'input_validation_flaw_metadata',
        category: 'PARAMETER_REFLECTION',
        candidateId: 'cand_a8',
        evidenceRecordId: 'evr_a8',
        lineage: {},
        endpointUrl: 'https://app.example.com/echo',
        parameterName: 'msg',
        reflectedCanary: 'fg_canary',
      },
    };

    const collectedAt = '2026-09-23T21:00:00.000Z';
    const cap = createNucleiXssScanCapability({
      observationProvider: async () => [
        {
          templateId: 'xss-reflected',
          templatePath: 'http/fuzzing/xss-reflected.yaml',
          matchedAt: 'https://app.example.com/echo?msg=1',
          host: 'app.example.com',
          evidenceExcerpt: 'OBSERVED matcher reflected-xss',
          tags: ['xss'],
          epistemicStatus: 'OBSERVED',
          discoveredAt: collectedAt,
          collectedAt,
          freshness: 'live',
          sourceReliability: 'direct_observation',
        },
      ],
    });

    const registry = new AttackCapabilityRegistry([cap]);
    const port = registry.get('nuclei_xss_scan');
    assert.ok(port, 'nuclei_xss_scan must be registered');

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
      targetUrl: plan.targetUrl ?? 'https://app.example.com/echo',
      scopeGrant: auth.authorizedScopeGrant,
      findings: [finding],
    };

    const capResult = await port.execute(ctx);
    assert.equal(capResult.outcome, 'succeeded');
    assert.equal(capResult.reasonCode, 'nuclei_xss_template_match_observed');
    assert.ok(capResult.safeMessage.includes('OBSERVED'));

    // Honest one-step advancement: observed_anomaly → suspected_vulnerability
    const advanced = VerificationStateService.advanceState(finding, 'suspected_vulnerability', {
      evidenceId: capResult.evidenceId ?? 'ev_a8_nuclei',
      reasonCode: 'nuclei_xss_template_match_observed',
    });
    assert.equal(advanced.updatedFinding.verificationState, 'suspected_vulnerability');
    assert.equal(advanced.transitionRecord.fromState, 'observed_anomaly');
    assert.equal(advanced.transitionRecord.toState, 'suspected_vulnerability');

    // Generator wiring
    const plans = generateAttackPlans({
      assessmentId: 'asm_a8_001',
      scanId: 'scn_a8_001',
      findings: [finding],
      identities: [],
      lineage: auth.lineage,
      generatedAt: collectedAt,
    });
    const nucleiPlan = plans.plans.find((p) => p.capability === 'nuclei_xss_scan');
    assert.ok(nucleiPlan, 'expected nuclei_xss_scan plan from reflection finding');
    assert.equal(nucleiPlan.capabilityGained, 'active_validation');
    assert.equal(nucleiPlan.blastRadius, 'single_parameter');
    assert.equal(nucleiPlan.executable, false);

    // Default registry includes nuclei_xss_scan
    const defaultRegistry = AttackCapabilityRegistry.createDefault();
    assert.ok(defaultRegistry.get('nuclei_xss_scan'), 'default registry registers nuclei_xss_scan');

    console.log('✓ Test 4: Capability registry + VerificationState one-step advancement');
  }

  // --- Hermetic binary-absent fallback ---
  {
    const absentRunner: ProcessRunner = {
      async execute(): Promise<RawExecutionOutput> {
        throw new Error('Command not found: nuclei. Ensure it is installed and in PATH.');
      },
    };
    const adapter = new NucleiAdapter(absentRunner, dnsResolver);
    const result = await adapter.scan({
      targetUrl: 'https://app.example.com/echo',
      templates: ['http/fuzzing/xss-'],
      ...auth,
    });
    assert.equal(result.status, 'success');
    if (result.status === 'success') {
      assert.equal(result.hermeticFallback, true);
      assert.equal(result.observations.length, 0);
    }
    console.log('✓ Hermetic fallback: binary absent → empty OBSERVED set (no fabricated hits)');
  }

  console.log('\n=== Milestone A8: ALL TESTS PASSED ===');
}

runSmokeTests().catch((err: unknown) => {
  console.error('Milestone A8 smoke failed:', err);
  process.exit(1);
});
