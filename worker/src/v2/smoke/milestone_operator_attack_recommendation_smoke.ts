/**
 * Operator Attack Recommendation smoke — deterministic A/B ranking + console lines.
 *
 * Verifies:
 * 1. IDOR + BYOT → A = idor_read_differential executable
 * 2. XSS on Next/Vercel → nuclei deprioritized; authz preferred when BYOT
 * 3. JWT finding → jwt_alg_none_probe
 * 4. CORS+creds → cors_chain_exploit
 * 5. SQLi validated → sql_injection_verification (technique=E flags)
 * 6. Unregistered capability shown disabled with capability_not_implemented
 * 7. AttackExecutionService persists commandSummary + consoleLines/verdict
 * 8. Gated API wordlist resolver returns a usable path
 */

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import type { Finding } from '../core/Evidence.js';
import { AttackRecommendationService } from '../attack-recommendation/AttackRecommendationService.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import { ATTACK_EXECUTION_CONTRACT_VERSION } from '../attack-execution/AttackExecutionContracts.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { ATTACK_PLANNING_CONTRACT_VERSION } from '../attack-planning/AttackPlanContracts.js';
import type { AttackCapabilityKind, AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { ATTACK_AUTHORIZATION_CONTRACT_VERSION } from '../attack-authorization/AttackAuthorizationContracts.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import {
  resolveApiDiscoveryWordlistPath,
  GATED_API_DISCOVERY_WORDLIST_RELATIVE,
} from '../recon/wordlists/resolveApiDiscoveryWordlist.js';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

const LINEAGE = {
  assessmentId: 'asmt_rec_smoke_001',
  scanId: 'scn_rec_smoke_001',
  authorizationGrantId: 'grn_rec_smoke_001',
  authorizationDecisionId: 'dec_rec_smoke_001',
  actorId: 'usr_rec_smoke',
} as const;

function baseFinding(
  overrides: Partial<Finding> & Pick<Finding, 'id' | 'type' | 'title' | 'target' | 'metadata'>
): Finding {
  return {
    severity: 'medium',
    description: 'smoke finding',
    evidence: 'observed',
    confidence: 0.9,
    verificationState: 'observed_anomaly',
    ...overrides,
  };
}

function registeredSet(): Set<AttackCapabilityKind> {
  const registry = AttackCapabilityRegistry.createDefault();
  const kinds: readonly AttackCapabilityKind[] = [
    'idor_read_differential',
    'cors_chain_exploit',
    'auth_bypass_probe',
    'jwt_alg_none_probe',
    'lfi_path_traversal',
    'sql_oracle_advancement',
    'nuclei_xss_scan',
    'parameter_reflection_probe',
    'sql_injection_verification',
    'credential_reuse',
  ];
  return new Set(kinds.filter((k) => registry.get(k) !== null));
}

async function testIdorByotPrefersA(): Promise<void> {
  const service = new AttackRecommendationService();
  const finding = baseFinding({
    id: 'fnd_idor_1',
    type: 'BROKEN_ACCESS_CONTROL',
    title: 'IDOR',
    target: 'https://app.example.com/api/users/1',
    metadata: {
      kind: 'broken_access_control_metadata',
      category: 'BROKEN_ACCESS_CONTROL',
      candidateId: 'cand_idor',
      evidenceRecordId: 'evr_idor',
      lineage: {},
      endpointUrl: 'https://app.example.com/api/users/1',
      resourceParamName: 'id',
    },
  });
  const result = service.recommend({
    assessmentId: LINEAGE.assessmentId,
    scanId: LINEAGE.scanId,
    finding,
    preconditions: {
      identityCount: 2,
      hasJwtIdentity: false,
      hasCredentialedCorsSignal: false,
      hasObservedParameter: true,
      hasCredentialReference: false,
    },
    registeredCapabilities: registeredSet(),
    lineage: LINEAGE,
    generatedAt: '2026-01-01T00:00:00.000Z',
  });
  assert.ok(result.recommendations.length >= 1);
  const a = result.recommendations.find((r) => r.rank === 'A');
  assert.ok(a);
  assert.equal(a.capabilityKind, 'idor_read_differential');
  assert.equal(a.executable, true);
  assert.equal(a.reasonKind, 'OBSERVED');
  assert.ok(result.rulesApplied.includes('rule_idor_byot'));
}

async function testSpaXssDeprioritize(): Promise<void> {
  const service = new AttackRecommendationService();
  const finding = baseFinding({
    id: 'fnd_xss_1',
    type: 'CROSS_SITE_SCRIPTING',
    title: 'XSS',
    target: 'https://app.example.com/search',
    metadata: {
      kind: 'input_validation_flaw_metadata',
      category: 'PARAMETER_REFLECTION',
      candidateId: 'cand_xss',
      evidenceRecordId: 'evr_xss',
      lineage: {},
      parameterName: 'q',
      endpointUrl: 'https://app.example.com/search',
    },
  });
  const result = service.recommend({
    assessmentId: LINEAGE.assessmentId,
    scanId: LINEAGE.scanId,
    finding,
    stackHints: {
      hasSpa: true,
      hasNextJs: true,
      hasVercel: true,
      spaFramework: 'nextjs',
      technologyNames: ['Next.js', 'Vercel'],
    },
    preconditions: {
      identityCount: 2,
      hasJwtIdentity: false,
      hasCredentialedCorsSignal: false,
      hasObservedParameter: true,
      hasCredentialReference: false,
    },
    registeredCapabilities: registeredSet(),
    lineage: LINEAGE,
    generatedAt: '2026-01-01T00:00:00.000Z',
  });
  const a = result.recommendations.find((r) => r.rank === 'A');
  assert.ok(a);
  assert.equal(a.capabilityKind, 'idor_read_differential');
  assert.ok(result.rulesApplied.includes('rule_spa_prefer_authz'));
}

async function testJwtAndCorsAndSqli(): Promise<void> {
  const service = new AttackRecommendationService();
  const jwt = baseFinding({
    id: 'fnd_jwt_1',
    type: 'BROKEN_AUTHENTICATION',
    title: 'JWT',
    target: 'https://app.example.com/api/me',
    metadata: {
      kind: 'jwt_algorithm_confusion_metadata',
      category: 'BROKEN_AUTHENTICATION',
      endpointUrl: 'https://app.example.com/api/me',
      httpMethod: 'GET',
      originalAlgorithm: 'RS256',
      manipulatedAlgorithm: 'none',
      probeMechanism: 'alg_none_header',
      observedAt: '2026-01-01T00:00:00.000Z',
    },
  });
  const jwtRes = service.recommend({
    assessmentId: LINEAGE.assessmentId,
    scanId: LINEAGE.scanId,
    finding: jwt,
    preconditions: {
      identityCount: 1,
      hasJwtIdentity: true,
      hasCredentialedCorsSignal: false,
      hasObservedParameter: false,
      hasCredentialReference: false,
    },
    registeredCapabilities: registeredSet(),
    lineage: LINEAGE,
    generatedAt: '2026-01-01T00:00:00.000Z',
  });
  assert.equal(jwtRes.recommendations[0]?.capabilityKind, 'jwt_alg_none_probe');

  const cors = baseFinding({
    id: 'fnd_cors_1',
    type: 'CORS_MISCONFIGURATION',
    title: 'CORS',
    target: 'https://app.example.com/api',
    metadata: {
      kind: 'credentialed_cors_metadata',
      category: 'SECURITY_MISCONFIGURATION',
      endpointUrl: 'https://app.example.com/api',
      httpMethod: 'GET',
      suppliedOrigin: 'https://evil.example',
      reflectedOrigin: 'https://evil.example',
      allowCredentialsHeader: true,
      acaoHeader: 'https://evil.example',
      observedAt: '2026-01-01T00:00:00.000Z',
    },
  });
  const corsRes = service.recommend({
    assessmentId: LINEAGE.assessmentId,
    scanId: LINEAGE.scanId,
    finding: cors,
    preconditions: {
      identityCount: 0,
      hasJwtIdentity: false,
      hasCredentialedCorsSignal: true,
      hasObservedParameter: false,
      hasCredentialReference: false,
    },
    registeredCapabilities: registeredSet(),
    lineage: LINEAGE,
    generatedAt: '2026-01-01T00:00:00.000Z',
  });
  assert.equal(corsRes.recommendations[0]?.capabilityKind, 'cors_chain_exploit');

  const sqli = baseFinding({
    id: 'fnd_sqli_1',
    type: 'INFORMATION_DISCLOSURE',
    title: 'SQLi',
    target: 'https://app.example.com/item',
    verificationState: 'validated_vulnerability',
    metadata: {
      kind: 'sql_error_oracle_metadata',
      category: 'INFORMATION_DISCLOSURE',
      databaseEngine: 'mysql',
      parameterName: 'id',
      injectedProbe: "'",
      errorFragment: 'syntax error',
      endpointUrl: 'https://app.example.com/item',
      observedAt: '2026-01-01T00:00:00.000Z',
    },
  });
  const sqliRes = service.recommend({
    assessmentId: LINEAGE.assessmentId,
    scanId: LINEAGE.scanId,
    finding: sqli,
    preconditions: {
      identityCount: 0,
      hasJwtIdentity: false,
      hasCredentialedCorsSignal: false,
      hasObservedParameter: true,
      hasCredentialReference: false,
    },
    registeredCapabilities: registeredSet(),
    lineage: LINEAGE,
    generatedAt: '2026-01-01T00:00:00.000Z',
  });
  const a = sqliRes.recommendations[0];
  assert.equal(a?.capabilityKind, 'sql_injection_verification');
  assert.equal(a?.suggestedFlags.technique, 'E');
}

async function testUnimplementedDisabled(): Promise<void> {
  const service = new AttackRecommendationService();
  const finding = baseFinding({
    id: 'fnd_sql_obs',
    type: 'INFORMATION_DISCLOSURE',
    title: 'SQL oracle',
    target: 'https://app.example.com/q',
    verificationState: 'observed_anomaly',
    metadata: {
      kind: 'sql_error_oracle_metadata',
      category: 'INFORMATION_DISCLOSURE',
      databaseEngine: 'unknown',
      parameterName: 'q',
      injectedProbe: "'",
      errorFragment: 'SQL',
      endpointUrl: 'https://app.example.com/q',
      observedAt: '2026-01-01T00:00:00.000Z',
    },
  });
  const result = service.recommend({
    assessmentId: LINEAGE.assessmentId,
    scanId: LINEAGE.scanId,
    finding,
    preconditions: {
      identityCount: 0,
      hasJwtIdentity: false,
      hasCredentialedCorsSignal: false,
      hasObservedParameter: true,
      hasCredentialReference: false,
    },
    registeredCapabilities: registeredSet(),
    lineage: LINEAGE,
    generatedAt: '2026-01-01T00:00:00.000Z',
  });
  const a = result.recommendations[0];
  assert.equal(a?.capabilityKind, 'sql_error_oracle_probe');
  assert.equal(a?.executable, false);
  assert.ok(a?.disabilityReason?.includes('capability_not_implemented'));
}

function createScopeGrant(host: string): AuthorizedScopeGrant {
  const now = Date.now();
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grn_rec_smoke_001',
    scanId: 'scn_rec_smoke_001',
    issuedAt: new Date(now - 3600_000).toISOString(),
    expiresAt: new Date(now + 86400_000).toISOString(),
    subject: {
      targetKind: 'origin',
      normalizedOrigin: `https://${host}`,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for recommendation smoke',
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
      allowedDomains: [host],
      allowedHosts: [host],
      allowedOrigins: [`https://${host}`],
      allowedMethods: ['GET', 'HEAD', 'POST'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: false,
      allowCredentialUse: true,
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

async function testExecutionConsoleLines(): Promise<void> {
  const host = 'app.example.com';
  const planRepo = new InMemoryAttackPlanRepository();
  const plan: AttackPlan = {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: 'apl_rec_console_001',
    assessmentId: LINEAGE.assessmentId,
    scanId: LINEAGE.scanId,
    capability: 'jwt_alg_none_probe',
    title: 'JWT alg none',
    reasoning: 'smoke',
    status: 'ready_for_authorization',
    blastRadius: 'single_endpoint',
    capabilityGained: 'active_validation',
    sourceFindingIds: [],
    sourceFindingTypes: ['BROKEN_AUTHENTICATION'],
    prerequisites: [],
    steps: [
      {
        stepId: 'stp_1',
        ordinal: 1,
        title: 'Probe',
        description: 'JWT alg=none',
        status: 'ready',
        requiredPermissions: ['activeValidation'],
      },
    ],
    targetUrl: `https://${host}/api/me`,
    lineage: LINEAGE,
    createdAt: '2026-01-01T00:00:00.000Z',
    executable: false,
  };
  await planRepo.savePlan(plan);

  const auth = new AttackAuthorizationService(planRepo);
  const authResult = await auth.establishAttackAuthorization({
    contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
    kind: 'establish_attack_authorization_request',
    planId: plan.planId,
    assessmentId: plan.assessmentId,
    blastRadiusClass: 'read_authenticated',
    operatorId: 'usr_rec_smoke',
  });
  assert.equal(authResult.status, 'established');
  if (authResult.status !== 'established') fail('auth failed');

  const registry = new AttackCapabilityRegistry([
    {
      capability: 'jwt_alg_none_probe',
      async execute() {
        return {
          outcome: 'refuted',
          reasonCode: 'jwt_alg_none_rejected',
          safeMessage: 'Server rejected alg=none token (OBSERVED)',
          commandSummary: 'jwt_alg_none_probe https://app.example.com/api/me alg=none',
          consoleLines: [
            {
              stream: 'stdout',
              text: 'probe_response status=401',
              at: '2026-01-01T00:00:01.000Z',
            },
          ],
        };
      },
    },
  ]);

  const exec = new AttackExecutionService({
    planRepository: planRepo,
    capabilityRegistry: registry,
  });

  const result = await exec.execute({
    contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
    kind: 'attack_execution_request',
    planId: plan.planId,
    assessmentId: plan.assessmentId,
    token: authResult.token,
    scopeGrant: createScopeGrant(host),
    coordinator: new TargetExecutionCoordinator(),
    dnsResolver: async () => ['93.184.216.34'],
    findings: [],
    operatorId: 'usr_rec_smoke',
  });

  assert.equal(result.status, 'completed');
  if (result.status !== 'completed') fail('execute failed');
  const step = result.record.stepRecords[0];
  assert.ok(step);
  assert.ok(step.commandSummary?.includes('jwt_alg_none_probe'));
  assert.ok(step.consoleLines && step.consoleLines.length >= 2);
  const verdict = step.consoleLines!.find((l) => l.stream === 'verdict');
  assert.ok(verdict?.text.startsWith('refuted:'));
}

async function testWordlistResolver(): Promise<void> {
  const path = resolveApiDiscoveryWordlistPath();
  assert.ok(typeof path === 'string' && path.length > 0);
  const gatedOk =
    existsSync(path) ||
    path.includes('api-discovery-gated') ||
    path.includes(GATED_API_DISCOVERY_WORDLIST_RELATIVE);
  assert.equal(gatedOk, true);
}

async function main(): Promise<void> {
  await testIdorByotPrefersA();
  await testSpaXssDeprioritize();
  await testJwtAndCorsAndSqli();
  await testUnimplementedDisabled();
  await testExecutionConsoleLines();
  await testWordlistResolver();
  console.log('PASS: operator attack recommendation smoke');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
