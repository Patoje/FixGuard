/**
 * Milestone F5 — Real Intelligence Layer Smoke Test Suite
 *
 * Validates TargetProfileBuilder and TargetRecommendationEngine:
 * 1. Consolidates canonical findings (F2 IDOR, F4 CORS, F4 Reflection) and observations into immutable TargetProfile.
 * 2. Correlates multi-vulnerability patterns into actionable advisory recommendations (Cross-Origin Exploit Chain & Access Control).
 * 3. Enforces abstention discipline: benign or quiet targets yield strictly 0 recommendations.
 * 4. End-to-end lineage tuple integrity is preserved across profiles and all emitted recommendations.
 */

import assert from 'node:assert';
import type { Finding } from '../core/Evidence.js';
import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';
import { TargetProfileBuilder, buildTargetProfile } from '../intelligence/TargetProfileBuilder.js';
import { TargetRecommendationEngine, correlateTargetProfile } from '../intelligence/TargetRecommendationEngine.js';
import { INTELLIGENCE_CONTRACT_VERSION } from '../intelligence/IntelligenceContracts.js';

const canonicalLineage: AuthorizedExecutionLineageTuple = {
  assessmentId: 'asmt_f5_test_001',
  scanId: 'scan_f5_test_001',
  authorizationGrantId: 'grant_f5_test_001',
  authorizationDecisionId: 'dec_f5_test_001',
  actorId: 'usr_secops_lead_01',
};

function createMockFinding(params: {
  id: string;
  type: string;
  target: string;
  confidence: number;
  severity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
  metadata?: Record<string, unknown>;
}): Finding {
  return {
    id: params.id,
    type: params.type,
    severity: params.severity ?? 'high',
    title: `Mock ${params.type}`,
    description: `Mock finding description for ${params.type}`,
    target: params.target,
    evidence: `evidence_for_${params.id}`,
    confidence: params.confidence,
    metadata: params.metadata ?? {},
  };
}

async function runMilestoneF5SmokeSuite(): Promise<void> {
  console.log('>>> RUNNING MILESTONE F5 SMOKE TEST SUITE (Real Intelligence Layer) <<<');

  const builder = new TargetProfileBuilder();
  const engine = new TargetRecommendationEngine();

  // -------------------------------------------------------------------------
  // Assertion 1: Profile Construction from Multi-Engine Findings & Observations
  // -------------------------------------------------------------------------
  {
    console.log('\n[+] Assertion 1: Consolidating canonical findings and observations into TargetProfile...');

    const findings: Finding[] = [
      createMockFinding({
        id: 'fnd_idor_001',
        type: 'BROKEN_ACCESS_CONTROL',
        target: 'https://api.example.com/api/v1/users/account?id=101',
        confidence: 0.95,
        metadata: {
          category: 'BROKEN_ACCESS_CONTROL',
          resourceParamName: 'id',
        },
      }),
      createMockFinding({
        id: 'fnd_cors_002',
        type: 'SECURITY_MISCONFIGURATION',
        target: 'https://api.example.com/api/v1/profile',
        confidence: 0.98,
        metadata: {
          category: 'CORS_MISCONFIGURATION',
          allowCredentials: true,
          reflectedOrigin: 'https://evil-untrusted-origin.org',
        },
      }),
      createMockFinding({
        id: 'fnd_refl_003',
        type: 'INPUT_VALIDATION_FLAW',
        target: 'https://api.example.com/api/v1/profile?view=summary',
        confidence: 0.92,
        metadata: {
          category: 'PARAMETER_REFLECTION',
          parameterName: 'view',
        },
      }),
    ];

    const observations = [
      {
        technologies: ['Node.js', 'Express', 'TypeScript'],
        webServer: 'nginx/1.24.0',
      },
      {
        url: 'https://api.example.com/api/v1/health',
        method: 'GET',
      },
    ];

    const profile = builder.build({
      targetHost: 'api.example.com',
      normalizedOrigin: 'https://api.example.com',
      findings,
      observations,
      lineage: canonicalLineage,
    });

    assert.strictEqual(profile.contractVersion, INTELLIGENCE_CONTRACT_VERSION);
    assert.strictEqual(profile.kind, 'target_profile');
    assert.strictEqual(profile.targetHost, 'api.example.com');
    assert.ok(profile.profileId.startsWith('prof_apiexamplecom_'));

    // Check technologies deduplication & sorting
    assert.deepStrictEqual(profile.technologies, ['Express', 'Node.js', 'TypeScript', 'nginx/1.24.0']);

    // Check endpoints consolidated
    assert.strictEqual(profile.endpoints.length, 3, 'Must consolidate into 3 distinct endpoints');

    const accountEp = profile.endpoints.find(e => e.path === '/api/v1/users/account');
    assert.ok(accountEp, 'Account endpoint must exist');
    assert.strictEqual(accountEp.authRequirement, 'authenticated');
    assert.ok(accountEp.parameters.includes('id'));
    assert.ok(accountEp.flawCategories.includes('BROKEN_ACCESS_CONTROL'));

    const profileEp = profile.endpoints.find(e => e.path === '/api/v1/profile');
    assert.ok(profileEp, 'Profile endpoint must exist');
    assert.strictEqual(profileEp.corsConfiguration?.allowCredentials, true);
    assert.ok(profileEp.parameters.includes('view'));
    assert.ok(profileEp.flawCategories.includes('CORS_MISCONFIGURATION'));
    assert.ok(profileEp.flawCategories.includes('PARAMETER_REFLECTION'));

    const healthEp = profile.endpoints.find(e => e.path === '/api/v1/health');
    assert.ok(healthEp, 'Health endpoint from observation must exist');

    // Check findings array and lineage
    assert.strictEqual(profile.knownFindings.length, 3);
    assert.deepStrictEqual(profile.lineage, canonicalLineage);

    console.log('    [PASS] TargetProfile correctly aggregates technologies, endpoints, flaw contexts, and lineage');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: Correlation Engine Multi-Vulnerability Advisory Recommendations
  // -------------------------------------------------------------------------
  {
    console.log('\n[+] Assertion 2: Correlating multi-vulnerability exploit chain and access control...');

    const findings: Finding[] = [
      createMockFinding({
        id: 'fnd_cors_001',
        type: 'SECURITY_MISCONFIGURATION',
        target: 'https://api.target.internal/data',
        confidence: 0.99,
        metadata: {
          category: 'CORS_MISCONFIGURATION',
          allowCredentials: true,
        },
      }),
      createMockFinding({
        id: 'fnd_refl_002',
        type: 'INPUT_VALIDATION_FLAW',
        target: 'https://api.target.internal/data?tag=test',
        confidence: 0.95,
        metadata: {
          category: 'PARAMETER_REFLECTION',
          parameterName: 'tag',
        },
      }),
      createMockFinding({
        id: 'fnd_idor_003',
        type: 'BROKEN_ACCESS_CONTROL',
        target: 'https://api.target.internal/orders?orderId=55',
        confidence: 0.90,
        metadata: {
          category: 'BROKEN_ACCESS_CONTROL',
          resourceParamName: 'orderId',
        },
      }),
    ];

    const profile = buildTargetProfile({
      targetHost: 'api.target.internal',
      findings,
      lineage: canonicalLineage,
    });

    const result = engine.correlate(profile);

    assert.strictEqual(result.contractVersion, INTELLIGENCE_CONTRACT_VERSION);
    assert.strictEqual(result.kind, 'recommendation_engine_result');
    assert.strictEqual(result.targetHost, 'api.target.internal');
    assert.strictEqual(result.recommendations.length, 2, 'Must produce exactly 2 correlated recommendations');

    const chainRec = result.recommendations.find(r => r.category === 'cross_origin_exploit_chain');
    assert.ok(chainRec, 'Cross-Origin exploit chain recommendation must be generated');
    assert.strictEqual(chainRec.suggestedCapability, 'cross_origin_escalation');
    assert.deepStrictEqual(chainRec.requiredPermissions, ['activeValidation', 'authenticatedTesting']);
    assert.strictEqual(chainRec.severity, 'high');
    assert.strictEqual(chainRec.confidence, 0.95);
    assert.ok(chainRec.sourceFindingIds.includes('fnd_cors_001'));
    assert.ok(chainRec.sourceFindingIds.includes('fnd_refl_002'));
    assert.deepStrictEqual(chainRec.lineage, canonicalLineage);

    const accessRec = result.recommendations.find(r => r.category === 'access_control_verification');
    assert.ok(accessRec, 'Access control verification recommendation must be generated');
    assert.strictEqual(accessRec.suggestedCapability, 'active_validation');
    assert.deepStrictEqual(accessRec.requiredPermissions, ['activeValidation']);
    assert.strictEqual(accessRec.severity, 'high');
    assert.strictEqual(accessRec.confidence, 0.90);
    assert.ok(accessRec.sourceFindingIds.includes('fnd_idor_003'));
    assert.deepStrictEqual(accessRec.lineage, canonicalLineage);

    console.log('    [PASS] TargetRecommendationEngine accurately generated Cross-Origin and Access Control recommendations');
  }

  // -------------------------------------------------------------------------
  // Assertion 3: Strict Abstention Discipline on Benign and Quiet Profiles
  // -------------------------------------------------------------------------
  {
    console.log('\n[+] Assertion 3: Validating abstention discipline on benign target profiles...');

    // Benign profile: zero findings, only secure health check
    const quietProfile = buildTargetProfile({
      targetHost: 'secure.internal.corp',
      findings: [],
      observations: [
        {
          url: 'https://secure.internal.corp/status',
          method: 'GET',
        },
      ],
      lineage: canonicalLineage,
    });

    const quietResult = correlateTargetProfile(quietProfile);
    assert.strictEqual(quietResult.recommendations.length, 0, 'Benign profile with no flaws or params must produce 0 recommendations');

    // Sparse unauthenticated parameterized surface triggers exploratory recommendation
    const paramProfile = buildTargetProfile({
      targetHost: 'search.internal.corp',
      findings: [],
      observations: [
        {
          url: 'https://search.internal.corp/search?query=hello',
          method: 'GET',
        },
      ],
      lineage: canonicalLineage,
    });

    const paramResult = correlateTargetProfile(paramProfile);
    assert.strictEqual(paramResult.recommendations.length, 1);
    assert.strictEqual(paramResult.recommendations[0]?.category, 'parameter_fuzzing');
    assert.strictEqual(paramResult.recommendations[0]?.severity, 'medium');

    console.log('    [PASS] Clean abstention enforced: 0 ungrounded recommendations on benign profiles');
  }

  // -------------------------------------------------------------------------
  // Assertion 4: Lineage Tuple Integrity End-to-End
  // -------------------------------------------------------------------------
  {
    console.log('\n[+] Assertion 4: Verifying end-to-end lineage tuple integrity...');

    const finding = createMockFinding({
      id: 'fnd_auth_009',
      type: 'BROKEN_ACCESS_CONTROL',
      target: 'https://secure-gw.example.com/api/records?recId=99',
      confidence: 0.91,
      metadata: { category: 'BROKEN_ACCESS_CONTROL' },
    });

    const customLineage: AuthorizedExecutionLineageTuple = {
      assessmentId: 'asmt_custom_lineage_999',
      scanId: 'scan_custom_lineage_999',
      authorizationGrantId: 'grant_custom_lineage_999',
      authorizationDecisionId: 'dec_custom_lineage_999',
      actorId: 'usr_compliance_officer_42',
    };

    const profile = buildTargetProfile({
      targetHost: 'secure-gw.example.com',
      findings: [finding],
      lineage: customLineage,
    });

    assert.deepStrictEqual(profile.lineage, customLineage);

    const result = engine.correlate(profile);
    assert.deepStrictEqual(result.lineage, customLineage);
    assert.ok(result.recommendations.length > 0);

    for (const rec of result.recommendations) {
      assert.deepStrictEqual(rec.lineage, customLineage);
      assert.ok(rec.recommendationId.length > 0);
      assert.ok(!rec.recommendationId.includes('idor'));
      assert.ok(!rec.recommendationId.includes('vulnerable'));
      assert.ok(!rec.recommendationId.includes('attack'));
    }

    console.log('    [PASS] Continuous lineage tuple preserved across profile and all generated recommendations');
  }

  console.log('\n>>> ALL 4 MILESTONE F5 ASSERTIONS PASSED SUCCESSFULLY! <<<');
}

runMilestoneF5SmokeSuite().catch((err) => {
  console.error('[!] MILESTONE F5 SMOKE SUITE FAILED:', err);
  process.exit(1);
});
