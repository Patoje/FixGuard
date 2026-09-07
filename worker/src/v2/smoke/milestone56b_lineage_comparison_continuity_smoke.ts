import assert from 'node:assert';
import { runAuthorizedComparisonValidation } from '../validation/AuthorizedComparisonValidationService.js';
import type { AuthorizedComparisonValidationRequest } from '../validation/AuthorizedComparisonValidationContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { evaluateHumanReviewedEvidencePromotion } from '../evidence-review/HumanReviewedEvidencePromotionService.js';
import type { HumanReviewedEvidencePromotionRequest } from '../evidence-review/HumanReviewedEvidencePromotionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { SafeResponseSnapshot } from '../comparison/ResponseComparatorContracts.js';

console.log('--- V2 M56B Lineage & Comparison Continuity Smoke Test ---');

const testEvaluatedAt = '2026-07-05T12:00:00.000Z';
const scanId = 'scan_m56b_1';
const assessmentId = 'assess_m56b_1';
const grantId = 'grant_m56b_1';
const decisionId = 'dec_m56b_1';

const scopeGrant: AuthorizedScopeGrant = {
  contractVersion: 'fixguard-authorized-scope-policy/v0',
  kind: 'authorized_scope_grant',
  grantId,
  scanId,
  issuedAt: '2026-07-01T00:00:00.000Z',
  expiresAt: '2026-07-10T23:59:59.999Z',
  subject: { targetKind: 'origin', normalizedOrigin: 'https://example.com' },
  authorizationBasis: { basisKind: 'internal_asset_record', recordedBy: 'human_user', authorizationText: 'Test' },
  permissionSet: {
    passiveRecon: true, technologyFingerprinting: true, endpointDiscovery: true, activeCrawling: false,
    authenticatedTesting: false, lightValidation: true, activeValidation: false, aggressiveValidation: false,
    oobTesting: false, destructiveOperations: false as const,
  },
  boundaries: {
    allowedOrigins: ['https://example.com'], allowedMethods: ['GET'],
    allowedPathPatterns: [{ match: 'prefix', pathTemplate: '/' }], deniedPathPatterns: [],
  },
  constraints: {
    allowLoginRequiredAreas: false, allowStateChangingRequests: false, allowCredentialUse: false,
    allowOobCallbacks: false, allowThirdPartyTargets: false,
  },
  classification: {
    createsRealFindings: false, createsPersistedEvidence: false, confirmsVulnerabilities: false,
    makesRiskClaims: false, makesSeverityClaims: false, makesImpactClaims: false,
    executesNetwork: false, executesTools: false, persistsData: false,
  },
};

const establishRes = establishVerifiedAuthorizationDecision({
  contractVersion: 'fixguard-verified-authorization-decision/v0',
  kind: 'establish_verified_authorization_decision_request',
  assessmentId,
  scanId,
  authorizationDecisionId: decisionId,
  authorizedActor: { actorId: 'sys_actor', actorType: 'human' },
  decision: 'authorized',
  decidedAt: '2026-07-01T12:00:00.000Z',
  scopeGrant,
}, '2026-07-01T12:00:00.000Z');

assert.strictEqual(establishRes.status, 'established');
assert.ok(establishRes.decision);
const validDecision = establishRes.decision;

const baselineSnapshot: SafeResponseSnapshot = {
  contractVersion: "fixguard-response-comparator/v0",
  kind: "safe_response_snapshot",
  snapshotId: "snap-base-1",
  scanId,
  capturedAt: testEvaluatedAt,
  role: "baseline",
  subject: { normalizedOrigin: "https://example.com", method: "GET" as const, pathTemplate: "/test" },
  statusCode: 200,
  contentLength: 1000,
  responseTimeMs: 200,
  headerNames: ["content-type", "content-length"],
  bodyHash: "hash1",
  classification: { createsRealFindings: false, createsPersistedEvidence: false, confirmsVulnerabilities: false, makesRiskClaims: false, makesSeverityClaims: false, makesImpactClaims: false, executesNetwork: false, executesTools: false, persistsData: false }
};

const validationSnapshot: SafeResponseSnapshot = {
  contractVersion: "fixguard-response-comparator/v0",
  kind: "safe_response_snapshot",
  snapshotId: "snap-val-1",
  scanId,
  capturedAt: testEvaluatedAt,
  role: "validation",
  subject: { normalizedOrigin: "https://example.com", method: "GET" as const, pathTemplate: "/test" },
  statusCode: 403,
  contentLength: 0,
  responseTimeMs: 200,
  headerNames: ["content-type", "content-length"],
  bodyHash: "hash4",
  classification: { createsRealFindings: false, createsPersistedEvidence: false, confirmsVulnerabilities: false, makesRiskClaims: false, makesSeverityClaims: false, makesImpactClaims: false, executesNetwork: false, executesTools: false, persistsData: false }
};

function createBaseRequest(): AuthorizedComparisonValidationRequest {
  return {
    contractVersion: 'fixguard-authorized-comparison-validation/v0',
    kind: 'authorized_comparison_validation_request',
    validationId: 'val-123',
    scanId,
    requestedAt: testEvaluatedAt,
    scopeGrant,
    scopeActionRequest: {
      contractVersion: "fixguard-authorized-scope-policy/v0",
      kind: "scope_action_request",
      requestId: "act-1",
      scanId,
      requestedAt: testEvaluatedAt,
      actionKind: "light_validation",
      target: { targetKind: "origin", normalizedOrigin: "https://example.com" },
      method: "GET",
      pathTemplate: "/test",
      intensity: "low",
      usesCredentials: false,
      mayChangeServerState: false,
      usesOob: false,
      classification: {
        createsRealFindings: false,
        createsPersistedEvidence: false,
        confirmsVulnerabilities: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false,
        executesNetwork: false,
        executesTools: false,
        persistsData: false
      }
    },
    baselineSnapshot,
    validationSnapshot,
    comparisonMode: 'http_difference',
    comparisonThresholds: {
      contentLengthDeltaPercentSignificant: 10,
      responseTimeDeltaMsSignificant: 1000
    },
    mappingMode: 'http_difference_to_evidence',
    reviewerPolicy: {
      requireHumanReview: true,
      allowAutoEvidenceRecord: false,
      allowFindingCandidateCreation: false,
      allowPersistence: false,
      allowExternalDelivery: false,
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
    }
  };
}

async function runTests() {
  // 1. Happy Path with Verified Authorization Decision and Lineage Ref
  {
    const req: AuthorizedComparisonValidationRequest = {
      ...createBaseRequest(),
      verifiedAuthorizationDecision: validDecision,
      lineageRef: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId: 'sys_actor',
      }
    };

    const result = runAuthorizedComparisonValidation(req, testEvaluatedAt);
    assert.strictEqual(result.status, 'completed');
    assert.strictEqual(result.reasonCode, 'completed_with_evidence_draft');
    assert.ok(result.provenance, 'Provenance must be populated on verified lineage run');
    assert.strictEqual(result.provenance?.authorizationDecisionId, decisionId);
    assert.strictEqual(result.provenance?.authorizationGrantId, grantId);
    assert.strictEqual(result.provenance?.assessmentId, assessmentId);
    assert.strictEqual(result.provenance?.scanId, scanId);
    assert.strictEqual(result.provenance?.actorId, 'sys_actor');
    assert.strictEqual(result.explicitNonClaims.noConfirmedVulnerability, true);
    assert.strictEqual(result.classification.confirmsVulnerabilities, false);
    console.log('[+] 1. Happy path with verified authorization and lineage passes with complete provenance.');

    // Verify downstream M50 consumption of M49 result with provenance
    const m50Request: HumanReviewedEvidencePromotionRequest = {
      contractVersion: 'fixguard-human-reviewed-evidence-promotion/v0',
      kind: 'human_reviewed_evidence_promotion_request',
      promotionId: 'promo_m56b_1',
      scanId,
      requestedAt: '2026-07-05T12:01:00.000Z',
      reviewDecision: {
        decision: 'approve_evidence',
        reviewerId: 'rev_human_1',
        reviewedAt: '2026-07-05T12:01:00.000Z',
      },
      sourceIndicatorRef: {
        kind: 'reviewed_indicator_reference',
        indicatorId: 'ind_diff_1',
        scanId,
      },
      validationResult: result,
      classification: {
        createsNonPersistedEvidenceRecord: false,
        createsPersistedEvidence: false,
        createsFindingCandidate: false,
        createsSafeReportItem: false,
        confirmsVulnerabilities: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false,
        executesNetwork: false,
        executesTools: false,
        persistsData: false,
      }
    };

    const m50Result = evaluateHumanReviewedEvidencePromotion(m50Request, '2026-07-05T12:02:00.000Z');
    assert.strictEqual(m50Result.status, 'promoted');
    assert.strictEqual(m50Result.reasonCode, 'promoted_to_non_persisted_evidence_record');
    assert.ok(m50Result.nonPersistedEvidenceRecord);
    console.log('[+] 1b. Downstream M50 promotion consumes M49 verified lineage result seamlessly.');
  }

  // 2. Unbranded / unconfirmed authorization fails closed
  {
    const req: AuthorizedComparisonValidationRequest = {
      ...createBaseRequest(),
      verifiedAuthorizationDecision: {
        contractVersion: 'fixguard-verified-authorization-decision/v0',
        kind: 'verified_authorization_decision',
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        authorizedActor: { actorId: 'sys_actor', actorType: 'human' },
        decision: 'authorized',
        decidedAt: '2026-07-01T12:00:00.000Z',
        scopeGrant,
        verification: { verifiedAt: '2026-07-01T12:00:00.000Z', method: 'trusted_application_boundary' }
      } as any,
    };

    const result = runAuthorizedComparisonValidation(req, testEvaluatedAt);
    assert.strictEqual(result.status, 'blocked');
    assert.strictEqual(result.reasonCode, 'blocked_authorization_invalid');
    console.log('[+] 2. Unbranded/unconfirmed authorization fails closed (blocked_authorization_invalid).');
  }

  // 3. ScanId mismatch fails closed
  {
    const req: AuthorizedComparisonValidationRequest = {
      ...createBaseRequest(),
      scanId: 'scan_other',
      verifiedAuthorizationDecision: validDecision,
    };

    const result = runAuthorizedComparisonValidation(req, testEvaluatedAt);
    assert.strictEqual(result.status, 'blocked');
    assert.strictEqual(result.reasonCode, 'blocked_lineage_mismatch');
    console.log('[+] 3. ScanId mismatch between request and authorization fails closed (blocked_lineage_mismatch).');
  }

  // 4. GrantId mismatch fails closed
  {
    const req: AuthorizedComparisonValidationRequest = {
      ...createBaseRequest(),
      scopeGrant: { ...scopeGrant, grantId: 'grant_different' } as AuthorizedScopeGrant,
      verifiedAuthorizationDecision: validDecision,
    };

    const result = runAuthorizedComparisonValidation(req, testEvaluatedAt);
    assert.strictEqual(result.status, 'blocked');
    assert.strictEqual(result.reasonCode, 'blocked_lineage_mismatch');
    console.log('[+] 4. GrantId mismatch between request and authorization fails closed (blocked_lineage_mismatch).');
  }

  // 5. LineageRef decisionId mismatch fails closed
  {
    const req: AuthorizedComparisonValidationRequest = {
      ...createBaseRequest(),
      verifiedAuthorizationDecision: validDecision,
      lineageRef: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: 'dec_other',
        actorId: 'sys_actor',
      }
    };

    const result = runAuthorizedComparisonValidation(req, testEvaluatedAt);
    assert.strictEqual(result.status, 'blocked');
    assert.strictEqual(result.reasonCode, 'blocked_lineage_mismatch');
    console.log('[+] 5. LineageRef mismatch fails closed (blocked_lineage_mismatch).');
  }

  // 6. LineageRef without Verified Authorization Decision fails closed
  {
    const req: AuthorizedComparisonValidationRequest = {
      ...createBaseRequest(),
      lineageRef: {
        assessmentId,
        scanId,
        authorizationGrantId: grantId,
        authorizationDecisionId: decisionId,
        actorId: 'sys_actor',
      }
    };

    const result = runAuthorizedComparisonValidation(req, testEvaluatedAt);
    assert.strictEqual(result.status, 'blocked');
    assert.strictEqual(result.reasonCode, 'blocked_lineage_mismatch');
    console.log('[+] 6. LineageRef without verified decision fails closed (blocked_lineage_mismatch).');
  }

  console.log('--- V2 M56B Lineage & Comparison Continuity Smoke Completed Successfully ---');
}

runTests().catch(err => {
  console.error(err);
  process.exit(1);
});
