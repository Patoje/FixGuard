import assert from 'node:assert/strict';
import { runAuthorizedComparisonValidation, validateEvidenceDraftEnvelopeForValidationResult } from '../validation/AuthorizedComparisonValidationService.js';
import { AUTHORIZED_COMPARISON_VALIDATION_CONTRACT_VERSION } from '../validation/AuthorizedComparisonValidationContracts.js';

const now = new Date();

export function makeRequest(overrides: any = {}) {
  return {
    contractVersion: AUTHORIZED_COMPARISON_VALIDATION_CONTRACT_VERSION,
    kind: "authorized_comparison_validation_request",
    validationId: "val-123",
    scanId: "scan-001",
    requestedAt: now.toISOString(),
    scopeGrant: {
      contractVersion: "fixguard-authorized-scope-policy/v0",
      kind: "authorized_scope_grant",
      grantId: "grant-1",
      scanId: "scan-001",
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 100000).toISOString(),
      subject: { targetKind: "origin", normalizedOrigin: "https://example.com" },
      authorizationBasis: {
        basisKind: "user_attestation",
        recordedBy: "human_user",
        authorizationText: "test"
      },
      permissionSet: {
        passiveRecon: false,
        technologyFingerprinting: false,
        endpointDiscovery: false,
        activeCrawling: false,
        authenticatedTesting: false,
        lightValidation: true,
        activeValidation: true,
        aggressiveValidation: false,
        oobTesting: false,
        destructiveOperations: false
      },
      boundaries: {
        allowedOrigins: ["https://example.com"],
        allowedMethods: ["GET"]
      },
      constraints: {
        allowLoginRequiredAreas: false,
        allowStateChangingRequests: false,
        allowCredentialUse: false,
        allowOobCallbacks: false,
        allowThirdPartyTargets: false
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
        persistsData: false
      }
    },
    scopeActionRequest: {
      contractVersion: "fixguard-authorized-scope-policy/v0",
      kind: "scope_action_request",
      requestId: "act-1",
      scanId: "scan-001",
      requestedAt: now.toISOString(),
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
    baselineSnapshot: {
      contractVersion: "fixguard-response-comparator/v0",
      kind: "safe_response_snapshot",
      snapshotId: "snap-base-1",
      scanId: "scan-001",
      capturedAt: now.toISOString(),
      role: "baseline",
      subject: { normalizedOrigin: "https://example.com", method: "GET", pathTemplate: "/test" },
      statusCode: 200,
      contentLength: 1000,
      responseTimeMs: 200,
      headerNames: ["content-type", "content-length"],
      bodyHash: "hash1",
      classification: { createsRealFindings: false, createsPersistedEvidence: false, confirmsVulnerabilities: false, makesRiskClaims: false, makesSeverityClaims: false, makesImpactClaims: false, executesNetwork: false, executesTools: false, persistsData: false }
    },
    validationSnapshot: {
      contractVersion: "fixguard-response-comparator/v0",
      kind: "safe_response_snapshot",
      snapshotId: "snap-val-1",
      scanId: "scan-001",
      capturedAt: now.toISOString(),
      role: "validation",
      subject: { normalizedOrigin: "https://example.com", method: "GET", pathTemplate: "/test" },
      statusCode: 403,
      contentLength: 0,
      responseTimeMs: 200,
      headerNames: ["content-type", "content-length"],
      bodyHash: "hash4",
      classification: { createsRealFindings: false, createsPersistedEvidence: false, confirmsVulnerabilities: false, makesRiskClaims: false, makesSeverityClaims: false, makesImpactClaims: false, executesNetwork: false, executesTools: false, persistsData: false }
    },
    comparisonMode: "http_difference",
    comparisonThresholds: {
      contentLengthDeltaPercentSignificant: 10,
      responseTimeDeltaMsSignificant: 1000
    },
    mappingMode: "http_difference_to_evidence",
    reviewerPolicy: {
      requireHumanReview: true,
      allowAutoEvidenceRecord: false,
      allowFindingCandidateCreation: false,
      allowPersistence: false,
      allowExternalDelivery: false
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
      persistsData: false
    },
    ...overrides
  };
}

// 1. Happy path HTTP difference
function testHappyPathHttpDifference() {
  console.log('[*] Testing Happy Path HTTP Difference...');
  const req = makeRequest();
  const res = runAuthorizedComparisonValidation(req, now.toISOString());
  console.log('Result:', JSON.stringify(res, null, 2));
  assert.strictEqual(res.status, 'completed');
  assert.strictEqual(res.reasonCode, 'completed_with_evidence_draft');
  assert.ok(res.evidenceDraft !== undefined);
  assert.strictEqual(res.explicitNonClaims.noConfirmedVulnerability, true);
  assert.strictEqual(res.classification.createsRealFindings, false);
  console.log('[+] Happy Path HTTP Difference works.');
}

// 2. Authorization difference path
function testAuthDifferencePath() {
  console.log('[*] Testing Authorization Difference Path...');
  const req = makeRequest({
    scopeActionRequest: { ...makeRequest().scopeActionRequest, actionKind: "active_validation" },
    comparisonMode: "authorization_difference",
    mappingMode: "authorization_difference_to_evidence",
    baselineSnapshot: { ...makeRequest().baselineSnapshot, statusCode: 200 },
    validationSnapshot: { ...makeRequest().validationSnapshot, statusCode: 403, authState: { authenticatedSignal: "appears_unauthenticated" } }
  });
  const res = runAuthorizedComparisonValidation(req, now.toISOString());
  if (res.status !== 'completed') {
    console.log("FAILED RES:", JSON.stringify(res, null, 2));
  }
  assert.strictEqual(res.status, 'completed');
  assert.strictEqual(res.reasonCode, 'completed_with_evidence_draft');
  const serialized = JSON.stringify(res).toLowerCase();
  assert.ok(!serialized.includes('idor'));
  assert.ok(!serialized.includes('bola'));
  assert.ok(!serialized.includes('auth bypass'));
  console.log('[+] Authorization Difference Path works safely.');
}

// 3. Time-based path
function testTimeBasedPath() {
  console.log('[*] Testing Time-based Path...');
  const req = makeRequest({
    scopeActionRequest: { ...makeRequest().scopeActionRequest, actionKind: "active_validation" },
    comparisonMode: "time_based_difference",
    mappingMode: "time_based_signal_to_evidence",
    baselineSnapshot: { ...makeRequest().baselineSnapshot, statusCode: 200, responseTimeMs: 100 },
    validationSnapshot: { ...makeRequest().validationSnapshot, statusCode: 200, responseTimeMs: 1500 }
  });
  const res = runAuthorizedComparisonValidation(req, now.toISOString());
  assert.strictEqual(res.status, 'completed');
  assert.strictEqual(res.reasonCode, 'completed_with_evidence_draft');
  const serialized = JSON.stringify(res).toLowerCase();
  assert.ok(!serialized.includes('sqli'));
  assert.ok(!serialized.includes('time-based attack'));
  console.log('[+] Time-based Path works safely.');
}

// 4. Scope denied short-circuit
function testScopeDenied() {
  console.log('[*] Testing Scope Denied Short-Circuit...');
  const req = makeRequest({
    scopeGrant: { ...makeRequest().scopeGrant, permissionSet: { ...makeRequest().scopeGrant.permissionSet, lightValidation: false } },
    // Inject bad snapshots that would crash if M47 ran
    baselineSnapshot: undefined,
    validationSnapshot: undefined
  });
  const res = runAuthorizedComparisonValidation(req, now.toISOString());
  assert.strictEqual(res.status, 'blocked');
  assert.strictEqual(res.reasonCode, 'blocked_scope_denied');
  assert.strictEqual(res.comparisonSummary, undefined);
  assert.strictEqual(res.mappingSummary, undefined);
  assert.strictEqual(res.evidenceDraft, undefined);
  console.log('[+] Scope Denied Short-Circuit works.');
}

// 5. Scope invalid / actionKind blocked
function testScopeInvalidActionKind() {
  console.log('[*] Testing Scope Invalid ActionKind...');
  const badKinds: any[] = [
    "passive_recon", "technology_fingerprint", "endpoint_discovery", "active_crawl", "aggressive_validation", "oob_validation", "destructive_operation",
    "unknown_random", undefined, 123, null, {}
  ];
  for (const k of badKinds) {
    const req = makeRequest();
    if (k === undefined) {
      delete req.scopeActionRequest;
    } else {
      req.scopeActionRequest.actionKind = k;
    }
    // ensure M47/M48 would crash if run (by omitting snapshots) to prove it short-circuits
    delete req.baselineSnapshot;
    delete req.validationSnapshot;
    const res = runAuthorizedComparisonValidation(req, now.toISOString());
    assert.strictEqual(res.status, 'blocked');
    assert.strictEqual(res.reasonCode, 'blocked_scope_invalid');
    assert.strictEqual(res.comparisonSummary, undefined);
    assert.strictEqual(res.mappingSummary, undefined);
    assert.strictEqual(res.evidenceDraft, undefined);
  }
  console.log('[+] ActionKinds blocked correctly.');
}

// 6. Comparison failed
function testComparisonFailed() {
  console.log('[*] Testing Comparison Failed...');
  // Force comparison failure (e.g., scanId mismatch between grant and snapshot)
  const req = makeRequest({
    baselineSnapshot: { ...makeRequest().baselineSnapshot, scanId: "wrong-scan" }
  });
  const res = runAuthorizedComparisonValidation(req, now.toISOString());
  assert.strictEqual(res.status, 'blocked');
  assert.strictEqual(res.reasonCode, 'blocked_comparison_failed');
  assert.strictEqual(res.mappingSummary, undefined);
  assert.strictEqual(res.evidenceDraft, undefined);
  console.log('[+] Comparison Failed works.');
}

// 7. Mapping blocked
function testMappingBlocked() {
  console.log('[*] Testing Mapping Blocked...');
  // Valid comparison, but mapping mode mismatch
  const req = makeRequest({
    comparisonMode: "http_difference",
    mappingMode: "authorization_difference_to_evidence"
  });
  const res = runAuthorizedComparisonValidation(req, now.toISOString());
  assert.strictEqual(res.status, 'blocked');
  assert.strictEqual(res.reasonCode, 'blocked_mapping_blocked');
  assert.strictEqual(res.evidenceDraft, undefined);
  console.log('[+] Mapping Blocked works.');
}

// 8. Mapping needs more review
function testMappingNeedsReview() {
  console.log('[*] Testing Mapping Needs Review...');
  // Identical snapshots -> weak/no difference -> needs_more_review
  const req = makeRequest({
    validationSnapshot: { ...makeRequest().baselineSnapshot, snapshotId: "snap-val-same", role: "validation" }
  });
  const res = runAuthorizedComparisonValidation(req, now.toISOString());
  if (res.status !== 'needs_more_review') {
    console.log("FAILED RES mapping needs review:", JSON.stringify(res, null, 2));
  }
  assert.strictEqual(res.status, 'needs_more_review');
  assert.strictEqual(res.reasonCode, 'needs_more_review_from_mapping');
  assert.strictEqual(res.evidenceDraft, undefined);
  console.log('[+] Mapping Needs Review works.');
}

// 9. Metadata sentinels/no raw echo
function testMetadataSentinels() {
  console.log('[*] Testing Metadata Sentinels...');
  const req1 = makeRequest({ validationId: "secret_token_123" });
  const res1 = runAuthorizedComparisonValidation(req1, now.toISOString());
  assert.strictEqual(res1.status, 'failed');
  assert.strictEqual(res1.validationId, 'invalid_validation_id');

  const req2 = makeRequest({ scanId: "secret_scan" });
  const res2 = runAuthorizedComparisonValidation(req2, now.toISOString());
  assert.strictEqual(res2.status, 'failed');
  assert.strictEqual(res2.scanId, 'invalid_scan_id');

  const res3 = runAuthorizedComparisonValidation(makeRequest(), "not-a-date");
  assert.strictEqual(res3.status, 'failed');
  assert.strictEqual(res3.evaluatedAt, '1970-01-01T00:00:00.000Z');

  // Too long validationId causing derived ID unsafe
  const req4 = makeRequest({ validationId: "a".repeat(128) });
  const res4 = runAuthorizedComparisonValidation(req4, now.toISOString());
  assert.strictEqual(res4.status, 'failed');
  assert.strictEqual(res4.reasonCode, 'invalid_validation_metadata');
  
  // snapshotId secret
  const req5 = makeRequest({ baselineSnapshot: { ...makeRequest().baselineSnapshot, snapshotId: "secret_snap" } });
  const res5 = runAuthorizedComparisonValidation(req5, now.toISOString());
  assert.strictEqual(res5.status, 'blocked');
  const str5 = JSON.stringify(res5);
  assert.ok(!str5.includes("secret_snap"));

  console.log('[+] Metadata Sentinels work.');
}

// 10. Runtime hardening
function testRuntimeHardening() {
  console.log('[*] Testing Runtime Hardening...');
  
  // 3.2 wrong kind
  const reqWrongKind = makeRequest({ kind: "wrong_kind" });
  const resWrongKind = runAuthorizedComparisonValidation(reqWrongKind, now.toISOString());
  assert.strictEqual(resWrongKind.status, 'failed');
  assert.strictEqual(resWrongKind.reasonCode, 'invalid_validation_request');
  assert.strictEqual(resWrongKind.comparisonSummary, undefined);
  assert.strictEqual(resWrongKind.mappingSummary, undefined);
  assert.strictEqual(resWrongKind.evidenceDraft, undefined);

  // 3.3 classification missing / extra
  const reqClassMissing = makeRequest();
  delete reqClassMissing.classification;
  assert.strictEqual(runAuthorizedComparisonValidation(reqClassMissing, now.toISOString()).status, 'failed');

  assert.strictEqual(runAuthorizedComparisonValidation(makeRequest({ classification: { ...makeRequest().classification, extra: true } }), now.toISOString()).status, 'failed');
  assert.strictEqual(runAuthorizedComparisonValidation(makeRequest({ classification: { ...makeRequest().classification, makesRiskClaims: true } }), now.toISOString()).status, 'failed');
  assert.strictEqual(runAuthorizedComparisonValidation(makeRequest({ classification: { ...makeRequest().classification, makesSeverityClaims: true } }), now.toISOString()).status, 'failed');
  assert.strictEqual(runAuthorizedComparisonValidation(makeRequest({ classification: { ...makeRequest().classification, makesImpactClaims: true } }), now.toISOString()).status, 'failed');
  assert.strictEqual(runAuthorizedComparisonValidation(makeRequest({ classification: { ...makeRequest().classification, createsRealFindings: "false" } }), now.toISOString()).status, 'failed');

  // 3.4 requestedAt invalid
  assert.strictEqual(runAuthorizedComparisonValidation(makeRequest({ requestedAt: "not-a-date" }), now.toISOString()).status, 'failed');
  assert.strictEqual(runAuthorizedComparisonValidation(makeRequest({ requestedAt: "2026-07-08" }), now.toISOString()).status, 'failed');
  const reqNoDate = makeRequest();
  delete reqNoDate.requestedAt;
  assert.strictEqual(runAuthorizedComparisonValidation(reqNoDate, now.toISOString()).status, 'failed');

  // 3.5 reviewerPolicy unsafe / extra
  const badPolicies = [
    { requireHumanReview: false, allowAutoEvidenceRecord: false, allowFindingCandidateCreation: false, allowPersistence: false, allowExternalDelivery: false },
    { requireHumanReview: true, allowAutoEvidenceRecord: true, allowFindingCandidateCreation: false, allowPersistence: false, allowExternalDelivery: false },
    { requireHumanReview: true, allowAutoEvidenceRecord: false, allowFindingCandidateCreation: true, allowPersistence: false, allowExternalDelivery: false },
    { requireHumanReview: true, allowAutoEvidenceRecord: false, allowFindingCandidateCreation: false, allowPersistence: true, allowExternalDelivery: false },
    { requireHumanReview: true, allowAutoEvidenceRecord: false, allowFindingCandidateCreation: false, allowPersistence: false, allowExternalDelivery: true },
    { requireHumanReview: true, allowAutoEvidenceRecord: false, allowFindingCandidateCreation: false, allowPersistence: false, allowExternalDelivery: false, extra: true }
  ];
  for (const pol of badPolicies) {
    const resPol = runAuthorizedComparisonValidation(makeRequest({ reviewerPolicy: pol }), now.toISOString());
    assert.ok(resPol.status === 'blocked' || resPol.status === 'failed');
  }
  const reqNoPol = makeRequest();
  delete reqNoPol.reviewerPolicy;
  assert.strictEqual(runAuthorizedComparisonValidation(reqNoPol, now.toISOString()).status, 'failed');

  // 3.6 comparisonMode invalid
  assert.strictEqual(runAuthorizedComparisonValidation(makeRequest({ comparisonMode: "SQLi" }), now.toISOString()).status, 'failed');
  assert.strictEqual(runAuthorizedComparisonValidation(makeRequest({ comparisonMode: "authorization_secret" }), now.toISOString()).status, 'failed');
  const reqNoCompMode = makeRequest();
  delete reqNoCompMode.comparisonMode;
  assert.strictEqual(runAuthorizedComparisonValidation(reqNoCompMode, now.toISOString()).status, 'failed');

  // 3.7 mappingMode invalid
  assert.strictEqual(runAuthorizedComparisonValidation(makeRequest({ mappingMode: "SQLi" }), now.toISOString()).status, 'failed');
  assert.strictEqual(runAuthorizedComparisonValidation(makeRequest({ mappingMode: "authorization_secret" }), now.toISOString()).status, 'failed');
  const reqNoMapMode = makeRequest();
  delete reqNoMapMode.mappingMode;
  assert.strictEqual(runAuthorizedComparisonValidation(reqNoMapMode, now.toISOString()).status, 'failed');

  // 3.8 forbidden terms
  const forbiddenTerms = [
    "SQLi", "IDOR", "BOLA", "auth bypass", "vulnerable", "exploit", "critical severity", "target is vulnerable",
    "Authorization: Bearer abc", "Cookie: session=abc", "secret_token_123", "raw_headers_content", "raw_body_content"
  ];
  for (const f of forbiddenTerms) {
    const r1 = runAuthorizedComparisonValidation(makeRequest({ validationId: f }), now.toISOString());
    assert.strictEqual(r1.status, 'failed');
    assert.ok(r1.reasonCode === 'invalid_validation_metadata' || r1.reasonCode === 'invalid_validation_request');
    assert.strictEqual(r1.comparisonSummary, undefined);
    assert.strictEqual(r1.mappingSummary, undefined);
    assert.strictEqual(r1.evidenceDraft, undefined);
    assert.ok(!r1.error?.safeMessage?.includes(f));
    assert.ok(r1.validationId !== f); // Uses sentinel, does not echo raw unsafe value

    const r2 = runAuthorizedComparisonValidation(makeRequest({ scanId: f }), now.toISOString());
    assert.strictEqual(r2.status, 'failed');
    assert.ok(r2.reasonCode === 'invalid_validation_metadata' || r2.reasonCode === 'invalid_validation_request');
    assert.strictEqual(r2.comparisonSummary, undefined);
    assert.strictEqual(r2.mappingSummary, undefined);
    assert.strictEqual(r2.evidenceDraft, undefined);
    assert.ok(!r2.error?.safeMessage?.includes(f));
    assert.ok(r2.scanId !== f); // Uses sentinel, does not echo raw unsafe value

    const reqUnknown = makeRequest({ [f]: true });
    const r3 = runAuthorizedComparisonValidation(reqUnknown, now.toISOString());
    assert.strictEqual(r3.status, 'failed');
    assert.ok(r3.reasonCode === 'invalid_validation_metadata' || r3.reasonCode === 'invalid_validation_request');
    assert.strictEqual(r3.comparisonSummary, undefined);
    assert.strictEqual(r3.mappingSummary, undefined);
    assert.strictEqual(r3.evidenceDraft, undefined);
    assert.ok(!r3.error?.safeMessage?.includes(f));
  }

  // 3.9 validationId/scanId authorization_difference
  const rAuthDiffVal = runAuthorizedComparisonValidation(makeRequest({ validationId: "authorization_difference" }), now.toISOString());
  assert.strictEqual(rAuthDiffVal.status, 'failed');
  assert.ok(rAuthDiffVal.reasonCode === 'invalid_validation_metadata' || rAuthDiffVal.reasonCode === 'invalid_validation_request');
  assert.strictEqual(rAuthDiffVal.comparisonSummary, undefined);
  assert.strictEqual(rAuthDiffVal.mappingSummary, undefined);
  assert.strictEqual(rAuthDiffVal.evidenceDraft, undefined);

  const rAuthDiffScan = runAuthorizedComparisonValidation(makeRequest({ scanId: "authorization_difference" }), now.toISOString());
  assert.strictEqual(rAuthDiffScan.status, 'failed');
  assert.ok(!rAuthDiffScan.error?.safeMessage?.includes("authorization_difference"));
  assert.strictEqual(rAuthDiffScan.evidenceDraft, undefined);
  assert.strictEqual(rAuthDiffScan.status, 'failed');

  console.log('[+] Runtime Hardening works.');
}

// 11. EvidenceDraft validation
function testEvidenceDraftValidation() {
  console.log('[*] Testing EvidenceDraft Validation (Internal)...');
  const baseDraft = {
    draftKind: "non_persisted_comparison_evidence_draft",
    draftId: "draft-1",
    suggestedEvidenceType: "http_difference",
    suggestedStrength: "moderate",
    sourceComparisonId: "comp-1",
    sourceSnapshotIds: {
      baselineSnapshotId: "base-1",
      validationSnapshotId: "val-1"
    },
    requiresHumanReview: true,
    notPersisted: true,
    notARealFinding: true,
    notConfirmedEvidence: true,
    notForExternalDelivery: true,
    notM45EvidenceRecord: true,
    safeRationale: "Safe comparison."
  };

  assert.strictEqual(validateEvidenceDraftEnvelopeForValidationResult(baseDraft), true);

  // 3.10 Draft coverage
  assert.strictEqual(validateEvidenceDraftEnvelopeForValidationResult({ ...baseDraft, suggestedStrength: "info" }), false);
  assert.strictEqual(validateEvidenceDraftEnvelopeForValidationResult({ ...baseDraft, suggestedStrength: "critical severity" }), false);
  assert.strictEqual(validateEvidenceDraftEnvelopeForValidationResult({ ...baseDraft, sourceSnapshotIds: { ...baseDraft.sourceSnapshotIds, extra: true } }), false);
  assert.strictEqual(validateEvidenceDraftEnvelopeForValidationResult({ ...baseDraft, notM45EvidenceRecord: false }), false);
  assert.strictEqual(validateEvidenceDraftEnvelopeForValidationResult({ ...baseDraft, notPersisted: false }), false);
  assert.strictEqual(validateEvidenceDraftEnvelopeForValidationResult({ ...baseDraft, safeRationale: "SQLi" }), false);

  console.log('[+] EvidenceDraft Validation logic verified.');
}

// 12. No raw leaks
function testNoRawLeaks() {
  console.log('[*] Testing No Raw Leaks...');
  const req = makeRequest();
  const res = runAuthorizedComparisonValidation(req, now.toISOString());
  const serialized = JSON.stringify(res).toLowerCase();
  const FORBIDDEN_VALUES = [
    'authorization: bearer', 'cookie: session', 'secret_token_123',
    'raw_body_content', 'raw_headers_content', 'stack trace',
    'confirmed vulnerability', 'target is vulnerable', 'critical severity',
    'sqli', 'idor', 'bola', 'auth bypass'
  ];
  for (const forbidden of FORBIDDEN_VALUES) {
    assert.ok(!serialized.includes(forbidden), `Forbidden value ${forbidden} found in result!`);
  }
  console.log('[+] No Raw Leaks works.');
}

// 13. No execution
function testNoExecution() {
  console.log('[*] Testing No Execution...');
  const res = runAuthorizedComparisonValidation(makeRequest(), now.toISOString());
  assert.strictEqual(res.classification.executesNetwork, false);
  assert.strictEqual(res.classification.executesTools, false);
  assert.strictEqual(res.classification.persistsData, false);
  console.log('[+] No Execution works.');
}

function runTests() {
  console.log('--- V2 M49 Authorized Comparison Validation DB-Free Smoke Test ---');
  testHappyPathHttpDifference();
  testAuthDifferencePath();
  testTimeBasedPath();
  testScopeDenied();
  testScopeInvalidActionKind();
  testComparisonFailed();
  testMappingBlocked();
  testMappingNeedsReview();
  testMetadataSentinels();
  testRuntimeHardening();
  testEvidenceDraftValidation();
  testNoRawLeaks();
  testNoExecution();
  console.log('--- M49 Authorized Comparison Validation DB-Free Smoke Completed Successfully ---');
}

try {
  runTests();
} catch (e) {
  console.error(e);
  process.exit(1);
}
