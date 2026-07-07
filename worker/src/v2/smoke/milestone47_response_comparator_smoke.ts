/**
 * M47 — Response Comparator Core DB-Free Smoke Test
 *
 * Tests proven:
 *  1. Valid no-difference comparison
 *  2. Status/content/body/header/json/redirect differences
 *  3. Auth difference -> authorization_difference hint
 *  4. Time difference (mode-gated hint)
 *  5. Error signals (closed enum)
 *  6. Invalid snapshots / request validation
 *  7. Safe sentinels / no raw metadata echo
 *  8. No raw leaks in text fields
 *  9. No execution invariant
 */

import assert from 'node:assert/strict';
import {
  validateSafeResponseSnapshot,
  validateResponseComparisonRequest,
  compareResponses,
  buildResponseDifference,
  deriveComparisonSignificance,
  deriveEvidenceMappingHint,
  getSafeClassification
} from '../comparison/ResponseComparatorService.js';
import { RESPONSE_COMPARATOR_CONTRACT_VERSION } from '../comparison/ResponseComparatorContracts.js';

const now = new Date();

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

function makeSubject(overrides: Record<string, unknown> = {}) {
  return {
    normalizedOrigin: 'https://example.com',
    method: 'GET',
    pathTemplate: '/api/v1/resource',
    ...overrides
  };
}

function makeSnapshot(overrides: Record<string, unknown> = {}) {
  return {
    contractVersion: RESPONSE_COMPARATOR_CONTRACT_VERSION,
    kind: 'safe_response_snapshot',
    snapshotId: 'snap-baseline-1',
    scanId: 'scan-001',
    capturedAt: now.toISOString(),
    role: 'baseline',
    subject: makeSubject(),
    statusCode: 200,
    contentLength: 1024,
    responseTimeMs: 150,
    headerNames: ['content-type', 'x-request-id'],
    bodyHash: 'sha256-abc123def456',
    classification: getSafeClassification(),
    ...overrides
  };
}

function makeValidationSnapshot(overrides: Record<string, unknown> = {}) {
  return makeSnapshot({
    snapshotId: 'snap-validation-1',
    role: 'validation',
    ...overrides
  });
}

function makeRequest(overrides: Record<string, unknown> = {}) {
  return {
    contractVersion: RESPONSE_COMPARATOR_CONTRACT_VERSION,
    kind: 'response_comparison_request',
    comparisonId: 'cmp-001',
    scanId: 'scan-001',
    requestedAt: now.toISOString(),
    baseline: makeSnapshot(),
    validation: makeValidationSnapshot(),
    comparisonMode: 'http_difference',
    thresholds: {
      contentLengthDeltaPercentSignificant: 20,
      responseTimeDeltaMsSignificant: 500
    },
    classification: getSafeClassification(),
    ...overrides
  };
}

// ---------------------------------------------------------------------------
// 1. Valid no-difference comparison
// ---------------------------------------------------------------------------

async function testNoDifference() {
  console.log('[*] Testing valid no-difference comparison...');

  const req = makeRequest();
  const result = compareResponses(req, now.toISOString());

  assert.strictEqual(result.status, 'completed');
  assert.strictEqual(result.comparisonId, 'cmp-001');
  assert.strictEqual(result.baselineSnapshotId, 'snap-baseline-1');
  assert.strictEqual(result.validationSnapshotId, 'snap-validation-1');
  assert.ok(result.difference);
  assert.strictEqual(result.difference.statusCodeChanged, false);
  assert.strictEqual(result.difference.bodyHashChanged, false);
  assert.strictEqual(result.difference.signalSummary.length, 0);
  assert.ok(result.significance);
  assert.strictEqual(result.significance.comparisonSignalStrength, 'none');
  assert.strictEqual(result.significance.hasAnyDifference, false);
  assert.strictEqual(result.significance.hasSignificantDifference, false);

  // Classification flags
  assert.strictEqual(result.classification.createsRealFindings, false);
  assert.strictEqual(result.classification.confirmsVulnerabilities, false);
  assert.strictEqual(result.classification.executesNetwork, false);
  assert.strictEqual(result.classification.executesTools, false);
  assert.strictEqual(result.classification.persistsData, false);

  // Explicit non-claims
  assert.strictEqual(result.explicitNonClaims.noConfirmedVulnerability, true);
  assert.strictEqual(result.explicitNonClaims.noFindingCreated, true);
  assert.strictEqual(result.explicitNonClaims.noPersistedEvidenceCreated, true);
  assert.strictEqual(result.explicitNonClaims.noSeverityRiskOrImpactClaim, true);
  assert.strictEqual(result.explicitNonClaims.noRawSensitiveDataIncluded, true);

  console.log('[+] No-difference comparison: completed, signalStrength=none, all flags safe.');
}

// ---------------------------------------------------------------------------
// 2. Status / content / body / header / json / redirect differences
// ---------------------------------------------------------------------------

async function testVariousDifferences() {
  console.log('[*] Testing status/content/body/header/json/redirect differences...');

  // Status code changed
  const statusReq = makeRequest({
    validation: makeValidationSnapshot({ statusCode: 403 })
  });
  const statusResult = compareResponses(statusReq, now.toISOString());
  assert.strictEqual(statusResult.status, 'completed');
  assert.strictEqual(statusResult.difference?.statusCodeChanged, true);
  assert.strictEqual(statusResult.difference?.baselineStatusCode, 200);
  assert.strictEqual(statusResult.difference?.validationStatusCode, 403);
  assert.ok(statusResult.difference?.signalSummary.includes('status_code_changed'));
  assert.ok(['moderate', 'strong'].includes(statusResult.significance!.comparisonSignalStrength));
  console.log('[+] Status code changed detected.');

  // Content length significant change
  const clReq = makeRequest({
    validation: makeValidationSnapshot({ contentLength: 2048 })
  });
  const clResult = compareResponses(clReq, now.toISOString());
  assert.strictEqual(clResult.difference?.contentLengthChanged, true);
  assert.strictEqual(clResult.difference?.contentLengthSignificant, true);
  assert.ok(clResult.difference?.signalSummary.includes('content_length_changed'));
  console.log('[+] Significant content length change detected.');

  // Body hash changed
  const bodyReq = makeRequest({
    validation: makeValidationSnapshot({ bodyHash: 'sha256-different789' })
  });
  const bodyResult = compareResponses(bodyReq, now.toISOString());
  assert.strictEqual(bodyResult.difference?.bodyHashChanged, true);
  assert.ok(bodyResult.difference?.signalSummary.includes('body_hash_changed'));
  console.log('[+] Body hash change detected.');

  // Header names added/removed
  const headerReq = makeRequest({
    baseline: makeSnapshot({ headerNames: ['content-type', 'x-old-header'] }),
    validation: makeValidationSnapshot({ headerNames: ['content-type', 'x-new-header'] })
  });
  const headerResult = compareResponses(headerReq, now.toISOString());
  assert.ok(headerResult.difference?.headerNamesAdded.includes('x-new-header'));
  assert.ok(headerResult.difference?.headerNamesRemoved.includes('x-old-header'));
  assert.ok(headerResult.difference?.signalSummary.includes('headers_changed'));
  console.log('[+] Header names added/removed detected.');

  // JSON keys added/removed
  const jsonReq = makeRequest({
    baseline: makeSnapshot({
      normalizedBodyShape: { shapeKind: 'json_object', topLevelJsonKeys: ['id', 'name'] }
    }),
    validation: makeValidationSnapshot({
      normalizedBodyShape: { shapeKind: 'json_object', topLevelJsonKeys: ['id', 'email'] }
    })
  });
  const jsonResult = compareResponses(jsonReq, now.toISOString());
  assert.ok(jsonResult.difference?.jsonKeysAdded.includes('email'));
  assert.ok(jsonResult.difference?.jsonKeysRemoved.includes('name'));
  assert.ok(jsonResult.difference?.signalSummary.includes('json_shape_changed'));
  console.log('[+] JSON keys added/removed detected.');

  // Redirect changed
  const redirectReq = makeRequest({
    baseline: makeSnapshot({ redirect: { redirected: false } }),
    validation: makeValidationSnapshot({ redirect: { redirected: true, locationOriginHash: 'hash-a1b2' } })
  });
  const redirectResult = compareResponses(redirectReq, now.toISOString());
  assert.strictEqual(redirectResult.difference?.redirectChanged, true);
  assert.ok(redirectResult.difference?.signalSummary.includes('redirect_changed'));
  console.log('[+] Redirect change detected.');

  console.log('[+] Status/content/body/header/json/redirect differences all pass.');
}

// ---------------------------------------------------------------------------
// 3. Auth difference -> authorization_difference hint
// ---------------------------------------------------------------------------

async function testAuthDifference() {
  console.log('[*] Testing auth difference -> authorization_difference hint...');

  // Mode: authorization_difference
  const authModeReq = makeRequest({
    comparisonMode: 'authorization_difference',
    baseline: makeSnapshot({ statusCode: 200 }),
    validation: makeValidationSnapshot({ statusCode: 200 })
  });
  const authModeResult = compareResponses(authModeReq, now.toISOString());
  assert.strictEqual(authModeResult.status, 'completed');
  assert.strictEqual(authModeResult.evidenceMappingHint?.suggestedEvidenceType, 'authorization_difference');
  assert.strictEqual(authModeResult.evidenceMappingHint?.requiresHumanReview, true);
  assert.strictEqual(authModeResult.evidenceMappingHint?.notPersistedEvidence, true);
  console.log('[+] authorization_difference mode -> hint is authorization_difference.');

  // Auth state changed -> auth_state_changed signal + authorization_difference hint
  const authStateReq = makeRequest({
    baseline: makeSnapshot({
      authState: { authenticatedSignal: 'appears_authenticated', authStateHash: 'hash-auth-1' }
    }),
    validation: makeValidationSnapshot({
      authState: { authenticatedSignal: 'appears_unauthenticated', authStateHash: 'hash-auth-2' }
    })
  });
  const authStateResult = compareResponses(authStateReq, now.toISOString());
  assert.strictEqual(authStateResult.difference?.authStateChanged, true);
  assert.ok(authStateResult.difference?.signalSummary.includes('auth_state_changed'));
  assert.strictEqual(authStateResult.significance?.comparisonSignalStrength, 'strong');
  assert.strictEqual(authStateResult.evidenceMappingHint?.suggestedEvidenceType, 'authorization_difference');
  console.log('[+] authStateChanged -> strong signal + authorization_difference hint.');

  // Status code across auth boundary (403 -> 200) -> strong signal
  const authBoundaryReq = makeRequest({
    baseline: makeSnapshot({ statusCode: 403 }),
    validation: makeValidationSnapshot({ statusCode: 200 })
  });
  const authBoundaryResult = compareResponses(authBoundaryReq, now.toISOString());
  assert.strictEqual(authBoundaryResult.significance?.comparisonSignalStrength, 'strong');
  assert.strictEqual(authBoundaryResult.significance?.strongestSignal, 'status_code');
  console.log('[+] 403->200 status boundary -> strong signal.');

  // No vulnerability claim in any case
  assert.strictEqual(authStateResult.explicitNonClaims.noConfirmedVulnerability, true);
  assert.strictEqual(authBoundaryResult.explicitNonClaims.noConfirmedVulnerability, true);
  console.log('[+] No vulnerability claims in auth difference results.');

  console.log('[+] Auth difference tests all pass.');
}

// ---------------------------------------------------------------------------
// 4. Time difference (mode-gated hint)
// ---------------------------------------------------------------------------

async function testTimeDifference() {
  console.log('[*] Testing time difference (mode-gated hint)...');

  // time_based_difference mode + responseTimeSignificant -> time_based_difference hint
  const timeReq = makeRequest({
    comparisonMode: 'time_based_difference',
    thresholds: { contentLengthDeltaPercentSignificant: 20, responseTimeDeltaMsSignificant: 200 },
    baseline: makeSnapshot({ responseTimeMs: 100 }),
    validation: makeValidationSnapshot({ responseTimeMs: 1500 })
  });
  const timeResult = compareResponses(timeReq, now.toISOString());
  assert.strictEqual(timeResult.status, 'completed');
  assert.strictEqual(timeResult.difference?.responseTimeSignificant, true);
  assert.ok(timeResult.difference?.signalSummary.includes('response_time_changed'));
  assert.strictEqual(timeResult.evidenceMappingHint?.suggestedEvidenceType, 'time_based_difference');
  assert.strictEqual(timeResult.evidenceMappingHint?.requiresHumanReview, true);
  console.log('[+] time_based_difference mode + responseTimeSignificant -> time_based_difference hint.');

  // http_difference mode + responseTimeSignificant -> http_difference hint (NOT time_based_difference)
  const httpTimeReq = makeRequest({
    comparisonMode: 'http_difference',
    thresholds: { contentLengthDeltaPercentSignificant: 20, responseTimeDeltaMsSignificant: 200 },
    baseline: makeSnapshot({ responseTimeMs: 100 }),
    validation: makeValidationSnapshot({ responseTimeMs: 1500 })
  });
  const httpTimeResult = compareResponses(httpTimeReq, now.toISOString());
  assert.strictEqual(httpTimeResult.difference?.responseTimeSignificant, true);
  assert.strictEqual(httpTimeResult.evidenceMappingHint?.suggestedEvidenceType, 'http_difference');
  console.log('[+] http_difference mode + responseTimeSignificant -> http_difference hint (not time_based).');

  // No SQLi implication, no vulnerability claim
  assert.strictEqual(timeResult.explicitNonClaims.noConfirmedVulnerability, true);
  assert.strictEqual(timeResult.explicitNonClaims.noSeverityRiskOrImpactClaim, true);
  // Rationale must not contain vulnerability/sqli claims
  const rationale = timeResult.significance!.rationale.toLowerCase();
  assert.ok(!rationale.includes('sql'), `Rationale must not imply SQLi: ${rationale}`);
  assert.ok(!rationale.includes('attack'), `Rationale must not use attack wording: ${rationale}`);
  assert.ok(!rationale.includes('vulnerable'), `Rationale must not use vulnerable: ${rationale}`);
  console.log('[+] No SQLi/attack/vulnerable claims in time difference rationale.');

  console.log('[+] Time difference tests all pass.');
}

// ---------------------------------------------------------------------------
// 5. Error signals (closed enum)
// ---------------------------------------------------------------------------

async function testErrorSignals() {
  console.log('[*] Testing error signals (closed enum)...');

  const errorReq = makeRequest({
    validation: makeValidationSnapshot({
      statusCode: 500,
      errorSignals: {
        hasSqlErrorSignal: true,
        hasStackTraceSignal: true,
        hasAuthErrorSignal: false,
        hasServerErrorSignal: true,
        signalNames: ['sql_error_like', 'stack_trace_like', 'server_error_like']
      }
    })
  });
  const errorResult = compareResponses(errorReq, now.toISOString());
  assert.strictEqual(errorResult.status, 'completed');
  assert.strictEqual(errorResult.difference?.errorSignalObserved, true);
  assert.ok(errorResult.difference?.signalSummary.includes('error_signal_observed'));
  assert.strictEqual(errorResult.significance?.strongestSignal, 'error_signal');
  assert.strictEqual(errorResult.significance?.comparisonSignalStrength, 'strong');
  console.log('[+] Error signals produce errorSignalObserved + strong signal.');

  // Verify signalSummary only contains closed enum values
  for (const item of errorResult.difference!.signalSummary) {
    const validItems = [
      'status_code_changed', 'content_length_changed', 'response_time_changed',
      'body_hash_changed', 'headers_changed', 'json_shape_changed',
      'redirect_changed', 'auth_state_changed', 'error_signal_observed'
    ];
    assert.ok(validItems.includes(item), `Invalid signal summary item: ${item}`);
  }
  console.log('[+] signalSummary contains only closed enum values.');

  // Invalid signal name in errorSignals must be rejected
  const invalidSignalSnapshot = makeSnapshot({
    errorSignals: {
      hasSqlErrorSignal: false,
      hasStackTraceSignal: false,
      hasAuthErrorSignal: false,
      hasServerErrorSignal: false,
      signalNames: ['some_unknown_signal']
    }
  });
  const invalidSignalVal = validateSafeResponseSnapshot(invalidSignalSnapshot);
  assert.strictEqual(invalidSignalVal.isValid, false);
  console.log('[+] Unknown signal name rejected.');

  // No raw error text or stack trace text in result
  const serialized = JSON.stringify(errorResult);
  assert.ok(!serialized.includes('stack trace'), 'No raw stack trace text in result');
  assert.ok(!serialized.includes('Error:'), 'No raw error prefix in result');
  console.log('[+] No raw error/stack text in result.');

  console.log('[+] Error signals tests all pass.');
}

// ---------------------------------------------------------------------------
// 6. Invalid snapshots / request validation
// ---------------------------------------------------------------------------

async function testInvalidInputs() {
  console.log('[*] Testing invalid snapshots / request validation...');

  // Wrong contractVersion
  assert.strictEqual(
    validateSafeResponseSnapshot({ ...makeSnapshot(), contractVersion: 'wrong/v999' }).isValid, false
  );
  // Wrong kind
  assert.strictEqual(
    validateSafeResponseSnapshot({ ...makeSnapshot(), kind: 'other_kind' }).isValid, false
  );
  // Classification flag true
  assert.strictEqual(
    validateSafeResponseSnapshot({ ...makeSnapshot(), classification: { ...getSafeClassification(), createsRealFindings: true } }).isValid, false
  );
  // Baseline role wrong (validation as baseline)
  const roleResult = compareResponses(
    makeRequest({ baseline: makeSnapshot({ role: 'validation' }) }),
    now.toISOString()
  );
  assert.strictEqual(roleResult.status, 'failed');
  assert.strictEqual(roleResult.error?.code, 'snapshot_role_mismatch');
  console.log('[+] Wrong baseline role rejected.');

  // Validation role wrong
  const roleResult2 = compareResponses(
    makeRequest({ validation: makeValidationSnapshot({ role: 'baseline' }) }),
    now.toISOString()
  );
  assert.strictEqual(roleResult2.status, 'failed');
  assert.strictEqual(roleResult2.error?.code, 'snapshot_role_mismatch');
  console.log('[+] Wrong validation role rejected.');

  // Scan mismatch
  const scanMismatch = compareResponses(
    makeRequest({ baseline: makeSnapshot({ scanId: 'scan-OTHER' }) }),
    now.toISOString()
  );
  assert.strictEqual(scanMismatch.status, 'failed');
  assert.strictEqual(scanMismatch.error?.code, 'scan_mismatch');
  console.log('[+] Scan mismatch rejected.');

  // Subject mismatch
  const subjectMismatch = compareResponses(
    makeRequest({
      baseline: makeSnapshot({ subject: makeSubject({ pathTemplate: '/api/v1/resource' }) }),
      validation: makeValidationSnapshot({ subject: makeSubject({ pathTemplate: '/api/v2/different' }) })
    }),
    now.toISOString()
  );
  assert.strictEqual(subjectMismatch.status, 'failed');
  assert.strictEqual(subjectMismatch.error?.code, 'subject_mismatch');
  console.log('[+] Subject mismatch rejected.');

  // Empty subject invalid
  assert.strictEqual(
    validateSafeResponseSnapshot({ ...makeSnapshot(), subject: {} }).isValid, false
  );
  console.log('[+] Empty subject rejected.');

  // Subject with only normalizedOrigin (no method/pathTemplate/routeId) invalid
  assert.strictEqual(
    validateSafeResponseSnapshot({ ...makeSnapshot(), subject: { normalizedOrigin: 'https://example.com' } }).isValid, false
  );
  console.log('[+] Subject with only normalizedOrigin (missing method+pathTemplate) rejected.');

  // Subject with routeId only -> valid
  assert.strictEqual(
    validateSafeResponseSnapshot({ ...makeSnapshot(), subject: { routeId: 'route-abc-1' } }).isValid, true
  );
  console.log('[+] Subject with only routeId is valid.');

  // Subject with normalizedOrigin + method + pathTemplate -> valid
  assert.strictEqual(
    validateSafeResponseSnapshot({ ...makeSnapshot(), subject: makeSubject() }).isValid, true
  );
  console.log('[+] Subject with normalizedOrigin + method + pathTemplate is valid.');

  // invalid comparedAt (and requestedAt/capturedAt) non-strict ISO
  const BAD_TIMESTAMPS = [
    "July 7, 2026",
    "2026-07-07",
    "2026-07-07T00:00:00Z", // strict requires ms
    "not-a-date"
  ];
  for (const ts of BAD_TIMESTAMPS) {
    assert.strictEqual(validateSafeResponseSnapshot({ ...makeSnapshot(), capturedAt: ts }).isValid, false);
    assert.strictEqual(validateResponseComparisonRequest({ ...makeRequest(), requestedAt: ts }).isValid, false);
    
    // comparedAt
    const cmpRes = compareResponses(makeRequest(), ts);
    assert.strictEqual(cmpRes.status, 'failed');
    assert.strictEqual(cmpRes.comparedAt, '1970-01-01T00:00:00.000Z');
  }
  console.log('[+] Invalid non-ISO timestamps rejected.');

  // Unsafe safeExcerpt
  assert.strictEqual(
    validateSafeResponseSnapshot({
      ...makeSnapshot(),
      safeExcerpt: { text: 'Authorization: Bearer secrettoken', source: 'sanitized_body_excerpt', redacted: true }
    }).isValid, false
  );
  console.log('[+] Unsafe safeExcerpt content rejected.');

  // safeExcerpt without redacted: true rejected
  assert.strictEqual(
    validateSafeResponseSnapshot({
      ...makeSnapshot(),
      safeExcerpt: { text: 'safe text here', source: 'sanitized_body_excerpt', redacted: false }
    }).isValid, false
  );
  console.log('[+] safeExcerpt without redacted:true rejected.');

  // Unsafe header names (string type checked above, now check shape and specific blacklisted words)
  const BAD_HEADERS = [
    "x-test: value",
    "Content-Type: text/html",
    "x test",
    "Bearer abc",
    "x-test\r\nx-evil",
    "Authorization",
    "authorization",
    "Cookie",
    "Set-Cookie",
    "Proxy-Authorization",
    "X-Api-Key"
  ];
  for (const h of BAD_HEADERS) {
    assert.strictEqual(
      validateSafeResponseSnapshot({ ...makeSnapshot(), headerNames: [h] }).isValid, false,
      `Header ${h} should be invalid`
    );
  }
  
  // ensure we can't get completed with a bad header
  const headerReq = makeRequest({ validation: makeValidationSnapshot({ headerNames: ['x-test: value'] }) });
  const badHeaderRes = compareResponses(headerReq, now.toISOString());
  assert.strictEqual(badHeaderRes.status, 'failed');
  assert.ok(!badHeaderRes.difference?.headerNamesAdded?.includes("x-test: value"), "Should not emit bad header");
  console.log('[+] Sensitive and malformed header names rejected.');

  // Unsafe json key
  assert.strictEqual(
    validateSafeResponseSnapshot({
      ...makeSnapshot(),
      normalizedBodyShape: { shapeKind: 'json_object', topLevelJsonKeys: ['secret_token_123'] }
    }).isValid, false
  );
  console.log('[+] Unsafe json key rejected.');

  // Unsafe pathTemplate
  assert.strictEqual(
    validateSafeResponseSnapshot({
      ...makeSnapshot(),
      subject: makeSubject({ pathTemplate: '/api?token=secret' })
    }).isValid, false
  );
  console.log('[+] Unsafe pathTemplate with query rejected.');

  // Array as string instead of real array
  assert.strictEqual(
    validateSafeResponseSnapshot({ ...makeSnapshot(), headerNames: 'content-type' as any }).isValid, false
  );
  console.log('[+] headerNames as string rejected.');

  // Unknown fields
  assert.strictEqual(
    validateSafeResponseSnapshot({ ...makeSnapshot(), rawBodyContent: 'some content' }).isValid, false
  );
  assert.strictEqual(
    validateResponseComparisonRequest({ ...makeRequest(), severity: 'high' }).isValid, false
  );
  console.log('[+] Unknown fields rejected.');

  // statusCode out of range
  assert.strictEqual(
    validateSafeResponseSnapshot({ ...makeSnapshot(), statusCode: 99 }).isValid, false
  );
  assert.strictEqual(
    validateSafeResponseSnapshot({ ...makeSnapshot(), statusCode: 600 }).isValid, false
  );
  console.log('[+] Invalid statusCode rejected.');

  // Forbidden content in hashes
  const BAD_HASH_FIELDS = [
    { field: 'bodyHash', val: 'secret_token', updateBase: (s: any) => ({ ...s, bodyHash: 'secret_token' }) },
    { field: 'normalizedSchemaHash', val: 'secret_token', updateBase: (s: any) => ({ ...s, normalizedBodyShape: { shapeKind: 'json_object', normalizedSchemaHash: 'secret_token' } }) },
    { field: 'locationOriginHash', val: 'secret_token', updateBase: (s: any) => ({ ...s, redirect: { redirected: true, locationOriginHash: 'secret_token' } }) },
    { field: 'authStateHash', val: 'secret_token', updateBase: (s: any) => ({ ...s, authState: { authenticatedSignal: 'appears_authenticated', authStateHash: 'secret_token' } }) }
  ];
  
  for (const { updateBase } of BAD_HASH_FIELDS) {
    const badSnap = updateBase(makeSnapshot());
    assert.strictEqual(validateSafeResponseSnapshot(badSnap).isValid, false);
    
    const cmpRes = compareResponses(makeRequest({ baseline: badSnap }), now.toISOString());
    assert.strictEqual(cmpRes.status, 'failed');
  }
  console.log('[+] Forbidden content in safeHash fields rejected.');

  console.log('[+] Invalid inputs tests all pass.');
}

// ---------------------------------------------------------------------------
// 7. Safe sentinels / no raw metadata echo
// ---------------------------------------------------------------------------

async function testSafeSentinels() {
  console.log('[*] Testing safe sentinels / no raw metadata echo...');

  const FORBIDDEN_TERMS = [
    'secret', 'token', 'authorization', 'bearer', 'cookie', 'password',
    'not-a-date',
    'cmp_secret_token',
    'snap_secret_token',
    'scan_secret_token'
  ];

  function assertNoForbiddenTerms(result: any, label: string) {
    const serialized = JSON.stringify(result).toLowerCase();
    for (const term of FORBIDDEN_TERMS) {
      if (serialized.includes(term.toLowerCase())) {
        assert.fail(`Forbidden term "${term}" found in result for: ${label}`);
      }
    }
  }

  // comparisonId with secret_token
  const secretCmpResult = compareResponses(
    { ...makeRequest(), comparisonId: 'cmp_secret_token' },
    now.toISOString()
  );
  assert.strictEqual(secretCmpResult.status, 'failed');
  assert.strictEqual(secretCmpResult.comparisonId, 'invalid_comparison_id');
  assertNoForbiddenTerms(secretCmpResult, 'comparisonId with secret_token');
  console.log('[+] comparisonId with secret_token uses sentinel, not echoed.');

  // baselineSnapshotId with secret_token
  const secretSnapReq = makeRequest({ baseline: makeSnapshot({ snapshotId: 'snap_secret_token' }) });
  const secretSnapResult = compareResponses(secretSnapReq, now.toISOString());
  assert.strictEqual(secretSnapResult.status, 'failed');
  assert.ok(secretSnapResult.baselineSnapshotId !== 'snap_secret_token', 'Raw snapshotId must not be echoed');
  assertNoForbiddenTerms(secretSnapResult, 'baselineSnapshotId with secret_token');
  console.log('[+] baselineSnapshotId with secret_token uses sentinel, not echoed.');

  // validationSnapshotId with secret_token
  const secretValReq = makeRequest({ validation: makeValidationSnapshot({ snapshotId: 'snap_secret_token' }) });
  const secretValResult = compareResponses(secretValReq, now.toISOString());
  assert.strictEqual(secretValResult.status, 'failed');
  assert.ok(secretValResult.validationSnapshotId !== 'snap_secret_token');
  assertNoForbiddenTerms(secretValResult, 'validationSnapshotId with secret_token');
  console.log('[+] validationSnapshotId with secret_token uses sentinel, not echoed.');

  // scanId with secret_token
  const secretScanReq = { ...makeRequest(), scanId: 'scan_secret_token' };
  const secretScanResult = compareResponses(secretScanReq, now.toISOString());
  assert.strictEqual(secretScanResult.status, 'failed');
  assert.ok(secretScanResult.scanId !== 'scan_secret_token', 'Raw scanId must not be echoed');
  assertNoForbiddenTerms(secretScanResult, 'scanId with secret_token');
  console.log('[+] scanId with secret_token uses sentinel, not echoed.');

  // invalid comparedAt
  const badAtResult = compareResponses(makeRequest(), 'not-a-date');
  assert.strictEqual(badAtResult.status, 'failed');
  assert.strictEqual(badAtResult.comparedAt, '1970-01-01T00:00:00.000Z');
  const badAtSerialized = JSON.stringify(badAtResult);
  assert.ok(!badAtSerialized.includes('not-a-date'), 'not-a-date must not be echoed');
  console.log('[+] Invalid comparedAt uses epoch sentinel, not echoed.');

  // Non-regression: valid metadata passes through
  const cleanResult = compareResponses(makeRequest(), now.toISOString());
  assert.strictEqual(cleanResult.status, 'completed');
  assert.strictEqual(cleanResult.comparisonId, 'cmp-001');
  assert.strictEqual(cleanResult.baselineSnapshotId, 'snap-baseline-1');
  console.log('[+] Valid metadata passes through correctly (non-regression).');

  console.log('[+] Safe sentinels tests all pass.');
}

// ---------------------------------------------------------------------------
// 8. No raw leaks in text fields
// ---------------------------------------------------------------------------

async function testNoRawLeaks() {
  console.log('[*] Testing no raw leaks in text fields...');

  const FORBIDDEN_VALUES = [
    'Authorization: Bearer abc',
    'Cookie: session=abc',
    'secret_token_123',
    'raw_body_content',
    'raw_headers_content',
    'stack trace',
    'confirmed vulnerability',
    'target is vulnerable',
    'critical severity'
  ];

  // Build a valid completed result
  const result = compareResponses(makeRequest(), now.toISOString());
  assert.strictEqual(result.status, 'completed');

  // Check text fields only (not field names like noSeverityRiskOrImpactClaim)
  const textFields = [
    result.significance?.rationale ?? '',
    ...(result.difference?.signalSummary ?? []),
    ...(result.difference?.headerNamesAdded ?? []),
    ...(result.difference?.headerNamesRemoved ?? []),
    ...(result.difference?.jsonKeysAdded ?? []),
    ...(result.difference?.jsonKeysRemoved ?? []),
    result.error?.safeMessage ?? ''
  ];

  for (const field of textFields) {
    const lower = field.toLowerCase();
    for (const forbidden of FORBIDDEN_VALUES) {
      if (lower.includes(forbidden.toLowerCase())) {
        assert.fail(`Forbidden value "${forbidden}" found in text field: "${field}"`);
      }
    }
  }
  console.log('[+] No forbidden values in text output fields.');

  // Verify executesNetwork/executesTools/persistsData are false at the type level
  assert.strictEqual(result.classification.executesNetwork, false);
  assert.strictEqual(result.classification.executesTools, false);
  assert.strictEqual(result.classification.persistsData, false);
  console.log('[+] No raw leaks in result text fields. All pass.');
}

// ---------------------------------------------------------------------------
// 9. No execution invariant
// ---------------------------------------------------------------------------

async function testNoExecution() {
  console.log('[*] Testing no-execution invariant...');

  const result = compareResponses(makeRequest(), now.toISOString());

  assert.strictEqual(result.classification.executesNetwork, false);
  assert.strictEqual(result.classification.executesTools, false);
  assert.strictEqual(result.classification.persistsData, false);
  assert.strictEqual(result.classification.createsRealFindings, false);
  assert.strictEqual(result.classification.createsPersistedEvidence, false);
  assert.strictEqual(result.classification.confirmsVulnerabilities, false);

  // Verify evidenceMappingHint is not an EvidenceRecord
  assert.strictEqual(result.evidenceMappingHint?.requiresHumanReview, true);
  assert.strictEqual(result.evidenceMappingHint?.notPersistedEvidence, true);

  console.log('[+] No-execution invariant verified. All classification flags are false.');
}

// ---------------------------------------------------------------------------
// 10. Significance and hint derivation unit tests
// ---------------------------------------------------------------------------

async function testDerivationHelpers() {
  console.log('[*] Testing derivation helpers directly...');

  // Build a diff with auth state changed
  const base = makeSnapshot({
    authState: { authenticatedSignal: 'appears_authenticated', authStateHash: 'h1' }
  }) as any;
  const val = makeValidationSnapshot({
    authState: { authenticatedSignal: 'appears_unauthenticated', authStateHash: 'h2' }
  }) as any;

  const thresholds = { contentLengthDeltaPercentSignificant: 20, responseTimeDeltaMsSignificant: 500 };
  const diff = buildResponseDifference(base, val, thresholds);
  assert.strictEqual(diff.authStateChanged, true);

  const sig = deriveComparisonSignificance(diff, 'authorization_difference');
  assert.strictEqual(sig.comparisonSignalStrength, 'strong');
  assert.strictEqual(sig.strongestSignal, 'auth_state');

  const hint = deriveEvidenceMappingHint(diff, sig, 'authorization_difference');
  assert.strictEqual(hint.suggestedEvidenceType, 'authorization_difference');
  assert.strictEqual(hint.requiresHumanReview, true);
  assert.strictEqual(hint.notPersistedEvidence, true);

  // Verify suggestedSignalStrength
  assert.ok(['weak', 'moderate', 'strong'].includes(hint.suggestedSignalStrength));
  assert.strictEqual(hint.suggestedSignalStrength, 'strong');

  console.log('[+] Derivation helpers work correctly.');
}

// ---------------------------------------------------------------------------
// Run all tests
// ---------------------------------------------------------------------------

async function runTests() {
  console.log('--- V2 M47 Response Comparator DB-Free Smoke Test ---');

  await testNoDifference();
  await testVariousDifferences();
  await testAuthDifference();
  await testTimeDifference();
  await testErrorSignals();
  await testInvalidInputs();
  await testSafeSentinels();
  await testNoRawLeaks();
  await testNoExecution();
  await testDerivationHelpers();

  console.log('--- M47 Response Comparator DB-Free Smoke Completed Successfully ---');
}

runTests().catch(err => {
  console.error(err);
  process.exit(1);
});
