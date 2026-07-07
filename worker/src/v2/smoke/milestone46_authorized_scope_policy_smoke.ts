import assert from 'node:assert';
import process from 'node:process';
import type {
  AuthorizedScopeGrant,
  ScopeActionRequest,
  PermissionSet,
  ScopeBoundaries,
  ScopeConstraints
} from '../scope/AuthorizedScopeContracts.js';
import {
  validateAuthorizedScopeGrant,
  validateScopeActionRequest,
  deriveRequiredPermissionForAction,
  evaluateScopePolicy,
  getSafeClassification
} from '../scope/AuthorizedScopePolicyService.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const baseClassification = getSafeClassification();

const now = new Date();
const future = new Date(now.getTime() + 86400_000).toISOString();
const past = new Date(now.getTime() - 86400_000).toISOString();

function makeGrant(overrides: any = {}): any {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant-1',
    scanId: 'scan-1',
    issuedAt: past,
    expiresAt: future,
    subject: { targetKind: 'origin', normalizedOrigin: 'https://example.com' },
    authorizationBasis: {
      basisKind: 'user_attestation',
      recordedBy: 'human_user',
      authorizationText: 'Authorized by security team lead for assessment.'
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: false,
      authenticatedTesting: false,
      lightValidation: false,
      activeValidation: false,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false
    },
    boundaries: {
      allowedOrigins: ['https://example.com'],
      allowedMethods: ['GET', 'HEAD']
    },
    constraints: {
      allowLoginRequiredAreas: false,
      allowStateChangingRequests: false,
      allowCredentialUse: false,
      allowOobCallbacks: false,
      allowThirdPartyTargets: false
    },
    classification: baseClassification,
    ...overrides
  };
}

function makeRequest(overrides: any = {}): any {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'scope_action_request',
    requestId: 'req-1',
    scanId: 'scan-1',
    requestedAt: now.toISOString(),
    actionKind: 'passive_recon',
    target: { targetKind: 'origin', normalizedOrigin: 'https://example.com' },
    method: 'GET',
    pathTemplate: '/api/v1/users',
    intensity: 'passive',
    usesCredentials: false,
    mayChangeServerState: false,
    usesOob: false,
    classification: baseClassification,
    ...overrides
  };
}

// ---------------------------------------------------------------------------
// 1. Valid grant + allowed actions
// ---------------------------------------------------------------------------

async function testAllowedActions() {
  console.log('[*] Testing valid grant + allowed actions...');

  const grant = makeGrant();

  const passiveDecision = evaluateScopePolicy({ grant, request: makeRequest({ actionKind: 'passive_recon' }), decisionId: 'dec-1', evaluatedAt: now.toISOString() });
  assert.strictEqual(passiveDecision.decision, 'allowed', 'passive_recon should be allowed');
  assert.strictEqual(passiveDecision.reasonCode, 'allowed_by_scope_policy');
  assert.strictEqual(passiveDecision.matchedPermission, 'passiveRecon');

  const fingerprint = evaluateScopePolicy({ grant, request: makeRequest({ actionKind: 'technology_fingerprint' }), decisionId: 'dec-2', evaluatedAt: now.toISOString() });
  assert.strictEqual(fingerprint.decision, 'allowed', 'technology_fingerprint should be allowed');

  const endpointDisc = evaluateScopePolicy({ grant, request: makeRequest({ actionKind: 'endpoint_discovery' }), decisionId: 'dec-3', evaluatedAt: now.toISOString() });
  assert.strictEqual(endpointDisc.decision, 'allowed', 'endpoint_discovery should be allowed');

  // Verify no execution flags in decision
  assert.strictEqual(passiveDecision.classification.executesNetwork, false);
  assert.strictEqual(passiveDecision.classification.executesTools, false);
  assert.strictEqual(passiveDecision.classification.persistsData, false);

  console.log('[+] Valid grant + allowed actions pass.');
}

// ---------------------------------------------------------------------------
// 2. No trusting requiredPermission (bypass prevention)
// ---------------------------------------------------------------------------

async function testRequiredPermissionBypassPrevention() {
  console.log('[*] Testing requiredPermission bypass prevention...');

  // Bypass attempt: aggressive_validation with fake requiredPermission: "passiveRecon"
  const bypassGrant = makeGrant({
    permissionSet: { ...makeGrant().permissionSet, passiveRecon: true, aggressiveValidation: false }
  });
  const bypassReq = makeRequest({
    actionKind: 'aggressive_validation',
    intensity: 'aggressive',
    requiredPermission: 'passiveRecon' // attacker lies
  });
  const bypassDecision = evaluateScopePolicy({ grant: bypassGrant, request: bypassReq, decisionId: 'dec-bp', evaluatedAt: now.toISOString() });
  assert.strictEqual(bypassDecision.decision, 'denied', 'Bypass attempt should be denied');
  assert.strictEqual(bypassDecision.reasonCode, 'denied_invalid_request', 'Bypass should result in denied_invalid_request (mismatch)');
  console.log('[+] Bypass attempt denied_invalid_request.');

  // Correct matching: aggressive_validation with matching requiredPermission passes to permission check
  const aggGrant = makeGrant({
    permissionSet: { ...makeGrant().permissionSet, aggressiveValidation: true }
  });
  const aggReq = makeRequest({
    actionKind: 'aggressive_validation',
    intensity: 'aggressive',
    requiredPermission: 'aggressiveValidation' // correct match
  });
  const aggDecision = evaluateScopePolicy({ grant: aggGrant, request: aggReq, decisionId: 'dec-agg', evaluatedAt: now.toISOString() });
  // Should be allowed (no state-changing, no oob, no credentials, GET)
  assert.strictEqual(aggDecision.decision, 'allowed', 'Matching requiredPermission with aggressive_validation should be allowed');
  assert.strictEqual(aggDecision.matchedPermission, 'aggressiveValidation');
  console.log('[+] Correct requiredPermission passes through to permission check.');

  // No requiredPermission: service derives it automatically
  const autoReq = makeRequest({ actionKind: 'passive_recon', intensity: 'passive' });
  const autoDecision = evaluateScopePolicy({ grant: makeGrant(), request: autoReq, decisionId: 'dec-auto', evaluatedAt: now.toISOString() });
  assert.strictEqual(autoDecision.decision, 'allowed');
  assert.strictEqual(autoDecision.matchedPermission, 'passiveRecon');
  console.log('[+] Service derives permission without requiredPermission hint.');
}

// ---------------------------------------------------------------------------
// 3. Denied permission
// ---------------------------------------------------------------------------

async function testDeniedPermission() {
  console.log('[*] Testing denied missing permissions...');

  const grant = makeGrant(); // only passiveRecon, technologyFingerprinting, endpointDiscovery

  const crawl = evaluateScopePolicy({ grant, request: makeRequest({ actionKind: 'active_crawl', intensity: 'low' }), decisionId: 'dec-c', evaluatedAt: now.toISOString() });
  assert.strictEqual(crawl.decision, 'denied');
  assert.strictEqual(crawl.reasonCode, 'denied_missing_permission');

  const activeVal = evaluateScopePolicy({ grant, request: makeRequest({ actionKind: 'active_validation', intensity: 'medium' }), decisionId: 'dec-av', evaluatedAt: now.toISOString() });
  assert.strictEqual(activeVal.decision, 'denied');
  assert.strictEqual(activeVal.reasonCode, 'denied_missing_permission');

  const aggressiveVal = evaluateScopePolicy({ grant, request: makeRequest({ actionKind: 'aggressive_validation', intensity: 'aggressive' }), decisionId: 'dec-agv', evaluatedAt: now.toISOString() });
  assert.strictEqual(aggressiveVal.decision, 'denied');
  assert.strictEqual(aggressiveVal.reasonCode, 'denied_missing_permission');

  const oobVal = evaluateScopePolicy({ grant, request: makeRequest({ actionKind: 'oob_validation', usesOob: true }), decisionId: 'dec-oob', evaluatedAt: now.toISOString() });
  assert.strictEqual(oobVal.decision, 'denied');
  // oob first hits denied_requires_oob_permission (step 12) before missing_permission (step 14)
  assert.ok(
    oobVal.reasonCode === 'denied_requires_oob_permission' || oobVal.reasonCode === 'denied_missing_permission',
    `Expected oob denied reason, got: ${oobVal.reasonCode}`
  );
  console.log('[+] Missing permissions correctly denied.');
}

// ---------------------------------------------------------------------------
// 4. Destructive always denied
// ---------------------------------------------------------------------------

async function testDestructiveAlwaysDenied() {
  console.log('[*] Testing destructive operations always denied...');

  const grant = makeGrant();

  const destOp = evaluateScopePolicy({ grant, request: makeRequest({ actionKind: 'destructive_operation' }), decisionId: 'dec-dest', evaluatedAt: now.toISOString() });
  assert.strictEqual(destOp.decision, 'denied');
  assert.strictEqual(destOp.reasonCode, 'denied_destructive_operation');

  const destIntensity = evaluateScopePolicy({ grant, request: makeRequest({ intensity: 'destructive' }), decisionId: 'dec-di', evaluatedAt: now.toISOString() });
  assert.strictEqual(destIntensity.decision, 'denied');
  assert.strictEqual(destIntensity.reasonCode, 'denied_destructive_operation');

  // Grant with destructiveOperations: true should be invalid (grant validation fails)
  const badGrant = makeGrant({ permissionSet: { ...makeGrant().permissionSet, destructiveOperations: true } });
  const badGrantVal = validateAuthorizedScopeGrant(badGrant);
  assert.strictEqual(badGrantVal.isValid, false, 'Grant with destructiveOperations: true should be invalid');

  // Raw cast bypass attempt
  const rawCastGrant = makeGrant({ permissionSet: { ...makeGrant().permissionSet, destructiveOperations: 'true' as any } });
  const rawCastVal = validateAuthorizedScopeGrant(rawCastGrant);
  assert.strictEqual(rawCastVal.isValid, false, 'Grant with destructiveOperations: "true" (string) should be invalid');

  console.log('[+] Destructive operations always denied.');
}

// ---------------------------------------------------------------------------
// 5. Auth and credentials
// ---------------------------------------------------------------------------

async function testAuthAndCredentials() {
  console.log('[*] Testing auth and credentials...');

  const grant = makeGrant(); // authenticatedTesting: false

  // usesCredentials without authenticatedTesting
  const credReq = makeRequest({ actionKind: 'authenticated_probe', intensity: 'low', usesCredentials: true });
  const credDenied = evaluateScopePolicy({ grant, request: credReq, decisionId: 'dec-cred', evaluatedAt: now.toISOString() });
  assert.strictEqual(credDenied.decision, 'denied');
  assert.strictEqual(credDenied.reasonCode, 'denied_requires_authenticated_testing');

  // Grant with allowCredentialUse: true but authenticatedTesting: false -> invalid grant
  const badCredGrant = makeGrant({
    constraints: { ...makeGrant().constraints, allowCredentialUse: true }
  });
  const badCredVal = validateAuthorizedScopeGrant(badCredGrant);
  assert.strictEqual(badCredVal.isValid, false, 'allowCredentialUse:true without authenticatedTesting should fail');

  // Valid: authenticatedTesting + allowCredentialUse both true
  const authGrant = makeGrant({
    permissionSet: { ...makeGrant().permissionSet, authenticatedTesting: true },
    constraints: { ...makeGrant().constraints, allowCredentialUse: true }
  });
  assert.strictEqual(validateAuthorizedScopeGrant(authGrant).isValid, true, 'Valid auth grant should pass');

  const authReq = makeRequest({ actionKind: 'authenticated_probe', intensity: 'low', usesCredentials: true, method: 'GET' });
  const authAllowed = evaluateScopePolicy({ grant: authGrant, request: authReq, decisionId: 'dec-auth', evaluatedAt: now.toISOString() });
  assert.strictEqual(authAllowed.decision, 'allowed');
  assert.strictEqual(authAllowed.matchedPermission, 'authenticatedTesting');

  console.log('[+] Auth and credentials work correctly.');
}

// ---------------------------------------------------------------------------
// 6. OOB
// ---------------------------------------------------------------------------

async function testOob() {
  console.log('[*] Testing OOB...');

  const grant = makeGrant(); // oobTesting: false

  const oobReq = makeRequest({ actionKind: 'oob_validation', usesOob: true });
  const oobDenied = evaluateScopePolicy({ grant, request: oobReq, decisionId: 'dec-oob', evaluatedAt: now.toISOString() });
  assert.strictEqual(oobDenied.decision, 'denied');
  assert.ok(oobDenied.reasonCode === 'denied_requires_oob_permission' || oobDenied.reasonCode === 'denied_missing_permission');

  // oobTesting true but allowOobCallbacks false
  const oobGrantNoCallback = makeGrant({ permissionSet: { ...makeGrant().permissionSet, oobTesting: true } });
  const oobNoCallbackDecision = evaluateScopePolicy({ grant: oobGrantNoCallback, request: oobReq, decisionId: 'dec-oob2', evaluatedAt: now.toISOString() });
  assert.strictEqual(oobNoCallbackDecision.decision, 'denied');
  assert.strictEqual(oobNoCallbackDecision.reasonCode, 'denied_requires_oob_permission');

  // oobTesting true + allowOobCallbacks true
  const oobGrantFull = makeGrant({
    permissionSet: { ...makeGrant().permissionSet, oobTesting: true },
    constraints: { ...makeGrant().constraints, allowOobCallbacks: true }
  });
  const oobAllowed = evaluateScopePolicy({ grant: oobGrantFull, request: oobReq, decisionId: 'dec-oob3', evaluatedAt: now.toISOString() });
  assert.strictEqual(oobAllowed.decision, 'allowed');
  assert.strictEqual(oobAllowed.matchedPermission, 'oobTesting');

  console.log('[+] OOB requirements work correctly.');
}

// ---------------------------------------------------------------------------
// 7. State change
// ---------------------------------------------------------------------------

async function testStateChange() {
  console.log('[*] Testing state-changing restrictions...');

  const grant = makeGrant({ boundaries: { allowedOrigins: ['https://example.com'] } }); // allowStateChangingRequests: false, no allowedMethods

  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE'] as const) {
    const req = makeRequest({ method, actionKind: 'passive_recon' });
    const decision = evaluateScopePolicy({ grant, request: req, decisionId: `dec-sc-${method}`, evaluatedAt: now.toISOString() });
    assert.strictEqual(decision.decision, 'denied', `${method} should be denied`);
    assert.strictEqual(decision.reasonCode, 'denied_state_change_not_allowed', `${method} should give denied_state_change_not_allowed`);
  }

  // mayChangeServerState: true also triggers it
  const mayChange = makeRequest({ mayChangeServerState: true });
  const mayDecision = evaluateScopePolicy({ grant, request: mayChange, decisionId: 'dec-may', evaluatedAt: now.toISOString() });
  assert.strictEqual(mayDecision.decision, 'denied');
  assert.strictEqual(mayDecision.reasonCode, 'denied_state_change_not_allowed');

  console.log('[+] State-changing restrictions work correctly.');
}

// ---------------------------------------------------------------------------
// 8. Scope boundaries
// ---------------------------------------------------------------------------

async function testScopeBoundaries() {
  console.log('[*] Testing scope boundaries...');

  // target origin outside allowedOrigins
  const grant = makeGrant();
  const outOfScopeReq = makeRequest({ target: { targetKind: 'origin', normalizedOrigin: 'https://evil.com' } });
  const outOfScope = evaluateScopePolicy({ grant, request: outOfScopeReq, decisionId: 'dec-oos', evaluatedAt: now.toISOString() });
  assert.strictEqual(outOfScope.decision, 'denied');
  assert.strictEqual(outOfScope.reasonCode, 'denied_target_out_of_scope');

  // Path patterns: denied wins over allowed
  const pathGrant = makeGrant({
    boundaries: {
      allowedOrigins: ['https://example.com'],
      allowedPathPatterns: [{ match: 'prefix', pathTemplate: '/api' }],
      deniedPathPatterns: [{ match: 'exact', pathTemplate: '/api/admin' }]
    }
  });
  const apiReq = makeRequest({ pathTemplate: '/api/users' });
  const apiAllowed = evaluateScopePolicy({ grant: pathGrant, request: apiReq, decisionId: 'dec-api', evaluatedAt: now.toISOString() });
  assert.strictEqual(apiAllowed.decision, 'allowed');

  const adminReq = makeRequest({ pathTemplate: '/api/admin' });
  const adminDenied = evaluateScopePolicy({ grant: pathGrant, request: adminReq, decisionId: 'dec-admin', evaluatedAt: now.toISOString() });
  assert.strictEqual(adminDenied.decision, 'denied');
  assert.strictEqual(adminDenied.reasonCode, 'denied_path_explicitly_denied');

  // Out of allowedPathPatterns
  const healthReq = makeRequest({ pathTemplate: '/health' });
  const healthDenied = evaluateScopePolicy({ grant: pathGrant, request: healthReq, decisionId: 'dec-health', evaluatedAt: now.toISOString() });
  assert.strictEqual(healthDenied.decision, 'denied');
  assert.strictEqual(healthDenied.reasonCode, 'denied_path_out_of_scope');

  // Exact path matching
  const exactGrant = makeGrant({
    boundaries: {
      allowedOrigins: ['https://example.com'],
      allowedPathPatterns: [{ match: 'exact', pathTemplate: '/api/v1' }]
    }
  });
  const exactMatch = makeRequest({ pathTemplate: '/api/v1' });
  assert.strictEqual(evaluateScopePolicy({ grant: exactGrant, request: exactMatch, decisionId: 'd1', evaluatedAt: now.toISOString() }).decision, 'allowed');
  const noExact = makeRequest({ pathTemplate: '/api/v1/users' });
  assert.strictEqual(evaluateScopePolicy({ grant: exactGrant, request: noExact, decisionId: 'd2', evaluatedAt: now.toISOString() }).decision, 'denied');

  // Prefix: /api should NOT match /apiary
  const prefixGrant = makeGrant({
    boundaries: {
      allowedOrigins: ['https://example.com'],
      allowedPathPatterns: [{ match: 'prefix', pathTemplate: '/api' }]
    }
  });
  const apiaryReq = makeRequest({ pathTemplate: '/apiary' });
  const apiaryDenied = evaluateScopePolicy({ grant: prefixGrant, request: apiaryReq, decisionId: 'dec-apiary', evaluatedAt: now.toISOString() });
  assert.strictEqual(apiaryDenied.decision, 'denied', '/api prefix should NOT match /apiary');

  // /api/sub should match /api prefix
  const apiSubReq = makeRequest({ pathTemplate: '/api/sub' });
  const apiSubAllowed = evaluateScopePolicy({ grant: prefixGrant, request: apiSubReq, decisionId: 'dec-apisub', evaluatedAt: now.toISOString() });
  assert.strictEqual(apiSubAllowed.decision, 'allowed', '/api/sub should match /api prefix');

  // Path with query/fragment -> invalid request
  const queryGrant = makeGrant({ boundaries: { allowedOrigins: ['https://example.com'] } });
  const queryReq = makeRequest({ pathTemplate: '/api?query=1' });
  const queryDenied = evaluateScopePolicy({ grant: queryGrant, request: queryReq, decisionId: 'dec-q', evaluatedAt: now.toISOString() });
  assert.strictEqual(queryDenied.decision, 'denied');
  assert.strictEqual(queryDenied.reasonCode, 'denied_invalid_request');

  // Method denied
  const methodGrant = makeGrant({
    boundaries: {
      allowedOrigins: ['https://example.com'],
      deniedMethods: ['DELETE'],
      allowedMethods: ['GET', 'POST', 'DELETE']
    },
    constraints: { ...makeGrant().constraints, allowStateChangingRequests: true }
  });
  const deleteReq = makeRequest({ method: 'DELETE', mayChangeServerState: true });
  const deleteDenied = evaluateScopePolicy({ grant: methodGrant, request: deleteReq, decisionId: 'dec-del', evaluatedAt: now.toISOString() });
  assert.strictEqual(deleteDenied.decision, 'denied');
  assert.strictEqual(deleteDenied.reasonCode, 'denied_method_explicitly_denied');

  // Method not in allowedMethods
  const patchReq = makeRequest({ method: 'PATCH', mayChangeServerState: true });
  const patchDenied = evaluateScopePolicy({
    grant: makeGrant({
      boundaries: { allowedOrigins: ['https://example.com'], allowedMethods: ['GET', 'POST'] },
      constraints: { ...makeGrant().constraints, allowStateChangingRequests: true }
    }),
    request: patchReq,
    decisionId: 'dec-patch',
    evaluatedAt: now.toISOString()
  });
  assert.strictEqual(patchDenied.decision, 'denied');
  assert.strictEqual(patchDenied.reasonCode, 'denied_method_not_allowed');

  console.log('[+] Scope boundaries work correctly.');
}

// ---------------------------------------------------------------------------
// 9. Expiration / scan mismatch
// ---------------------------------------------------------------------------

async function testExpirationAndScanMismatch() {
  console.log('[*] Testing expiration and scan mismatch...');

  // Expired grant
  const expiredGrant = makeGrant({ expiresAt: past });
  const expDecision = evaluateScopePolicy({ grant: expiredGrant, request: makeRequest(), decisionId: 'dec-exp', evaluatedAt: now.toISOString() });
  assert.strictEqual(expDecision.decision, 'denied');
  assert.strictEqual(expDecision.reasonCode, 'denied_expired_grant');

  // Scan mismatch
  const mismatchReq = makeRequest({ scanId: 'scan-different' });
  const mismatch = evaluateScopePolicy({ grant: makeGrant(), request: mismatchReq, decisionId: 'dec-mm', evaluatedAt: now.toISOString() });
  assert.strictEqual(mismatch.decision, 'denied');
  assert.strictEqual(mismatch.reasonCode, 'denied_scan_mismatch');

  console.log('[+] Expiration and scan mismatch work correctly.');
}

// ---------------------------------------------------------------------------
// 10. Runtime hardening (negative tests)
// ---------------------------------------------------------------------------

async function testRuntimeHardening() {
  console.log('[*] Testing runtime hardening (negative tests)...');

  // Wrong contractVersion
  assert.strictEqual(validateAuthorizedScopeGrant({ ...makeGrant(), contractVersion: 'wrong' }).isValid, false);

  // Wrong kind
  assert.strictEqual(validateAuthorizedScopeGrant({ ...makeGrant(), kind: 'something_else' }).isValid, false);

  // Classification flag true
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), classification: { ...baseClassification, createsRealFindings: true } }).isValid,
    false
  );

  // executesNetwork: true in classification
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), classification: { ...baseClassification, executesNetwork: true } }).isValid,
    false
  );

  // permissionSet with string "true"
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), permissionSet: { ...makeGrant().permissionSet, passiveRecon: 'true' as any } }).isValid,
    false
  );

  // destructiveOperations: true
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), permissionSet: { ...makeGrant().permissionSet, destructiveOperations: true } }).isValid,
    false
  );

  // allowThirdPartyTargets: true
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), constraints: { ...makeGrant().constraints, allowThirdPartyTargets: true } }).isValid,
    false
  );

  // allowedOrigins as string instead of array
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), boundaries: { allowedOrigins: 'https://example.com' as any } }).isValid,
    false
  );

  // allowedMethods as string instead of array
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), boundaries: { allowedMethods: 'GET' as any } }).isValid,
    false
  );

  // allowedPathPatterns as string instead of array
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), boundaries: { allowedPathPatterns: '/api' as any } }).isValid,
    false
  );

  // Unknown field severity in grant
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), severity: 'critical' }).isValid,
    false
  );

  // Unknown field risk in request
  assert.strictEqual(
    validateScopeActionRequest({ ...makeRequest(), risk: 'high' }).isValid,
    false
  );

  // Forbidden content in authorizationText
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), authorizationBasis: { ...makeGrant().authorizationBasis, authorizationText: 'Authorization: Bearer token123' } }).isValid,
    false
  );

  // Forbidden content in path
  assert.strictEqual(
    validateScopeActionRequest({ ...makeRequest(), pathTemplate: '/api/secret/path' }).isValid,
    false
  );

  // normalizedOrigin with path
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), subject: { targetKind: 'origin', normalizedOrigin: 'https://example.com/path' } }).isValid,
    false
  );

  // normalizedOrigin with credentials
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), subject: { targetKind: 'origin', normalizedOrigin: 'https://user:pass@example.com' } }).isValid,
    false
  );

  // normalizedOrigin with query
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), subject: { targetKind: 'origin', normalizedOrigin: 'https://example.com?foo=bar' } }).isValid,
    false
  );

  // Invalid timestamp
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), issuedAt: 'not-a-date' }).isValid,
    false
  );

  // Invalid ID
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), grantId: '' }).isValid,
    false
  );

  // Extra unknown nested field in permissionSet
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), permissionSet: { ...makeGrant().permissionSet, impact: 'data exposure' } }).isValid,
    false
  );

  // Extra unknown nested field in constraints
  assert.strictEqual(
    validateAuthorizedScopeGrant({ ...makeGrant(), constraints: { ...makeGrant().constraints, rawPayload: 'unsafe' } }).isValid,
    false
  );

  console.log('[+] Runtime hardening (negative tests) all pass.');
}

// ---------------------------------------------------------------------------
// 11. No execution demonstration
// ---------------------------------------------------------------------------

async function testNoExecution() {
  console.log('[*] Testing no-execution invariant...');

  const grant = makeGrant();
  const request = makeRequest();
  const decision = evaluateScopePolicy({ grant, request, decisionId: 'dec-ne', evaluatedAt: now.toISOString() });

  // No network, no tools, no persistence in classification
  assert.strictEqual(decision.classification.executesNetwork, false, 'executesNetwork must be false');
  assert.strictEqual(decision.classification.executesTools, false, 'executesTools must be false');
  assert.strictEqual(decision.classification.persistsData, false, 'persistsData must be false');

  // No findings/evidence claims
  assert.strictEqual(decision.classification.createsRealFindings, false);
  assert.strictEqual(decision.classification.createsPersistedEvidence, false);
  assert.strictEqual(decision.classification.confirmsVulnerabilities, false);
  assert.strictEqual(decision.classification.makesRiskClaims, false);
  assert.strictEqual(decision.classification.makesSeverityClaims, false);
  assert.strictEqual(decision.classification.makesImpactClaims, false);

  // No raw URL, path, secrets in decision reason
  const reasonStr = JSON.stringify(decision).toLowerCase();
  const forbiddenInReason = ['https://example.com', 'bearer', 'cookie', 'password', 'raw request', 'stack trace'];
  for (const term of forbiddenInReason) {
    // reason and matchedBoundary should not echo raw values
    const reasonOnly = JSON.stringify({ reason: decision.reason, matchedBoundary: decision.matchedBoundary }).toLowerCase();
    if (reasonOnly.includes(term.toLowerCase())) {
      assert.fail(`Forbidden term found in decision reason/boundary: ${term}`);
    }
  }

  console.log('[+] No-execution invariant verified.');
}

// ---------------------------------------------------------------------------
// 12. Permission derivation
// ---------------------------------------------------------------------------

async function testPermissionDerivation() {
  console.log('[*] Testing permission derivation...');

  assert.strictEqual(deriveRequiredPermissionForAction('passive_recon', 'passive', false, false, false), 'passiveRecon');
  assert.strictEqual(deriveRequiredPermissionForAction('technology_fingerprint', 'passive', false, false, false), 'technologyFingerprinting');
  assert.strictEqual(deriveRequiredPermissionForAction('endpoint_discovery', 'passive', false, false, false), 'endpointDiscovery');
  assert.strictEqual(deriveRequiredPermissionForAction('active_crawl', 'low', false, false, false), 'activeCrawling');
  assert.strictEqual(deriveRequiredPermissionForAction('authenticated_probe', 'low', true, false, false), 'authenticatedTesting');
  assert.strictEqual(deriveRequiredPermissionForAction('light_validation', 'low', false, false, false), 'lightValidation');
  assert.strictEqual(deriveRequiredPermissionForAction('active_validation', 'medium', false, false, false), 'activeValidation');
  assert.strictEqual(deriveRequiredPermissionForAction('aggressive_validation', 'aggressive', false, false, false), 'aggressiveValidation');
  assert.strictEqual(deriveRequiredPermissionForAction('oob_validation', 'medium', false, true, false), 'oobTesting');
  assert.strictEqual(deriveRequiredPermissionForAction('destructive_operation', 'passive', false, false, false), 'destructiveOperations');
  assert.strictEqual(deriveRequiredPermissionForAction('passive_recon', 'destructive', false, false, false), 'destructiveOperations');

  // Intensity upgrade: aggressive intensity upgrades light_validation to aggressiveValidation
  assert.strictEqual(deriveRequiredPermissionForAction('light_validation', 'aggressive', false, false, false), 'aggressiveValidation');
  // medium intensity upgrades light_validation to activeValidation
  assert.strictEqual(deriveRequiredPermissionForAction('light_validation', 'medium', false, false, false), 'activeValidation');

  console.log('[+] Permission derivation works correctly.');
}

// ---------------------------------------------------------------------------
// 13. Decision metadata safety (decisionId / evaluatedAt injection)
// ---------------------------------------------------------------------------

async function testDecisionMetadataSafety() {
  console.log('[*] Testing decision metadata safety (unsafe decisionId / evaluatedAt / IDs)...');

  const grant = makeGrant();
  const request = makeRequest();

  const FORBIDDEN_TERMS = [
    'secret', 'token', 'authorization', 'bearer', 'cookie', 'raw', 'password',
    'not-a-date',
    'dec_secret_token',
    'grant_secret_token',
    'req_secret_token',
    'scan_secret_token'
  ];

  function assertNoForbiddenTerms(decision: any, label: string): void {
    const serialized = JSON.stringify(decision).toLowerCase();
    for (const term of FORBIDDEN_TERMS) {
      if (serialized.includes(term.toLowerCase())) {
        assert.fail(`Forbidden term "${term}" found in decision output for: ${label}`);
      }
    }
  }

  // 1. Unsafe decisionId containing secret_token must not be echoed
  const decIdWithSecret = evaluateScopePolicy({
    grant,
    request,
    decisionId: 'dec_secret_token',
    evaluatedAt: now.toISOString()
  });
  assert.strictEqual(decIdWithSecret.decision, 'denied', 'Unsafe decisionId must result in denied');
  assert.strictEqual(decIdWithSecret.reasonCode, 'denied_invalid_request');
  assertNoForbiddenTerms(decIdWithSecret, 'unsafe decisionId');
  // Verify sentinel is used, not the raw unsafe value
  assert.strictEqual(decIdWithSecret.decisionId, 'invalid_decision_id', 'Sentinel decisionId must be used');
  console.log('[+] Unsafe decisionId replaced with sentinel and not echoed.');

  // 2. Invalid evaluatedAt (not-a-date) must not produce allowed and must not be echoed raw
  const badTimestamp = evaluateScopePolicy({
    grant,
    request,
    decisionId: 'dec-valid-1',
    evaluatedAt: 'not-a-date'
  });
  assert.strictEqual(badTimestamp.decision, 'denied', 'Invalid evaluatedAt must result in denied');
  assert.strictEqual(badTimestamp.reasonCode, 'denied_invalid_request');
  // Sentinel epoch time used, not the raw invalid value
  assert.strictEqual(badTimestamp.evaluatedAt, '1970-01-01T00:00:00.000Z', 'Sentinel evaluatedAt must be used');
  assertNoForbiddenTerms(badTimestamp, 'invalid evaluatedAt');
  console.log('[+] Invalid evaluatedAt replaced with epoch sentinel and not echoed.');

  // 3. Both decisionId and evaluatedAt invalid
  const bothBad = evaluateScopePolicy({
    grant,
    request,
    decisionId: 'dec_secret_token',
    evaluatedAt: 'not-a-date'
  });
  assert.strictEqual(bothBad.decision, 'denied');
  assert.strictEqual(bothBad.decisionId, 'invalid_decision_id');
  assert.strictEqual(bothBad.evaluatedAt, '1970-01-01T00:00:00.000Z');
  assertNoForbiddenTerms(bothBad, 'both bad metadata');
  console.log('[+] Both unsafe decisionId + evaluatedAt replaced with sentinels.');

  // 4. Grant with grantId containing secret_token — decision must not echo the raw grantId
  const secretGrant = makeGrant({ grantId: 'grant_secret_token' });
  // grant validation will fail because 'secret' is in grantId (forbidden content scan)
  const secretGrantDecision = evaluateScopePolicy({
    grant: secretGrant,
    request,
    decisionId: 'dec-clean-1',
    evaluatedAt: now.toISOString()
  });
  assert.strictEqual(secretGrantDecision.decision, 'denied');
  assertNoForbiddenTerms(secretGrantDecision, 'grantId with secret_token');
  // Should use sentinel for grantId since it didn't pass validateSafeId
  assert.ok(
    secretGrantDecision.grantId !== 'grant_secret_token',
    'Raw unsafe grantId must not be echoed in decision'
  );
  console.log('[+] Grant with unsafe grantId does not echo raw grantId in decision.');

  // 5. Request with requestId containing secret_token — decision must not echo the raw requestId
  const secretRequest = makeRequest({ requestId: 'req_secret_token' });
  // request validation will fail because 'secret' is in requestId (forbidden content scan)
  const secretRequestDecision = evaluateScopePolicy({
    grant,
    request: secretRequest,
    decisionId: 'dec-clean-2',
    evaluatedAt: now.toISOString()
  });
  assert.strictEqual(secretRequestDecision.decision, 'denied');
  assertNoForbiddenTerms(secretRequestDecision, 'requestId with secret_token');
  assert.ok(
    secretRequestDecision.requestId !== 'req_secret_token',
    'Raw unsafe requestId must not be echoed in decision'
  );
  console.log('[+] Request with unsafe requestId does not echo raw requestId in decision.');

  // 6. Grant with scanId containing secret_token — decision must not echo the raw scanId
  const secretScanGrant = makeGrant({ scanId: 'scan_secret_token' });
  const secretScanDecision = evaluateScopePolicy({
    grant: secretScanGrant,
    request,
    decisionId: 'dec-clean-3',
    evaluatedAt: now.toISOString()
  });
  assert.strictEqual(secretScanDecision.decision, 'denied');
  assertNoForbiddenTerms(secretScanDecision, 'scanId with secret_token');
  assert.ok(
    secretScanDecision.scanId !== 'scan_secret_token',
    'Raw unsafe scanId must not be echoed in decision'
  );
  console.log('[+] Grant with unsafe scanId does not echo raw scanId in decision.');

  // 7. Valid decisionId and evaluatedAt still work (non-regression)
  const cleanDecision = evaluateScopePolicy({
    grant,
    request,
    decisionId: 'dec-clean-final',
    evaluatedAt: now.toISOString()
  });
  assert.strictEqual(cleanDecision.decision, 'allowed');
  assert.strictEqual(cleanDecision.decisionId, 'dec-clean-final');
  assert.strictEqual(cleanDecision.evaluatedAt, now.toISOString());
  console.log('[+] Valid decisionId/evaluatedAt pass through correctly (non-regression).');

  console.log('[+] Decision metadata safety tests all pass.');
}

// ---------------------------------------------------------------------------
// Run all tests
// ---------------------------------------------------------------------------

async function runTests() {
  console.log('--- V2 M46 Authorized Scope Policy DB-Free Smoke Test ---');

  await testAllowedActions();
  await testRequiredPermissionBypassPrevention();
  await testDeniedPermission();
  await testDestructiveAlwaysDenied();
  await testAuthAndCredentials();
  await testOob();
  await testStateChange();
  await testScopeBoundaries();
  await testExpirationAndScanMismatch();
  await testRuntimeHardening();
  await testNoExecution();
  await testPermissionDerivation();
  await testDecisionMetadataSafety();

  console.log('--- M46 Authorized Scope Policy DB-Free Smoke Completed Successfully ---');
}

runTests().catch(err => {
  console.error(err);
  process.exit(1);
});
