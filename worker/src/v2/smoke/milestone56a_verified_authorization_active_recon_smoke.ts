import assert from 'node:assert';
import process from 'node:process';
import { runActiveReconOriginProbes } from '../recon/active/ActiveReconOriginRunService.js';
import type { 
  ActiveReconOriginRunRequest,
  ActiveReconOriginProbeSelection 
} from '../recon/active/ActiveReconOriginRunContracts.js';
import type { 
  EstablishVerifiedAuthorizationDecisionRequest,
  VerifiedAuthorizationDecision 
} from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { executeAndPersistActiveReconOriginRun } from '../recon/active/ActiveReconRunExecutionPersistenceService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { ActiveReconDocumentProbeAdapters } from '../recon/active/ActiveReconDocumentProbeRunner.js';
import type { ActiveReconRunRepository } from '../recon/active/ActiveReconOriginRunRepository.js';
import type { PersistedActiveReconRunRecord } from '../recon/active/ActiveReconOriginRunPersistenceContracts.js';
import { deriveAuthorizationLineageRef } from '../authorization/VerifiedAuthorizationDecisionService.js';

// ============================================================================
function isUnknownRecord(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }

// Typed Helpers
// ============================================================================

function buildAuthorizedScopeGrant(
  overrides?: Partial<AuthorizedScopeGrant>,
  permissionOverrides?: Partial<AuthorizedScopeGrant['permissionSet']>,
  boundariesOverrides?: Partial<AuthorizedScopeGrant['boundaries']>,
  constraintsOverrides?: Partial<AuthorizedScopeGrant['constraints']>,
  classificationOverrides?: Partial<AuthorizedScopeGrant['classification']>
): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_1',
    scanId: 'scan_1',
    issuedAt: '2026-07-01T00:00:00.000Z',
    expiresAt: '2026-07-10T23:59:59.999Z',
    subject: { targetKind: 'origin', normalizedOrigin: 'https://example.com' },
    authorizationBasis: { basisKind: 'internal_asset_record', recordedBy: 'human_user', authorizationText: 'Test' },
    permissionSet: {
      passiveRecon: true, technologyFingerprinting: true, endpointDiscovery: true, activeCrawling: true,
      authenticatedTesting: false, lightValidation: true, activeValidation: false, aggressiveValidation: false,
      oobTesting: false, destructiveOperations: false,
      ...permissionOverrides,
    },
    boundaries: { 
      allowedOrigins: ['https://example.com'], 
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
      allowedPathPatterns: [{ match: 'prefix', pathTemplate: '/' }],
      deniedPathPatterns: [],
      ...boundariesOverrides 
    },
    constraints: { 
      allowLoginRequiredAreas: false, allowStateChangingRequests: false, allowCredentialUse: false, 
      allowOobCallbacks: false, allowThirdPartyTargets: false,
      ...constraintsOverrides
    },
    classification: { 
      createsRealFindings: false, createsPersistedEvidence: false, confirmsVulnerabilities: false, 
      makesRiskClaims: false, makesSeverityClaims: false, makesImpactClaims: false, 
      executesNetwork: false, executesTools: false, persistsData: false,
      ...classificationOverrides
    },
    ...overrides,
  };
}

function establishDecisionOrThrow(
  request: EstablishVerifiedAuthorizationDecisionRequest,
  evaluatedAt: string
): VerifiedAuthorizationDecision {
  const result = establishVerifiedAuthorizationDecision(request, evaluatedAt);
  if (result.status === 'failed') {
    throw new Error(`Establishment failed: ${result.reasonCode} / ${result.safeMessage}`);
  }
  assert.strictEqual(result.status, 'established');
  return result.decision;
}

// ============================================================================
// Negative Helpers (Where unsafe casts are explicitly allowed)
// ============================================================================

const buildMalformedEstablishmentRequest = (overrides: Partial<Omit<import("../authorization/VerifiedAuthorizationDecisionContracts.js").EstablishVerifiedAuthorizationDecisionRequest, "decision" | "authorizedActor" | "scopeGrant" | "verification">> & Record<string, unknown>): import("../authorization/VerifiedAuthorizationDecisionContracts.js").EstablishVerifiedAuthorizationDecisionRequest => {
  return overrides as import("../authorization/VerifiedAuthorizationDecisionContracts.js").EstablishVerifiedAuthorizationDecisionRequest;
};

const buildMalformedActiveReconOriginRunRequest = (overrides: Partial<Omit<import("../recon/active/ActiveReconOriginRunContracts.js").ActiveReconOriginRunRequest, "verifiedAuthorizationDecision" | "probes">> & Record<string, unknown>): import("../recon/active/ActiveReconOriginRunContracts.js").ActiveReconOriginRunRequest => {
  return overrides as import("../recon/active/ActiveReconOriginRunContracts.js").ActiveReconOriginRunRequest;
};

const attemptMutation = (fn: () => void) => {
  try {
    fn();
  } catch {}
};

// ============================================================================
// Main
// ============================================================================

async function main() {
  console.log('--- M56A Corrective Pass Smoke Test ---');

  // P1 Correction 5 — complete missing establishment coverage
  console.log('[*] Testing unauthorized establishment rejection...');
  const baseGrant = buildAuthorizedScopeGrant();
  const unauthRequest = buildMalformedEstablishmentRequest({
    contractVersion: 'fixguard-verified-authorization-decision/v0',
    kind: 'establish_verified_authorization_decision_request',
    assessmentId: 'assess_1',
    scanId: 'scan_1',
    authorizationDecisionId: 'dec_1',
    authorizedActor: { actorId: 'actor_1', actorType: 'human' },
    decision: 'rejected', // NOT authorized
    decidedAt: '2026-07-05T00:00:00.000Z',
    scopeGrant: baseGrant
  });
  const unauthResult = establishVerifiedAuthorizationDecision(unauthRequest, '2026-07-05T12:00:00.000Z');
  assert.strictEqual(unauthResult.status, 'failed');
  assert.strictEqual(unauthResult.reasonCode, 'decision_not_authorized');
  console.log('  [+] Rejected non-authorized decision.');

  // Create valid decision for remaining tests
  const validReq: EstablishVerifiedAuthorizationDecisionRequest = {
    contractVersion: 'fixguard-verified-authorization-decision/v0',
    kind: 'establish_verified_authorization_decision_request',
    assessmentId: 'assess_1',
    scanId: 'scan_1',
    authorizationDecisionId: 'dec_1',
    authorizedActor: { actorId: 'actor_1', actorType: 'human' },
    decision: 'authorized',
    decidedAt: '2026-07-05T00:00:00.000Z',
    scopeGrant: baseGrant,
  };
  const validDecision = establishDecisionOrThrow(validReq, '2026-07-05T12:00:00.000Z');

  // P1 Correction 11 — complete recursive immutability coverage
  console.log('[*] Testing recursive immutability...');
  assert.ok(Object.isFrozen(validDecision));
  assert.ok(Object.isFrozen(validDecision.authorizedActor));
  assert.ok(Object.isFrozen(validDecision.verification));
  assert.ok(Object.isFrozen(validDecision.scopeGrant));
  assert.ok(Object.isFrozen(validDecision.scopeGrant.subject));
  assert.ok(Object.isFrozen(validDecision.scopeGrant.authorizationBasis));
  assert.ok(Object.isFrozen(validDecision.scopeGrant.permissionSet));
  assert.ok(Object.isFrozen(validDecision.scopeGrant.boundaries));
  assert.ok(Object.isFrozen(validDecision.scopeGrant.boundaries.allowedOrigins));
  assert.ok(Object.isFrozen(validDecision.scopeGrant.boundaries.allowedMethods));
  assert.ok(Object.isFrozen(validDecision.scopeGrant.boundaries.allowedPathPatterns));
  assert.ok(Object.isFrozen(validDecision.scopeGrant.boundaries.deniedPathPatterns));
  assert.ok(Object.isFrozen(validDecision.scopeGrant.constraints));
  assert.ok(Object.isFrozen(validDecision.scopeGrant.classification));

  const originalVerifiedAt = validDecision.verification.verifiedAt;
  const originalVerificationMethod = validDecision.verification.method;

  // Safely narrow to attempt mutation on frozen objects
  const vd = validDecision as Record<string, unknown>;
  const sg = vd.scopeGrant as Record<string, unknown>;
  const ps = sg.permissionSet as Record<string, unknown>;
  const sb = sg.boundaries as Record<string, unknown>;
  const sc = sg.constraints as Record<string, unknown>;
  const sclass = sg.classification as Record<string, unknown>;
  const actor = vd.authorizedActor as Record<string, unknown>;
  const ver = vd.verification as Record<string, unknown>;
  const subj = sg.subject as Record<string, unknown>;

  attemptMutation(() => { vd.kind = 'mutated'; });
  attemptMutation(() => { ps.endpointDiscovery = false; });
  attemptMutation(() => { ps.activeValidation = true; });
  attemptMutation(() => { (sb.allowedOrigins as unknown[])[0] = 'https://hacked.com'; });
  attemptMutation(() => { (sb.allowedMethods as unknown[])[0] = 'POST'; });
  attemptMutation(() => { (sb.allowedPathPatterns as unknown[])[0] = { match: 'exact', pathTemplate: '/hack' }; });
  attemptMutation(() => { (sb.deniedPathPatterns as unknown[])[0] = { match: 'prefix', pathTemplate: '/' }; });
  attemptMutation(() => { sc.allowCredentialUse = true; });
  attemptMutation(() => { sclass.executesNetwork = true; });
  attemptMutation(() => { actor.actorId = 'hacker'; });
  attemptMutation(() => { ver.verifiedAt = '1970-01-01T00:00:00.000Z'; });
  attemptMutation(() => { ver.method = 'hacked'; });
  attemptMutation(() => { sg.grantId = 'hacked_grant'; });
  attemptMutation(() => { sg.scanId = 'hacked_scan'; });
  attemptMutation(() => { subj.normalizedOrigin = 'https://hacked.com'; });

  assert.strictEqual(validDecision.kind, 'verified_authorization_decision');
  assert.strictEqual(validDecision.scopeGrant.permissionSet.endpointDiscovery, true);
  assert.strictEqual(validDecision.scopeGrant.permissionSet.activeValidation, false);
  assert.strictEqual(validDecision.scopeGrant.boundaries.allowedOrigins?.[0], 'https://example.com');
  assert.strictEqual(validDecision.scopeGrant.boundaries.allowedMethods?.[0], 'GET');
  assert.strictEqual(validDecision.scopeGrant.boundaries.allowedPathPatterns?.[0]?.pathTemplate, '/');
  assert.strictEqual(validDecision.scopeGrant.boundaries.deniedPathPatterns?.length, 0);
  assert.strictEqual(validDecision.scopeGrant.constraints.allowCredentialUse, false);
  assert.strictEqual(validDecision.scopeGrant.classification.executesNetwork, false);
  assert.strictEqual(validDecision.authorizedActor.actorId, 'actor_1');
  assert.strictEqual(validDecision.scopeGrant.grantId, 'grant_1');
  assert.strictEqual(validDecision.scopeGrant.scanId, 'scan_1');
  assert.strictEqual(validDecision.scopeGrant.subject.normalizedOrigin, 'https://example.com');
  
  assert.strictEqual(validDecision.verification.verifiedAt, originalVerifiedAt);
  assert.strictEqual(validDecision.verification.method, originalVerificationMethod);
  
  console.log('  [+] Mutability correctly resisted across all nested objects and arrays.');

  // Test execution remains unhacked
  const immutabilityExecResult = await runActiveReconOriginProbes({
    contractVersion: 'active-recon-origin-run/v1',
    evaluatedAt: '2026-07-05T12:00:00.000Z',
    verifiedAuthorizationDecision: validDecision,
    origin: 'https://example.com',
    probes: [{ family: 'document', probe: 'http.robots.inspect' }]
  }, { robots: { async probe() { return []; } } });
  if(immutabilityExecResult.status !== "completed") console.error(JSON.stringify(immutabilityExecResult, null, 2)); assert.strictEqual(immutabilityExecResult.status, "completed");
  assert.strictEqual(immutabilityExecResult.probes[0].status, 'completed');
  console.log('  [+] Execution behavior remains unchanged after mutation attempts.');

  // Check forgery
  console.log('[*] Testing forgery resistance...');
  
  async function checkForgery(forgedReq: import("../recon/active/ActiveReconOriginRunContracts.js").ActiveReconOriginRunRequest) {
    let adapterCalls = 0;
    
    const res = await runActiveReconOriginProbes(forgedReq, { robots: { async probe() { adapterCalls++; return []; } } });
    assert.strictEqual(res.status, 'failed');
    assert.strictEqual(res.runErrors[0].code, 'authorization_not_confirmed');
    assert.strictEqual(adapterCalls, 0);
  }

  const plainStructuralLookalike = buildMalformedActiveReconOriginRunRequest({
    contractVersion: 'active-recon-origin-run/v1',
    evaluatedAt: '2026-07-05T12:00:00.000Z',
    verifiedAuthorizationDecision: { ...validDecision, verification: undefined },
    origin: 'https://example.com',
    probes: [{ family: 'document', probe: 'http.robots.inspect' }]
  });
  await checkForgery(plainStructuralLookalike);
  console.log('  [+] plain structural lookalike failed correctly.');

  const forgedSpreadDecision = buildMalformedActiveReconOriginRunRequest({
    contractVersion: 'active-recon-origin-run/v1',
    evaluatedAt: '2026-07-05T12:00:00.000Z',
    verifiedAuthorizationDecision: { ...validDecision },
    origin: 'https://example.com',
    probes: [{ family: 'document', probe: 'http.robots.inspect' }]
  });
  await checkForgery(forgedSpreadDecision);
  console.log('  [+] spread copy failed correctly.');

  const forgedDeepCopy = buildMalformedActiveReconOriginRunRequest({
    contractVersion: 'active-recon-origin-run/v1',
    evaluatedAt: '2026-07-05T12:00:00.000Z',
    verifiedAuthorizationDecision: structuredClone(validDecision),
    origin: 'https://example.com',
    probes: [{ family: 'document', probe: 'http.robots.inspect' }]
  });
  await checkForgery(forgedDeepCopy);
  console.log('  [+] non-JSON deep copy failed correctly.');

  const forgedJsonRoundTrip = buildMalformedActiveReconOriginRunRequest({
    contractVersion: 'active-recon-origin-run/v1',
    evaluatedAt: '2026-07-05T12:00:00.000Z',
    verifiedAuthorizationDecision: JSON.parse(JSON.stringify(validDecision)),
    origin: 'https://example.com',
    probes: [{ family: 'document', probe: 'http.robots.inspect' }]
  });
  await checkForgery(forgedJsonRoundTrip);
  console.log('  [+] JSON round-trip failed correctly.');

  const callerFrozenLookalike = buildMalformedActiveReconOriginRunRequest({
    contractVersion: 'active-recon-origin-run/v1',
    evaluatedAt: '2026-07-05T12:00:00.000Z',
    verifiedAuthorizationDecision: Object.freeze(JSON.parse(JSON.stringify(validDecision))),
    origin: 'https://example.com',
    probes: [{ family: 'document', probe: 'http.robots.inspect' }]
  });
  await checkForgery(callerFrozenLookalike);
  console.log('  [+] caller-frozen lookalike failed correctly.');

  const malformedRequest = buildMalformedActiveReconOriginRunRequest({
    contractVersion: 'active-recon-origin-run/v1',
    evaluatedAt: '2026-07-05T12:00:00.000Z',
    verifiedAuthorizationDecision: 'string-not-decision',
    origin: 'https://example.com',
    probes: [{ family: 'document', probe: 'http.robots.inspect' }]
  });
  await checkForgery(malformedRequest);
  console.log('  [+] malformed establishment request failed correctly.');

  // Check invalid actor on establish
  const unauthActorRequest = buildMalformedEstablishmentRequest({
    contractVersion: 'fixguard-verified-authorization-decision/v0',
    kind: 'establish_verified_authorization_decision_request',
    assessmentId: 'assess_1',
    scanId: 'scan_1',
    authorizationDecisionId: 'dec_1',
    authorizedActor: { actorId: 'actor_1' }, // Missing actorType
    decision: 'authorized',
    decidedAt: '2026-07-05T00:00:00.000Z',
    scopeGrant: baseGrant
  });
  const unauthActorResult = establishVerifiedAuthorizationDecision(unauthActorRequest, '2026-07-05T12:00:00.000Z');
  assert.strictEqual(unauthActorResult.status, 'failed');
  assert.strictEqual(unauthActorResult.reasonCode, 'actor_invalid');
  console.log('  [+] invalid actor failed correctly.');

  // Check scan mismatch on establish
  const mismatchScanRequest = buildMalformedEstablishmentRequest({
    contractVersion: 'fixguard-verified-authorization-decision/v0',
    kind: 'establish_verified_authorization_decision_request',
    assessmentId: 'assess_1',
    scanId: 'scan_1',
    authorizationDecisionId: 'dec_1',
    authorizedActor: { actorId: 'actor_1', actorType: 'human' },
    decision: 'authorized',
    decidedAt: '2026-07-05T00:00:00.000Z',
    scopeGrant: buildAuthorizedScopeGrant({ scanId: 'scan_2' })
  });
  const mismatchScanResult = establishVerifiedAuthorizationDecision(mismatchScanRequest, '2026-07-05T12:00:00.000Z');
  assert.strictEqual(mismatchScanResult.status, 'failed');
  assert.strictEqual(mismatchScanResult.reasonCode, 'id_invariant_violated');
  console.log('  [+] grant/scan mismatch failed correctly.');

  // Already verified non-authorized at line 119
  console.log('  [+] non-authorized establishment request failed correctly (verified above).');

  // P1 Correction 9 — Prove derived lineage equality
  console.log('[*] Testing derived lineage equality...');
  const derived = deriveAuthorizationLineageRef(validDecision);
  assert.strictEqual(derived.assessmentId, validDecision.assessmentId);
  assert.strictEqual(derived.scanId, validDecision.scanId);
  assert.strictEqual(derived.authorizationGrantId, validDecision.scopeGrant.grantId);
  assert.strictEqual(derived.authorizationDecisionId, validDecision.authorizationDecisionId);
  assert.strictEqual(derived.actorId, validDecision.authorizedActor.actorId);
  console.log('  [+] Lineage strictly matches decision truth.');

  // P1 Correction 2, 3, 4 — fully instrument the four denied-batch cases
  console.log('[*] Testing denied batch scenarios...');

  const runInstrumentedBatch = async (
    probes: unknown[],
    testDecision: VerifiedAuthorizationDecision,
    adaptersToInclude: ('robots' | 'securityTxt')[]
  ) => {
    let robotsAdapterCalls = 0;
    let securityTxtAdapterCalls = 0;
    let repositorySaveRunCalls = 0;
    let repositoryGetRunCalls = 0;
    let repositoryListRunsCalls = 0;
    let repositoryRecordCount = 0;
    let persistedRecord: PersistedActiveReconRunRecord | null = null;
    let executionPersistenceCompositionCalls = 0;

    const req = buildMalformedActiveReconOriginRunRequest({
      contractVersion: 'active-recon-origin-run/v1',
      evaluatedAt: '2026-07-05T12:00:00.000Z',
      verifiedAuthorizationDecision: testDecision,
      origin: 'https://example.com',
      probes,
    });

    const adapters: ActiveReconDocumentProbeAdapters = {};
    if (adaptersToInclude.includes('robots')) {
      adapters.robots = { async probe() { robotsAdapterCalls++; return [{ kind: 'robots_metadata', safeSummary: 'test', confidence: 'high' }]; } };
    }
    if (adaptersToInclude.includes('securityTxt')) {
      adapters.securityTxt = { async probe() { securityTxtAdapterCalls++; return [{ kind: 'security_txt_metadata', safeSummary: 'test', confidence: 'high' }]; } };
    }

    const repo: ActiveReconRunRepository = {
      async saveRun(record: PersistedActiveReconRunRecord) { 
        repositorySaveRunCalls++; 
        repositoryRecordCount++;
        persistedRecord = record;
        return record;
      },
      async getRun() { repositoryGetRunCalls++; return null; },
      async listRuns() { repositoryListRunsCalls++; return []; }
    };

    // First call runActiveReconOriginProbes to observe execution facts (disposition, probes, observations)
    
    const execResult = await runActiveReconOriginProbes(req, adapters);

    // Then call composition to observe persistence facts
    executionPersistenceCompositionCalls++;
    
    const compositionResult = await executeAndPersistActiveReconOriginRun({ request: req, adapters, repository: repo });
    
    const totalAdapterCalls = robotsAdapterCalls + securityTxtAdapterCalls;

    return {
      execResult,
      compositionResult,
      robotsAdapterCalls, // since adapter calls are counted, if we call both, they would double if both run. But for denied batches, they run 0 times. For successful batches, we must divide by 2 or isolate. We'll just rely on the counters and expect them.
      securityTxtAdapterCalls,
      totalAdapterCalls,
      repositorySaveRunCalls,
      repositoryGetRunCalls,
      repositoryListRunsCalls,
      repositoryRecordCount,
      persistedRecord,
      observationsProduced: execResult.observations.length,
      reloadVerified: compositionResult.reloadVerified,
      executionPersistenceCompositionCalls
    };
  };

  // Case 1: allowed (robots), denied (security.txt by scope permission)
  const case1Decision = establishDecisionOrThrow({
    ...validReq,
    scopeGrant: buildAuthorizedScopeGrant({}, {}, { deniedPathPatterns: [{ match: 'exact', pathTemplate: '/.well-known/security.txt' }] })
  }, '2026-07-05T12:00:00.000Z');
  const case1 = await runInstrumentedBatch(
    [{ family: 'document', probe: 'http.robots.inspect' }, { family: 'document', probe: 'http.security_txt.inspect' }],
    case1Decision,
    ['robots', 'securityTxt']
  );
  assert.strictEqual(case1.execResult.status, 'failed');
  assert.strictEqual(case1.execResult.disposition, 'preflight_denied');
  assert.strictEqual(case1.robotsAdapterCalls, 0);
  assert.strictEqual(case1.securityTxtAdapterCalls, 0);
  assert.strictEqual(case1.totalAdapterCalls, 0);
  assert.strictEqual(case1.observationsProduced, 0);
  assert.strictEqual(case1.repositorySaveRunCalls, 0);
  assert.strictEqual(case1.repositoryGetRunCalls, 0);
  assert.strictEqual(case1.repositoryRecordCount, 0);
  assert.strictEqual(case1.persistedRecord, null);
  assert.strictEqual(case1.reloadVerified, false);
  const c1Robots = case1.execResult.probes.find(p => p.safeKind === 'http.robots.inspect');
  const c1SecTxt = case1.execResult.probes.find(p => p.safeKind === 'http.security_txt.inspect');
  assert.ok(c1Robots, 'Case 1: robots probe must be present');
  assert.ok(c1SecTxt, 'Case 1: security.txt probe must be present');
  assert.strictEqual(c1Robots.status, 'failed');
  assert.strictEqual(c1Robots.error?.code, 'batch_preflight_aborted');
  assert.strictEqual(c1SecTxt.status, 'blocked');
  assert.strictEqual(c1SecTxt.error?.code, 'policy_blocked');
  assert.strictEqual(case1.repositoryListRunsCalls, 0);
  console.log('  [+] Case 1 (allowed then denied): preflight_denied correctly enforced.');
  console.log(`      Case 1 Counters - robots: ${case1.robotsAdapterCalls}, sec: ${case1.securityTxtAdapterCalls}, total: ${case1.totalAdapterCalls}, obs: ${case1.observationsProduced}, save: ${case1.repositorySaveRunCalls}, get: ${case1.repositoryGetRunCalls}, list: ${case1.repositoryListRunsCalls}, records: ${case1.repositoryRecordCount}`);
  console.log(`      Case 1 Probes - probe1 status: ${c1Robots.status}/${c1Robots.error?.code}, probe2 status: ${c1SecTxt.status}/${c1SecTxt.error?.code}`);

  // Case 2: denied (robots by scope permission), allowed (security.txt)
  const case2Decision = establishDecisionOrThrow({
    ...validReq,
    scopeGrant: buildAuthorizedScopeGrant({}, {}, { deniedPathPatterns: [{ match: 'exact', pathTemplate: '/robots.txt' }] })
  }, '2026-07-05T12:00:00.000Z');
  const case2 = await runInstrumentedBatch(
    [{ family: 'document', probe: 'http.robots.inspect' }, { family: 'document', probe: 'http.security_txt.inspect' }],
    case2Decision,
    ['robots', 'securityTxt']
  );
  assert.strictEqual(case2.execResult.status, 'failed');
  assert.strictEqual(case2.execResult.disposition, 'preflight_denied');
  assert.strictEqual(case2.robotsAdapterCalls, 0);
  assert.strictEqual(case2.securityTxtAdapterCalls, 0);
  assert.strictEqual(case2.totalAdapterCalls, 0);
  assert.strictEqual(case2.observationsProduced, 0);
  assert.strictEqual(case2.repositorySaveRunCalls, 0);
  assert.strictEqual(case2.repositoryGetRunCalls, 0);
  assert.strictEqual(case2.repositoryRecordCount, 0);
  assert.strictEqual(case2.persistedRecord, null);
  assert.strictEqual(case2.reloadVerified, false);
  const c2Robots = case2.execResult.probes.find(p => p.safeKind === 'http.robots.inspect');
  const c2SecTxt = case2.execResult.probes.find(p => p.safeKind === 'http.security_txt.inspect');
  assert.ok(c2Robots, 'Case 2: robots probe must be present');
  assert.ok(c2SecTxt, 'Case 2: security.txt probe must be present');
  assert.strictEqual(c2Robots.status, 'blocked');
  assert.strictEqual(c2Robots.error?.code, 'policy_blocked');
  assert.strictEqual(c2SecTxt.status, 'failed');
  assert.strictEqual(c2SecTxt.error?.code, 'batch_preflight_aborted');
  assert.strictEqual(case2.repositoryListRunsCalls, 0);
  console.log('  [+] Case 2 (denied then allowed): preflight_denied correctly enforced.');
  console.log(`      Case 2 Counters - robots: ${case2.robotsAdapterCalls}, sec: ${case2.securityTxtAdapterCalls}, total: ${case2.totalAdapterCalls}, obs: ${case2.observationsProduced}, save: ${case2.repositorySaveRunCalls}, get: ${case2.repositoryGetRunCalls}, list: ${case2.repositoryListRunsCalls}, records: ${case2.repositoryRecordCount}`);
  console.log(`      Case 2 Probes - probe1 status: ${c2Robots.status}/${c2Robots.error?.code}, probe2 status: ${c2SecTxt.status}/${c2SecTxt.error?.code}`);

  // Case 3: allowed (robots) + supported allowed missing adapter (security.txt)
  const case3 = await runInstrumentedBatch(
    [{ family: 'document', probe: 'http.robots.inspect' }, { family: 'document', probe: 'http.security_txt.inspect' }],
    validDecision,
    ['robots'] // Miss securityTxt adapter
  );
  assert.strictEqual(case3.execResult.status, 'failed');
  assert.strictEqual(case3.execResult.disposition, 'preflight_denied');
  assert.strictEqual(case3.robotsAdapterCalls, 0);
  assert.strictEqual(case3.securityTxtAdapterCalls, 0);
  assert.strictEqual(case3.totalAdapterCalls, 0);
  assert.strictEqual(case3.observationsProduced, 0);
  assert.strictEqual(case3.repositorySaveRunCalls, 0);
  assert.strictEqual(case3.repositoryGetRunCalls, 0);
  assert.strictEqual(case3.repositoryRecordCount, 0);
  assert.strictEqual(case3.persistedRecord, null);
  assert.strictEqual(case3.reloadVerified, false);
  const c3Robots = case3.execResult.probes.find(p => p.safeKind === 'http.robots.inspect');
  const c3SecTxt = case3.execResult.probes.find(p => p.safeKind === 'http.security_txt.inspect');
  assert.ok(c3Robots, 'Case 3: robots probe must be present');
  assert.ok(c3SecTxt, 'Case 3: security.txt probe must be present');
  assert.strictEqual(c3Robots.status, 'failed');
  assert.strictEqual(c3Robots.error?.code, 'batch_preflight_aborted');
  assert.strictEqual(c3SecTxt.status, 'failed');
  assert.strictEqual(c3SecTxt.error?.code, 'adapter_missing');
  assert.strictEqual(case3.repositoryListRunsCalls, 0);
  console.log('  [+] Case 3 (allowed + supported missing adapter): preflight_denied correctly enforced.');
  console.log(`      Case 3 Counters - robots: ${case3.robotsAdapterCalls}, sec: ${case3.securityTxtAdapterCalls}, total: ${case3.totalAdapterCalls}, obs: ${case3.observationsProduced}, save: ${case3.repositorySaveRunCalls}, get: ${case3.repositoryGetRunCalls}, list: ${case3.repositoryListRunsCalls}, records: ${case3.repositoryRecordCount}`);
  console.log(`      Case 3 Probes - probe1 status: ${c3Robots.status}/${c3Robots.error?.code}, probe2 status: ${c3SecTxt.status}/${c3SecTxt.error?.code}`);

  // Case 4: unsupported probe + otherwise allowed supported probe
  const case4 = await runInstrumentedBatch(
    [
      { family: 'document', probe: 'http.unsupported.inspect' }, 
      { family: 'document', probe: 'http.robots.inspect' }
    ],
    validDecision,
    ['robots', 'securityTxt']
  );
  assert.strictEqual(case4.execResult.status, 'failed');
  assert.strictEqual(case4.execResult.disposition, 'preflight_denied');
  assert.strictEqual(case4.robotsAdapterCalls, 0);
  assert.strictEqual(case4.securityTxtAdapterCalls, 0);
  assert.strictEqual(case4.totalAdapterCalls, 0);
  assert.strictEqual(case4.observationsProduced, 0);
  assert.strictEqual(case4.repositorySaveRunCalls, 0);
  assert.strictEqual(case4.repositoryGetRunCalls, 0);
  assert.strictEqual(case4.repositoryRecordCount, 0);
  assert.strictEqual(case4.persistedRecord, null);
  assert.strictEqual(case4.reloadVerified, false);
  assert.strictEqual(case4.execResult.probes[0].error?.code, 'unsupported_probe');
  assert.strictEqual(case4.execResult.probes[1].error?.code, 'batch_preflight_aborted');
  assert.strictEqual(case4.repositoryListRunsCalls, 0);
  console.log('  [+] Case 4 (unsupported + allowed): preflight_denied correctly enforced.');
  console.log(`      Case 4 Counters - robots: ${case4.robotsAdapterCalls}, sec: ${case4.securityTxtAdapterCalls}, total: ${case4.totalAdapterCalls}, obs: ${case4.observationsProduced}, save: ${case4.repositorySaveRunCalls}, get: ${case4.repositoryGetRunCalls}, list: ${case4.repositoryListRunsCalls}, records: ${case4.repositoryRecordCount}`);

  // P1 Correction 6 — Complete missing scope and target coverage
  console.log('[*] Testing exact scope and target coverage...');
  
  const runSingleInstrumented = async (decision: VerifiedAuthorizationDecision, origin: string, expectedReason: string, method?: string) => {
    let robotsAdapterCalls = 0;
    let securityAdapterCalls = 0;
    let saveRunCalls = 0;
    let getRunCalls = 0;
    let listRunsCalls = 0;
    let recordCount = 0;

    const req: ActiveReconOriginRunRequest = {
      contractVersion: 'active-recon-origin-run/v1',
      evaluatedAt: '2026-07-05T12:00:00.000Z',
      verifiedAuthorizationDecision: decision,
      origin,
      probes: [{ family: 'document', probe: 'http.robots.inspect' }],
    };
    const localRepo: ActiveReconRunRepository = {
      async saveRun(record: PersistedActiveReconRunRecord) { saveRunCalls++; recordCount++; return record; },
      async getRun() { getRunCalls++; return null; },
      async listRuns() { listRunsCalls++; return []; }
    };
    const localAdapters: ActiveReconDocumentProbeAdapters = {
      robots: { async probe() { robotsAdapterCalls++; return [{ kind: 'robots_metadata', safeSummary: 'test', confidence: 'high' }]; } },
      securityTxt: { async probe() { securityAdapterCalls++; return []; } }
    };
    const execResult = await runActiveReconOriginProbes(req, localAdapters);
    const persistResult = await executeAndPersistActiveReconOriginRun({ request: req, adapters: localAdapters, repository: localRepo });
    
    assert.strictEqual(execResult.status, 'failed');
    assert.strictEqual(execResult.disposition, 'preflight_denied');
    assert.strictEqual(persistResult.status, 'failed');
    assert.strictEqual(persistResult.persistenceErrors.some(e => e.code === 'preflight_denied_no_persistence'), true);
    assert.strictEqual(robotsAdapterCalls, 0);
    assert.strictEqual(securityAdapterCalls, 0);
    assert.strictEqual(robotsAdapterCalls + securityAdapterCalls, 0);
    assert.strictEqual(execResult.observations.length, 0);
    assert.strictEqual(saveRunCalls, 0);
    assert.strictEqual(getRunCalls, 0);
    assert.strictEqual(listRunsCalls, 0);
    assert.strictEqual(recordCount, 0);
    assert.strictEqual(persistResult.persistedRecord, null);
    assert.strictEqual(persistResult.reloadVerified, false);

    const expectedStatus = expectedReason === 'policy_blocked' ? 'blocked' : 'failed';
    if (expectedReason === 'invalid_origin' || expectedReason === 'empty_probe_set') {
      assert.strictEqual(execResult.runErrors[0].code, expectedReason);
    } else {
      assert.strictEqual(execResult.probes[0].status, expectedStatus);
      assert.strictEqual(execResult.probes[0].error?.code, expectedReason);
    }
  };

  // endpointDiscovery false
  console.log('Classif:', JSON.stringify(validReq.scopeGrant.classification));
  const noEndpointDiscoveryDec = establishDecisionOrThrow({ ...validReq, scopeGrant: { ...validReq.scopeGrant, permissionSet: { ...validReq.scopeGrant.permissionSet, endpointDiscovery: false }} } as EstablishVerifiedAuthorizationDecisionRequest, '2026-07-05T12:00:00.000Z');
  await runSingleInstrumented(noEndpointDiscoveryDec, 'https://example.com', 'policy_blocked');
  console.log('  [+] endpointDiscovery false: denied correctly.');

  // wrong origin
  await runSingleInstrumented(validDecision, 'https://evil.com', 'policy_blocked');
  console.log('  [+] wrong origin: denied correctly.');

  // wrong explicit port (distinct from wrong origin)
  await runSingleInstrumented(validDecision, 'https://example.com:9999', 'policy_blocked');

  // non-canonical origin (has path)
  await runSingleInstrumented(validDecision, 'https://example.com/path', 'invalid_origin');

  // trailing slash
  await runSingleInstrumented(validDecision, 'https://example.com/', 'invalid_origin');
  console.log('  [+] wrong port (same origin, different port): denied correctly.');

  // wrong HTTP method
  // Note: GET is standard for HTTP probes, but if we restricted to POST:
  const caseMethodDeniedDec = establishDecisionOrThrow({ ...validReq, scopeGrant: { ...validReq.scopeGrant, boundaries: { ...validReq.scopeGrant.boundaries, allowedMethods: ['POST'] }} } as EstablishVerifiedAuthorizationDecisionRequest, '2026-07-05T12:00:00.000Z');
  await runSingleInstrumented(caseMethodDeniedDec, 'https://example.com', 'policy_blocked');
  console.log('  [+] wrong HTTP method: denied correctly.');

  // explicitly denied path
  const deniedPathDec = establishDecisionOrThrow({ ...validReq, scopeGrant: { ...validReq.scopeGrant, boundaries: { ...validReq.scopeGrant.boundaries, deniedPathPatterns: [{ match: 'exact', pathTemplate: '/robots.txt' }] }} } as EstablishVerifiedAuthorizationDecisionRequest, '2026-07-05T12:00:00.000Z');
  await runSingleInstrumented(deniedPathDec, 'https://example.com', 'policy_blocked');
  console.log('  [+] explicitly denied path: denied correctly.');

  // outside allowed path prefix
  const pathPrefixDec = establishDecisionOrThrow({ ...validReq, scopeGrant: { ...validReq.scopeGrant, boundaries: { ...validReq.scopeGrant.boundaries, allowedPathPatterns: [{ match: 'prefix', pathTemplate: '/api' }] }} } as EstablishVerifiedAuthorizationDecisionRequest, '2026-07-05T12:00:00.000Z');
  await runSingleInstrumented(pathPrefixDec, 'https://example.com', 'policy_blocked');
  console.log('  [+] outside allowed path prefix: denied correctly.');

  // invalid target URL
  await runSingleInstrumented(validDecision, 'not-a-url', 'invalid_origin');
  console.log('  [+] invalid target URL: denied correctly.');


  // invalid target URL
  const invalidTargetReq = buildMalformedActiveReconOriginRunRequest({
    contractVersion: 'active-recon-origin-run/v1',
    evaluatedAt: '2026-07-05T12:00:00.000Z',
    verifiedAuthorizationDecision: validDecision,
    origin: 'not-a-valid-url',
    probes: [{ family: 'document', probe: 'http.robots.inspect' }]
  });
  let invalidTargetRobotsCalls = 0;
  let invalidTargetSecurityCalls = 0;
  let invalidTargetSaveCalls = 0;
  let invalidTargetGetCalls = 0;
  let invalidTargetListCalls = 0;
  let invalidTargetRecordCount = 0;
  const invalidTargetRepo: ActiveReconRunRepository = {
    async saveRun(record: PersistedActiveReconRunRecord) { invalidTargetSaveCalls++; invalidTargetRecordCount++; return record; },
    async getRun() { invalidTargetGetCalls++; return null; },
    async listRuns() { invalidTargetListCalls++; return []; }
  };
  const invalidTargetAdapters: ActiveReconDocumentProbeAdapters = {
    robots: { async probe() { invalidTargetRobotsCalls++; return []; } },
    securityTxt: { async probe() { invalidTargetSecurityCalls++; return []; } }
  };
  
  const invalidTargetExec = await runActiveReconOriginProbes(invalidTargetReq, invalidTargetAdapters);
  
  const invalidTargetPersist = await executeAndPersistActiveReconOriginRun({ request: invalidTargetReq, adapters: invalidTargetAdapters, repository: invalidTargetRepo });

  assert.strictEqual(invalidTargetExec.status, 'failed');
  assert.strictEqual(invalidTargetExec.disposition, 'preflight_denied');
  assert.strictEqual(invalidTargetPersist.status, 'failed');
  assert.strictEqual(invalidTargetPersist.persistenceErrors.some(e => e.code === 'preflight_denied_no_persistence'), true);
  assert.strictEqual(invalidTargetRobotsCalls, 0);
  assert.strictEqual(invalidTargetSecurityCalls, 0);
  assert.strictEqual(invalidTargetRobotsCalls + invalidTargetSecurityCalls, 0);
  assert.strictEqual(invalidTargetExec.observations.length, 0);
  assert.strictEqual(invalidTargetSaveCalls, 0);
  assert.strictEqual(invalidTargetGetCalls, 0);
  assert.strictEqual(invalidTargetListCalls, 0);
  assert.strictEqual(invalidTargetRecordCount, 0);
  assert.strictEqual(invalidTargetPersist.persistedRecord, null);
  assert.strictEqual(invalidTargetPersist.reloadVerified, false);
  console.log('  [+] invalid target URL: denied correctly.');
  console.log('  [+] Scope boundaries all strictly enforced.');

  // Positive Scenario A — exact origin execution (no persistence)
  console.log('[*] Testing positive Scenario A — exact origin https://example.com...');
  let scenA_robotsCalls = 0;
  let scenA_secCalls = 0;
  const scenAAdapters: ActiveReconDocumentProbeAdapters = {
    robots: { async probe() { scenA_robotsCalls++; return [{ kind: 'robots_metadata', safeSummary: 'test', confidence: 'high' }]; } },
    securityTxt: { async probe() { scenA_secCalls++; return [{ kind: 'security_txt_metadata', safeSummary: 'test', confidence: 'high' }]; } }
  };
  const scenAResult = await runActiveReconOriginProbes({
    contractVersion: 'active-recon-origin-run/v1',
    evaluatedAt: '2026-07-05T12:00:00.000Z',
    verifiedAuthorizationDecision: validDecision,
    origin: 'https://example.com',
    probes: [{ family: 'document', probe: 'http.robots.inspect' }],
  }, scenAAdapters);
  assert.strictEqual(scenAResult.status, 'completed');
  assert.strictEqual(scenAResult.disposition, 'execution_completed');
  assert.strictEqual(scenA_robotsCalls, 1);
  assert.strictEqual(scenA_secCalls, 0);
  assert.strictEqual(scenAResult.observations.length, 1);
  console.log(`  [+] Positive Scenario A — robots calls: ${scenA_robotsCalls}, security calls: ${scenA_secCalls}, observations: ${scenAResult.observations.length}, disposition: ${scenAResult.disposition}`);

  // Positive Scenario B — explicit non-default port execution (no persistence)
  console.log('[*] Testing positive Scenario B — explicit non-default port https://example.com:8443...');
  let scenB_robotsCalls = 0;
  let scenB_secCalls = 0;
  const portGrantB = buildAuthorizedScopeGrant({}, {}, { allowedOrigins: ['https://example.com:8443'] });
  const portDecisionB = establishDecisionOrThrow({ ...validReq, scopeGrant: portGrantB }, '2026-07-05T12:00:00.000Z');
  const scenBAdapters: ActiveReconDocumentProbeAdapters = {
    robots: { async probe() { scenB_robotsCalls++; return [{ kind: 'robots_metadata', safeSummary: 'test', confidence: 'high' }]; } },
    securityTxt: { async probe() { scenB_secCalls++; return [{ kind: 'security_txt_metadata', safeSummary: 'test', confidence: 'high' }]; } }
  };
  const scenBResult = await runActiveReconOriginProbes({
    contractVersion: 'active-recon-origin-run/v1',
    evaluatedAt: '2026-07-05T12:00:00.000Z',
    verifiedAuthorizationDecision: portDecisionB,
    origin: 'https://example.com:8443',
    probes: [{ family: 'document', probe: 'http.robots.inspect' }],
  }, scenBAdapters);
  assert.strictEqual(scenBResult.status, 'completed');
  assert.strictEqual(scenBResult.disposition, 'execution_completed');
  assert.strictEqual(scenB_robotsCalls, 1);
  assert.strictEqual(scenB_secCalls, 0);
  assert.strictEqual(scenBResult.observations.length, 1);
  console.log(`  [+] Positive Scenario B — robots calls: ${scenB_robotsCalls}, security calls: ${scenB_secCalls}, observations: ${scenBResult.observations.length}, disposition: ${scenBResult.disposition}`);

  // Positive Scenario C — successful execution and persistence
  console.log('[*] Testing positive Scenario C — execution and persistence...');
  let scenC_robotsCalls = 0;
  let scenC_secCalls = 0;
  let scenC_saveCalls = 0;
  let scenC_getCalls = 0;
  let scenC_listCalls = 0;
  let scenC_recordCount = 0;
  let scenC_persistedRecord: PersistedActiveReconRunRecord | null = null;
  const scenCAdapters: ActiveReconDocumentProbeAdapters = {
    robots: { async probe() { scenC_robotsCalls++; return [{ kind: 'robots_metadata', safeSummary: 'test', confidence: 'high' }]; } },
    securityTxt: { async probe() { scenC_secCalls++; return [{ kind: 'security_txt_metadata', safeSummary: 'test', confidence: 'high' }]; } }
  };
  const scenCRepo: ActiveReconRunRepository = {
    async saveRun(record: PersistedActiveReconRunRecord) { 
      scenC_saveCalls++; 
      scenC_recordCount++; 
      scenC_persistedRecord = JSON.parse(JSON.stringify(record)); 
      return JSON.parse(JSON.stringify(record)); 
    },
    async getRun() { 
      scenC_getCalls++; 
      return JSON.parse(JSON.stringify(scenC_persistedRecord)); 
    },
    async listRuns() { scenC_listCalls++; return []; }
  };
  const scenCReq: ActiveReconOriginRunRequest = {
    contractVersion: 'active-recon-origin-run/v1',
    evaluatedAt: '2026-07-05T12:00:00.000Z',
    verifiedAuthorizationDecision: validDecision,
    origin: 'https://example.com',
    probes: [{ family: 'document', probe: 'http.robots.inspect' }],
  };
  const scenCResult = await executeAndPersistActiveReconOriginRun({ request: scenCReq, adapters: scenCAdapters, repository: scenCRepo });
  assert.strictEqual(scenC_robotsCalls, 1);
  assert.strictEqual(scenC_secCalls, 0);
  assert.strictEqual(scenC_saveCalls, 1);
  assert.strictEqual(scenC_getCalls, 1);
  assert.strictEqual(scenC_recordCount, 1);
  assert.notStrictEqual(scenCResult.persistedRecord, null);
  assert.strictEqual(scenCResult.reloadVerified, true);
  
  // Independent object references
  assert.notStrictEqual(scenC_persistedRecord, scenCResult.persistedRecord, 'Saved record and reloaded record must not be same reference');
  assert.deepStrictEqual(scenC_persistedRecord, scenCResult.persistedRecord, 'Saved record and reloaded record must be structurally equal');
  
  console.log(`  [+] Scenario C — robots: ${scenC_robotsCalls}, sec: ${scenC_secCalls}, saveRun: ${scenC_saveCalls}, getRun: ${scenC_getCalls}, records: ${scenC_recordCount}, reloadVerified: ${scenCResult.reloadVerified}`);

  // P1 Correction 4 — Add adversarial repository reload tests
  console.log('[*] Testing adversarial repository mismatches...');
  
  async function runAdversarialTest(mutator: (rec: PersistedActiveReconRunRecord) => void) {
    let saved: Record<string, unknown> | null = null;
    const advRepo: ActiveReconRunRepository = {
      async saveRun(record: PersistedActiveReconRunRecord) { 
        saved = JSON.parse(JSON.stringify(record)); 
        return JSON.parse(JSON.stringify(record)); 
      },
      async getRun() { 
        const clone = JSON.parse(JSON.stringify(saved));
        mutator(clone);
        return clone;
      },
      async listRuns() { return []; }
    };
    const advResult = await executeAndPersistActiveReconOriginRun({ request: scenCReq, adapters: scenCAdapters, repository: advRepo });
    return advResult;
  }
  
  const advScanIdResult = await runAdversarialTest(rec => Object.assign(rec.provenance, { scanId: 'different_scan' }));
  assert.strictEqual(advScanIdResult.reloadVerified, false);
  assert.strictEqual(advScanIdResult.status, 'failed');
  assert.strictEqual(advScanIdResult.persistenceErrors.some(e => e.code === 'repository_reload_mismatch'), true);
  console.log('  [+] mismatched scanId rejected successfully.');
  
  const advRunIdResult = await runAdversarialTest(rec => rec.runId = 'different_run');
  assert.strictEqual(advRunIdResult.reloadVerified, false);
  assert.strictEqual(advRunIdResult.status, 'failed');
  assert.strictEqual(advRunIdResult.persistenceErrors.some(e => e.code === 'repository_reload_mismatch'), true);
  console.log('  [+] mismatched runId rejected successfully.');
  
  const advCountsResult = await runAdversarialTest(rec => rec.counts.failed = 999);
  assert.strictEqual(advCountsResult.reloadVerified, false);
  assert.strictEqual(advCountsResult.status, 'failed');
  assert.strictEqual(advCountsResult.persistenceErrors.some(e => e.code === 'repository_reload_invalid'), true);
  console.log('  [+] mismatched counts rejected successfully.');
  
  const advVersionResult = await runAdversarialTest(rec => Object.assign(rec, { recordVersion: 'active-recon-origin-run-record/v99' }));
  assert.strictEqual(advVersionResult.reloadVerified, false);
  assert.strictEqual(advVersionResult.status, 'failed');
  assert.strictEqual(advVersionResult.persistenceErrors.some(e => e.code === 'repository_reload_invalid'), true);
  console.log('  [+] invalid record version rejected successfully.');

  // P1 Correction 10 — assert derived lineage and persisted provenance equality (including scanId)
  console.log('[*] Testing persisted provenance equality (including scanId)...');
  const derived2 = deriveAuthorizationLineageRef(validDecision);
  assert.strictEqual(derived2.assessmentId, validDecision.assessmentId);
  assert.strictEqual(derived2.scanId, validDecision.scanId);
  assert.strictEqual(derived2.authorizationGrantId, validDecision.scopeGrant.grantId);
  assert.strictEqual(derived2.authorizationDecisionId, validDecision.authorizationDecisionId);
  assert.strictEqual(derived2.actorId, validDecision.authorizedActor.actorId);

  const scenCProvenance = scenC_persistedRecord!.provenance;
  assert.strictEqual(scenCProvenance.sourceBoundary, 'M39');
  assert.strictEqual(scenCProvenance.sourceContractVersion, 'active-recon-origin-run/v1');
  if (!('authorizationDecisionId' in scenCProvenance)) throw new Error('Missing authorization provenance');
  assert.strictEqual(scenCProvenance.assessmentId, derived2.assessmentId);
  assert.strictEqual(scenCProvenance.scanId, derived2.scanId);
  assert.strictEqual(scenCProvenance.authorizationGrantId, derived2.authorizationGrantId);
  assert.strictEqual(scenCProvenance.authorizationDecisionId, derived2.authorizationDecisionId);
  assert.strictEqual(scenCProvenance.actorId, derived2.actorId);
  console.log(`  [+] Persisted provenance perfectly matches derived lineage.`);
  console.log(`      assessmentId: ${scenCProvenance.assessmentId}, scanId: ${scenCProvenance.scanId}, grantId: ${scenCProvenance.authorizationGrantId}, decId: ${scenCProvenance.authorizationDecisionId}, actorId: ${scenCProvenance.actorId}`);

  // P1 Correction 7 — M39 structural preflight for malformed family selections
  console.log('[*] Testing M39 malformed-family structural preflight atomicity...');
  
  // Case: malformed family first + valid robots sibling second
  const malformedFamilyFirst = [
    { family: 'totally_unknown_family', probe: 'some.probe' },
    { family: 'document', probe: 'http.robots.inspect' }
  ];
  const mfFirstCase = await runInstrumentedBatch(malformedFamilyFirst, validDecision, ['robots']);
  assert.strictEqual(mfFirstCase.execResult.disposition, 'preflight_denied');
  assert.strictEqual(mfFirstCase.robotsAdapterCalls, 0, 'No adapter calls allowed when malformed family present');
  assert.strictEqual(mfFirstCase.observationsProduced, 0, 'No observations when malformed family present');
  assert.strictEqual(mfFirstCase.repositorySaveRunCalls, 0, 'No persistence allowed');
  assert.strictEqual(mfFirstCase.repositoryGetRunCalls, 0, 'No persistence allowed');
  assert.strictEqual(mfFirstCase.repositoryListRunsCalls, 0, 'No persistence allowed');
  assert.strictEqual(mfFirstCase.repositoryRecordCount, 0, 'No persistence allowed');
  assert.strictEqual(mfFirstCase.persistedRecord, null, 'No persistence allowed');
  assert.strictEqual(mfFirstCase.reloadVerified, false, 'No persistence allowed');
  
  assert.strictEqual(mfFirstCase.execResult.probes[0].error?.code, 'unsupported_probe');
  assert.strictEqual(mfFirstCase.execResult.probes[1].error?.code, 'batch_preflight_aborted');
  console.log('  [+] Malformed family first + valid second rejected properly');

  // Case: valid robots first + malformed family second
  const malformedFamilySecond = [
    { family: 'document', probe: 'http.robots.inspect' },
    { family: 'totally_unknown_family', probe: 'some.probe' },
  ];
  const mfSecondCase = await runInstrumentedBatch(malformedFamilySecond, validDecision, ['robots']);
  assert.strictEqual(mfSecondCase.execResult.disposition, 'preflight_denied');
  assert.strictEqual(mfSecondCase.robotsAdapterCalls, 0, 'No adapter calls allowed when malformed family present');
  assert.strictEqual(mfSecondCase.observationsProduced, 0, 'No observations when malformed family present');
  assert.strictEqual(mfSecondCase.repositorySaveRunCalls, 0, 'No persistence allowed');
  assert.strictEqual(mfSecondCase.repositoryGetRunCalls, 0, 'No persistence allowed');
  assert.strictEqual(mfSecondCase.repositoryListRunsCalls, 0, 'No persistence allowed');
  assert.strictEqual(mfSecondCase.repositoryRecordCount, 0, 'No persistence allowed');
  assert.strictEqual(mfSecondCase.persistedRecord, null, 'No persistence allowed');
  assert.strictEqual(mfSecondCase.reloadVerified, false, 'No persistence allowed');
  
  assert.strictEqual(mfSecondCase.execResult.probes[0].error?.code, 'batch_preflight_aborted');
  assert.strictEqual(mfSecondCase.execResult.probes[1].error?.code, 'unsupported_probe');
  console.log('  [+] Valid first + malformed family second rejected properly');

  // --- COMPLETE VALIDATION MATRIX ---
  console.log('[*] Testing complete validation matrix...');
  const { validatePersistedActiveReconRecord } = await import('../recon/active/ActiveReconOriginRunPersistenceService.js');

  const validV0Provenance: PersistedActiveReconRunRecord['provenance'] = {
    sourceBoundary: 'M39',
    sourceContractVersion: 'active-recon-origin-run/v0',
    persistedBy: 'M40'
  };

  const validV1Provenance: PersistedActiveReconRunRecord['provenance'] = {
    sourceBoundary: 'M39',
    sourceContractVersion: 'active-recon-origin-run/v1',
    persistedBy: 'M40',
    authorizationSource: 'fixguard-verified-authorization-decision/v0',
    authorizationDecisionId: 'dec_1',
    authorizationGrantId: 'grant_1',
    assessmentId: 'assess_1',
    scanId: 'scan_1',
    actorId: 'actor_1'
  };

  const baseValidRecord: PersistedActiveReconRunRecord = {
    recordVersion: 'active-recon-origin-run-record/v1',
    recordKind: 'active-recon.origin-run',
    runId: 'run_valid_1',
    subject: { kind: 'origin', normalizedOrigin: 'https://example.com' },
    status: 'completed',
    counts: { requested: 1, planned: 1, completed: 1, blocked: 0, candidate: 0, failed: 0 },
    classification: { finding: false, evidence: false, vulnerability: false, riskClaim: false },
    items: [{
      itemVersion: 'active-recon-document-probe-item/v0',
      family: 'document',
      safeProbeIndex: 'http.robots.inspect',
      safeKind: 'http.robots.inspect',
      status: 'completed',
      target: { normalizedOrigin: 'https://example.com' },
      observations: []
    }],
    observations: [],
    runErrors: [],
    createdAt: '2026-07-01T00:00:00.000Z',
    updatedAt: '2026-07-02T00:00:00.000Z',
    provenance: validV1Provenance
  };

  function cloneRecordForNegativeTest(record: PersistedActiveReconRunRecord): Record<string, unknown> {
    return JSON.parse(JSON.stringify(record));
  }

  function testValidation(name: string, mutator: (rec: Record<string, unknown>) => void, expectedStatus: string, expectedReason: string) {
    if (expectedStatus === 'invalid') {
      const clone = cloneRecordForNegativeTest(baseValidRecord);
      mutator(clone);
      const res = validatePersistedActiveReconRecord(clone);
      assert.strictEqual(res.status, expectedStatus, `[${name}] Expected status ${expectedStatus}, got ${res.status}`);
      assert.strictEqual(res.reasonCode, expectedReason, `[${name}] Expected reason ${expectedReason}, got ${res.reasonCode}`);
    } else {
      const clone = JSON.parse(JSON.stringify(baseValidRecord));
      mutator(clone); 
      const res = validatePersistedActiveReconRecord(clone);
      assert.strictEqual(res.status, expectedStatus, `[${name}] Expected status ${expectedStatus}, got ${res.status}`);
    }
  }

  testValidation('valid V1', (r) => { }, 'valid_v1', '');
  testValidation('valid V0', (r) => { r.recordVersion = 'active-recon-origin-run-record/v0'; r.provenance = validV0Provenance; }, 'valid_v0_legacy', '');
  
  testValidation('missing runId', (r) => delete (r as Partial<PersistedActiveReconRunRecord>).runId, 'invalid', 'invalid_record_structure');
  testValidation('missing subject', (r) => delete (r as Partial<PersistedActiveReconRunRecord>).subject, 'invalid', 'invalid_record_structure');
  testValidation('missing status', (r) => delete (r as Partial<PersistedActiveReconRunRecord>).status, 'invalid', 'invalid_record_structure');
  testValidation('missing counts', (r) => delete (r as Partial<PersistedActiveReconRunRecord>).counts, 'invalid', 'invalid_record_structure');
  testValidation('missing classification', (r) => delete (r as Partial<PersistedActiveReconRunRecord>).classification, 'invalid', 'invalid_record_structure');
  testValidation('missing items', (r) => delete (r as Partial<PersistedActiveReconRunRecord>).items, 'invalid', 'invalid_record_structure');
  testValidation('missing observations', (r) => delete (r as Partial<PersistedActiveReconRunRecord>).observations, 'invalid', 'invalid_record_structure');
  testValidation('missing runErrors', (r) => delete (r as Partial<PersistedActiveReconRunRecord>).runErrors, 'invalid', 'invalid_record_structure');
  testValidation('missing createdAt', (r) => delete (r as Partial<PersistedActiveReconRunRecord>).createdAt, 'invalid', 'invalid_record_structure');
  testValidation('missing updatedAt', (r) => delete (r as Partial<PersistedActiveReconRunRecord>).updatedAt, 'invalid', 'invalid_record_structure');
  testValidation('missing provenance', (r) => r.provenance = null as never, 'invalid', 'missing_provenance');

  testValidation('unknown top-level key', (r) => r.unknownKey = true, 'invalid', 'invalid_record_structure');
  testValidation('unknown subject key', (r) => (r.subject as Record<string, unknown>).unknown = true, 'invalid', 'invalid_record_structure');
  testValidation('invalid subject kind', (r) => (r.subject as Record<string, unknown>).kind = 'ip', 'invalid', 'invalid_record_structure');
  testValidation('invalid origin (number)', (r) => (r.subject as Record<string, unknown>).normalizedOrigin = 123, 'invalid', 'invalid_record_structure');
  testValidation('invalid origin (not-a-url)', (r) => (r.subject as Record<string, unknown>).normalizedOrigin = 'not-a-url', 'invalid', 'invalid_record_structure');
  testValidation('invalid origin (ftp)', (r) => (r.subject as Record<string, unknown>).normalizedOrigin = 'ftp://example.com', 'invalid', 'invalid_record_structure');
  testValidation('invalid origin (credentials)', (r) => (r.subject as Record<string, unknown>).normalizedOrigin = 'https://user@example.com', 'invalid', 'invalid_record_structure');
  testValidation('invalid origin (path)', (r) => (r.subject as Record<string, unknown>).normalizedOrigin = 'https://example.com/path', 'invalid', 'invalid_record_structure');
  testValidation('invalid origin (query)', (r) => (r.subject as Record<string, unknown>).normalizedOrigin = 'https://example.com?query=1', 'invalid', 'invalid_record_structure');
  testValidation('invalid origin (fragment)', (r) => (r.subject as Record<string, unknown>).normalizedOrigin = 'https://example.com#fragment', 'invalid', 'invalid_record_structure');
  testValidation('invalid origin (explicit default port)', (r) => (r.subject as Record<string, unknown>).normalizedOrigin = 'https://example.com:443', 'invalid', 'invalid_record_structure');
  testValidation('invalid origin (uppercase)', (r) => (r.subject as Record<string, unknown>).normalizedOrigin = 'HTTPS://EXAMPLE.COM', 'invalid', 'invalid_record_structure');

  testValidation('negative count', (r) => (r.counts as Record<string, unknown>).requested = -1, 'invalid', 'invalid_record_structure');
  testValidation('non-integer count', (r) => (r.counts as Record<string, unknown>).requested = 1.5, 'invalid', 'invalid_record_structure');
  testValidation('unknown classification key', (r) => (r.classification as Record<string, unknown>).unknown = true, 'invalid', 'invalid_record_structure');
  testValidation('invalid classification value', (r) => (r.classification as Record<string, unknown>).finding = true, 'invalid', 'invalid_record_structure');
  testValidation('invalid item', (r) => (r.items as unknown[])[0] = null, 'invalid', 'invalid_record_structure');
  testValidation('unknown item key', (r) => ((r.items as unknown[])[0] as Record<string, unknown>).unknown = true, 'invalid', 'invalid_record_structure');
  testValidation('invalid item status', (r) => ((r.items as unknown[])[0] as Record<string, unknown>).status = 'weird', 'invalid', 'invalid_record_structure');
  testValidation('invalid item error', (r) => ((r.items as unknown[])[0] as Record<string, unknown>).error = { code: 'weird', message: 'test' }, 'invalid', 'invalid_record_structure');
  testValidation('invalid observation', (r) => (r.observations as unknown[]).push(null), 'invalid', 'invalid_record_structure');
  testValidation('unknown observation key', (r) => (r.observations as unknown[]).push({ kind: 'robots_metadata', safeSummary: 'test', confidence: 'high', unknown: true }), 'invalid', 'invalid_record_structure');
  testValidation('invalid run error', (r) => (r.runErrors as unknown[]).push({ code: 'weird', message: 'test' }), 'invalid', 'invalid_record_structure');
  testValidation('invalid createdAt', (r) => r.createdAt = 'not-a-date', 'invalid', 'invalid_record_structure');
  testValidation('invalid createdAt (date-only)', (r) => r.createdAt = '2026-07-01', 'invalid', 'invalid_record_structure');
  testValidation('invalid createdAt (no milliseconds)', (r) => r.createdAt = '2026-07-01T00:00:00Z', 'invalid', 'invalid_record_structure');
  testValidation('invalid updatedAt', (r) => r.updatedAt = 'not-a-date', 'invalid', 'invalid_record_structure');
  testValidation('createdAt after updatedAt', (r) => { r.createdAt = '2026-07-02T00:00:00.000Z'; r.updatedAt = '2026-07-01T00:00:00.000Z'; }, 'invalid', 'invalid_record_structure');

  testValidation('missing assessmentId', (r) => delete (r.provenance as Record<string, unknown>).assessmentId, 'invalid', 'invalid_provenance_shape');
  testValidation('missing scanId', (r) => delete (r.provenance as Record<string, unknown>).scanId, 'invalid', 'invalid_provenance_shape');
  testValidation('missing authorizationGrantId', (r) => delete (r.provenance as Record<string, unknown>).authorizationGrantId, 'invalid', 'invalid_provenance_shape');
  testValidation('missing authorizationDecisionId', (r) => delete (r.provenance as Record<string, unknown>).authorizationDecisionId, 'invalid', 'invalid_provenance_shape');
  testValidation('missing actorId', (r) => delete (r.provenance as Record<string, unknown>).actorId, 'invalid', 'invalid_provenance_shape');
  testValidation('empty/whitespace IDs', (r) => (r.provenance as Record<string, unknown>).scanId = '   ', 'invalid', 'empty_provenance_id');
  testValidation('wrong authorizationSource', (r) => (r.provenance as Record<string, unknown>).authorizationSource = 'weird', 'invalid', 'wrong_authorization_source');
  testValidation('wrong provenance version', (r) => (r.provenance as Record<string, unknown>).sourceContractVersion = 'active-recon-origin-run/v0', 'invalid', 'legacy_provenance_on_v1');
  testValidation('unknown provenance key', (r) => (r.provenance as Record<string, unknown>).unknown = true, 'invalid', 'invalid_provenance_shape');
  testValidation('legacy provenance shape on V1', (r) => r.provenance = JSON.parse(JSON.stringify(validV0Provenance)), 'invalid', 'invalid_provenance_shape');

  testValidation('authorizationSource present on V0', (r) => { r.recordVersion = 'active-recon-origin-run-record/v0'; r.provenance = JSON.parse(JSON.stringify(validV0Provenance)); (r.provenance as Record<string, unknown>).authorizationSource = 'test'; }, 'invalid', 'v1_provenance_on_v0');
  testValidation('assessmentId present on V0', (r) => { r.recordVersion = 'active-recon-origin-run-record/v0'; r.provenance = JSON.parse(JSON.stringify(validV0Provenance)); (r.provenance as Record<string, unknown>).assessmentId = 'test'; }, 'invalid', 'v1_provenance_on_v0');
  testValidation('scanId present on V0', (r) => { r.recordVersion = 'active-recon-origin-run-record/v0'; r.provenance = JSON.parse(JSON.stringify(validV0Provenance)); (r.provenance as Record<string, unknown>).scanId = 'test'; }, 'invalid', 'v1_provenance_on_v0');
  testValidation('authorizationGrantId present on V0', (r) => { r.recordVersion = 'active-recon-origin-run-record/v0'; r.provenance = JSON.parse(JSON.stringify(validV0Provenance)); (r.provenance as Record<string, unknown>).authorizationGrantId = 'test'; }, 'invalid', 'v1_provenance_on_v0');
  testValidation('authorizationDecisionId present on V0', (r) => { r.recordVersion = 'active-recon-origin-run-record/v0'; r.provenance = JSON.parse(JSON.stringify(validV0Provenance)); (r.provenance as Record<string, unknown>).authorizationDecisionId = 'test'; }, 'invalid', 'v1_provenance_on_v0');
  testValidation('actorId present on V0', (r) => { r.recordVersion = 'active-recon-origin-run-record/v0'; r.provenance = JSON.parse(JSON.stringify(validV0Provenance)); (r.provenance as Record<string, unknown>).actorId = 'test'; }, 'invalid', 'v1_provenance_on_v0');
  testValidation('V1 provenance version on V0', (r) => { r.recordVersion = 'active-recon-origin-run-record/v0'; r.provenance = JSON.parse(JSON.stringify(validV0Provenance)); (r.provenance as Record<string, unknown>).sourceContractVersion = 'active-recon-origin-run/v1'; }, 'invalid', 'v1_provenance_on_v0');
  testValidation('unknown provenance key on V0', (r) => { r.recordVersion = 'active-recon-origin-run-record/v0'; r.provenance = JSON.parse(JSON.stringify(validV0Provenance)); (r.provenance as Record<string, unknown>).unknown = true; }, 'invalid', 'invalid_provenance_shape');
  
  // Semantic validations
  testValidation('counts versus item count mismatch', (r) => (r.counts as Record<string, unknown>).requested = 0, 'invalid', 'invalid_record_structure');
  testValidation('completed count mismatch', (r) => (r.counts as Record<string, unknown>).completed = 99, 'invalid', 'invalid_record_structure');
  testValidation('blocked count mismatch', (r) => (r.counts as Record<string, unknown>).blocked = 99, 'invalid', 'invalid_record_structure');
  testValidation('candidate count mismatch', (r) => (r.counts as Record<string, unknown>).candidate = 99, 'invalid', 'invalid_record_structure');
  testValidation('failed count mismatch', (r) => (r.counts as Record<string, unknown>).failed = 99, 'invalid', 'invalid_record_structure');
  testValidation('top-level observation missing', (r) => {
    ((r.items as unknown[])[0] as Record<string, unknown>).observations = [{ kind: 'robots_metadata', safeSummary: 'test', confidence: 'high' }];
  }, 'invalid', 'invalid_record_structure');
  testValidation('top-level extra observation', (r) => {
    if (Array.isArray(r.observations)) {
      Object.assign(r, { observations: [...r.observations, { kind: 'robots_metadata', safeSummary: 'test', confidence: 'high' }] });
    }
  }, 'invalid', 'invalid_record_structure');
  testValidation('completed status with contradictory failed items', (r) => {
    ((r.items as unknown[])[0] as Record<string, unknown>).status = 'failed';
    (r.counts as Record<string, unknown>).completed = 0;
    (r.counts as Record<string, unknown>).failed = 1;
  }, 'invalid', 'invalid_record_structure');
  testValidation('failed status with contradictory terminal counts', (r) => {
    r.status = 'failed';
  }, 'invalid', 'invalid_record_structure');
  console.log('  [+] Complete validation matrix passed.');

  // --- COMPLETE SAVE CORRUPTION MATRIX ---
  console.log('[*] Testing complete save corruption matrix...');
  
  async function testSaveCorruption(name: string, mutator: (rec: PersistedActiveReconRunRecord) => void, expectedError: string) {
    let saved: Record<string, unknown> | null = null;
    const repo: ActiveReconRunRepository = {
      async saveRun(record: PersistedActiveReconRunRecord) {
        if (name === 'saveRun throws') throw new Error('DB Error');
        const clone = JSON.parse(JSON.stringify(record));
        mutator(clone);
        saved = clone;
        return clone;
      },
      async getRun() { return JSON.parse(JSON.stringify(saved)); },
      async listRuns() { return []; }
    };
    const req: ActiveReconOriginRunRequest = {
      contractVersion: 'active-recon-origin-run/v1',
      evaluatedAt: '2026-07-05T12:00:00.000Z',
      verifiedAuthorizationDecision: validDecision,
      origin: 'https://example.com',
      probes: [{ family: 'document', probe: 'http.robots.inspect' }],
    };
    const adapters: ActiveReconDocumentProbeAdapters = { robots: { async probe() { return []; } } };
    const res = await executeAndPersistActiveReconOriginRun({ request: req, adapters, repository: repo });
    
    assert.strictEqual(res.status, 'failed', `[${name}] Expected status failed, got ${res.status}`);
    assert.strictEqual(res.reloadVerified, false, `[${name}] Expected reloadVerified false, got ${res.reloadVerified}`);
    assert.ok(res.persistenceErrors.some(e => e.code === expectedError), `[${name}] Expected error ${expectedError}, got ${JSON.stringify(res.persistenceErrors)}`);
  }

  await testSaveCorruption('saveRun throws', () => {}, 'repository_save_failed');
  await testSaveCorruption('saveRun returns structurally invalid value', r => Object.assign(r, { counts: null }), 'repository_save_result_invalid');
  await testSaveCorruption('saveRun returns a different runId', r => r.runId = 'altered', 'repository_save_result_mismatch');
  await testSaveCorruption('saveRun returns a different normalized origin', r => Object.assign(r.subject, { normalizedOrigin: 'https://altered.com' }), 'repository_save_result_mismatch');
  await testSaveCorruption('saveRun returns a different status', r => Object.assign(r, { status: 'partial' }), 'repository_save_result_invalid');
  await testSaveCorruption('saveRun returns a different count', r => Object.assign(r.counts, { failed: 9 }), 'repository_save_result_invalid'); // The counts mismatches semantics, so invalid
  await testSaveCorruption('saveRun returns a different count valid', r => { r.counts.requested = 0; r.items = []; }, 'repository_save_result_invalid'); // Semantics will fail it first
  // Actually, wait, if it fails semantics it's 'repository_save_result_invalid'. Let's do exact bypass:
  await testSaveCorruption('saveRun returns different classification', r => Object.assign(r.classification, { finding: true }), 'repository_save_result_invalid');
  await testSaveCorruption('saveRun returns different createdAt', r => { r.createdAt = '2026-08-01T00:00:00.000Z'; r.updatedAt = '2026-08-01T00:00:00.000Z'; }, 'repository_save_result_mismatch');
  await testSaveCorruption('saveRun returns different updatedAt', r => Object.assign(r, { updatedAt: '2026-10-01T00:00:00.000Z' }), 'repository_save_result_mismatch');
  await testSaveCorruption('saveRun returns a different item', r => Object.assign(r.items[0].target, { normalizedOrigin: 'https://altered.com' }), 'repository_save_result_mismatch');
  await testSaveCorruption('saveRun returns a different item error', r => {
    r.items[0].error = { code: 'runner_failed', message: 'test' };
    r.items[0].status = 'failed';
    r.counts.completed = 0;
    r.counts.failed = 1;
    r.status = 'failed';
  }, 'repository_save_result_mismatch');
  await testSaveCorruption('saveRun returns a different observation', r => (r.observations as unknown[]).push({ kind: 'robots_metadata', safeSummary: 'test', confidence: 'high' }), 'repository_save_result_invalid'); // Semantics: top level observation requires corresponding item observation
  await testSaveCorruption('saveRun returns a different observation valid', r => {
    Object.assign(r.items[0].observations, [...r.items[0].observations, { kind: 'robots_metadata', safeSummary: 'test', confidence: 'high' }]);
    (r.observations as unknown[]).push({ kind: 'robots_metadata', safeSummary: 'test', confidence: 'high' });
  }, 'repository_save_result_mismatch');
  await testSaveCorruption('saveRun returns a different run error', r => Object.assign(r.runErrors, [ { code: 'runner_failed', message: 'test' } ]), 'repository_save_result_invalid');
  await testSaveCorruption('saveRun returns a different assessmentId', r => Object.assign(r.provenance, { assessmentId: 'altered' }), 'repository_save_result_mismatch');
  await testSaveCorruption('saveRun returns a different scanId', r => Object.assign(r.provenance, { scanId: 'altered' }), 'repository_save_result_mismatch');
  await testSaveCorruption('saveRun returns a different authorizationGrantId', r => Object.assign(r.provenance, { authorizationGrantId: 'altered' }), 'repository_save_result_mismatch');
  await testSaveCorruption('saveRun returns a different authorizationDecisionId', r => Object.assign(r.provenance, { authorizationDecisionId: 'altered' }), 'repository_save_result_mismatch');
  await testSaveCorruption('saveRun returns a different actorId', r => Object.assign(r.provenance, { actorId: 'altered' }), 'repository_save_result_mismatch');
  await testSaveCorruption('saveRun returns a different authorizationSource', r => Object.assign(r.provenance, { authorizationSource: 'altered' }), 'repository_save_result_invalid');
  await testSaveCorruption('saveRun returns a different provenance version', r => { r.recordVersion = 'active-recon-origin-run-record/v0'; r.provenance = validV0Provenance; }, 'repository_save_result_mismatch');
  console.log('  [+] Complete save corruption matrix passed.');

  // --- COMPLETE RELOAD CORRUPTION MATRIX ---
  console.log('[*] Testing complete reload corruption matrix...');
  
  async function testReloadCorruption(name: string, mutator: (rec: PersistedActiveReconRunRecord) => void, expectedError: string) {
    let saved: Record<string, unknown> | null = null;
    const repo: ActiveReconRunRepository = {
      async saveRun(record: PersistedActiveReconRunRecord) { 
        saved = JSON.parse(JSON.stringify(record)); 
        return JSON.parse(JSON.stringify(record)); 
      },
      async getRun() { 
        if (name === 'getRun returns null') return null;
        const clone = JSON.parse(JSON.stringify(saved));
        mutator(clone);
        return clone as Parameters<ActiveReconRunRepository["saveRun"]>[0];
      },
      async listRuns() { return []; }
    };
    const req: ActiveReconOriginRunRequest = {
      contractVersion: 'active-recon-origin-run/v1',
      evaluatedAt: '2026-07-05T12:00:00.000Z',
      verifiedAuthorizationDecision: validDecision,
      origin: 'https://example.com',
      probes: [{ family: 'document', probe: 'http.robots.inspect' }],
    };
    const adapters: ActiveReconDocumentProbeAdapters = { robots: { async probe() { return []; } } };
    const res = await executeAndPersistActiveReconOriginRun({ request: req, adapters, repository: repo });
    
    assert.strictEqual(res.status, 'failed', `[${name}] Expected status failed, got ${res.status}`);
    assert.strictEqual(res.reloadVerified, false, `[${name}] Expected reloadVerified false, got ${res.reloadVerified}`);
    assert.ok(res.persistenceErrors.some(e => e.code === expectedError), `[${name}] Expected error ${expectedError}, got ${JSON.stringify(res.persistenceErrors)}`);
  }

  await testReloadCorruption('getRun returns null', () => {}, 'repository_reload_missing');
  await testReloadCorruption('getRun returns invalid record', r => Object.assign(r, { counts: null }), 'repository_reload_invalid');
  await testReloadCorruption('different runId', r => r.runId = 'altered', 'repository_reload_mismatch');
  await testReloadCorruption('different subject.kind', r => Object.assign(r.subject, { kind: 'ip' }), 'repository_reload_invalid');
  await testReloadCorruption('different normalized origin', r => Object.assign(r.subject, { normalizedOrigin: 'https://altered.com' }), 'repository_reload_mismatch');
  await testReloadCorruption('different status', r => Object.assign(r, { status: 'partial' }), 'repository_reload_invalid');
  await testReloadCorruption('different count', r => Object.assign(r.counts, { failed: 9 }), 'repository_reload_invalid');
  await testReloadCorruption('different classification', r => Object.assign(r.classification, { finding: true }), 'repository_reload_invalid');
  await testReloadCorruption('different createdAt', r => { r.createdAt = '2026-08-01T00:00:00.000Z'; r.updatedAt = '2026-08-01T00:00:00.000Z'; }, 'repository_reload_mismatch');
  await testReloadCorruption('different updatedAt', r => Object.assign(r, { updatedAt: '2026-10-01T00:00:00.000Z' }), 'repository_reload_mismatch');
  await testReloadCorruption('different item', r => Object.assign(r.items[0].target, { normalizedOrigin: 'https://altered.com' }), 'repository_reload_mismatch');
  await testReloadCorruption('different item error', r => {
    r.items[0].error = { code: 'runner_failed', message: 'test' };
    r.items[0].status = 'failed';
    r.counts.completed = 0;
    r.counts.failed = 1;
    r.status = 'failed';
  }, 'repository_reload_mismatch');
  await testReloadCorruption('different observation', r => Object.assign(r.observations, [...r.observations, { kind: 'robots_metadata', safeSummary: 'test', confidence: 'high' }]), 'repository_reload_invalid');
  await testReloadCorruption('different observation valid', r => {
    (r.items[0].observations as unknown[]).push({ kind: 'robots_metadata', safeSummary: 'test', confidence: 'high' });
    (r.observations as unknown[]).push({ kind: 'robots_metadata', safeSummary: 'test', confidence: 'high' });
  }, 'repository_reload_mismatch');
  await testReloadCorruption('different run error', r => Object.assign(r.runErrors, [...r.runErrors, { code: 'runner_failed', message: 'test' }]), 'repository_reload_invalid');
  await testReloadCorruption('different assessmentId', r => Object.assign(r.provenance, { assessmentId: 'altered' }), 'repository_reload_mismatch');
  await testReloadCorruption('different scanId', r => Object.assign(r.provenance, { scanId: 'altered' }), 'repository_reload_mismatch');
  await testReloadCorruption('different grant ID', r => Object.assign(r.provenance, { authorizationGrantId: 'altered' }), 'repository_reload_mismatch');
  await testReloadCorruption('different decision ID', r => Object.assign(r.provenance, { authorizationDecisionId: 'altered' }), 'repository_reload_mismatch');
  await testReloadCorruption('different actor ID', r => Object.assign(r.provenance, { actorId: 'altered' }), 'repository_reload_mismatch');
  await testReloadCorruption('different provenance source', r => Object.assign(r.provenance, { authorizationSource: 'altered' }), 'repository_reload_invalid');
  await testReloadCorruption('different provenance version', r => { r.recordVersion = 'active-recon-origin-run-record/v0'; r.provenance = validV0Provenance; }, 'repository_reload_mismatch');
  console.log('  [+] Complete reload mismatch matrix passed.');

  console.log('--- M56A Corrective Pass Completed Successfully ---');
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
