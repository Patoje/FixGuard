/**
 * Identical bodies on the Vercel challenge wasm are not BROKEN_AUTHENTICATION.
 * /login keeps the detector's existing positive rule.
 * Hermetic transport only. No requests to other hosts.
 */
import assert from 'node:assert/strict';
import { applyFindingAutoPromotion } from '../finding-auto-promotion/FindingAutoPromotionService.js';
import type { EnrichedEvidenceDraft } from '../application/OrchestratedAssessmentContracts.js';
import { AttackPlanGeneratorService } from '../attack-planning/AttackPlanGeneratorService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type { HttpProbeRequest, HttpProbeResponse, IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import { runAuthBypassDetection } from '../detection/AuthBypassDetectionService.js';
import { runAuthBoundaryDifferentialDetection } from '../detection/AuthBoundaryDifferentialDetectionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';

const HOST = 'app.example.com';
const WASM_URL = `https://${HOST}/.well-known/vercel/security/static/challenge.v2.wasm`;
const LOGIN_URL = `https://${HOST}/login`;
const WASM_BODY = 'challenge-wasm-bytes';
const LOGIN_BODY = JSON.stringify({ role: 'member', id: 'u_1' });

function fail(error: unknown): never {
  const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function scopeGrant(): AuthorizedScopeGrant {
  const now = Date.now();
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_challenge_001',
    scanId: 'scan_challenge_001',
    issuedAt: new Date(now - 3600_000).toISOString(),
    expiresAt: new Date(now + 86400_000).toISOString(),
    subject: { targetKind: 'domain', domain: HOST },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized challenge abstention smoke',
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
      allowedDomains: [HOST],
      allowedHosts: [HOST],
      allowedOrigins: [`https://${HOST}`],
      allowedMethods: ['GET', 'HEAD'],
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

function sameHostTransport(url: string, body: string, contentType: string): IdorHttpProbeTransport {
  return async (request: HttpProbeRequest): Promise<HttpProbeResponse> => {
    const parsed = new URL(request.url);
    assert.equal(parsed.hostname, HOST);
    assert.equal(request.url, url);
    return {
      statusCode: 200,
      headers: { 'content-type': contentType },
      bodyText: body,
      responseTimeMs: 1,
    };
  };
}

async function main(): Promise<void> {
  const grant = scopeGrant();
  const decidedAt = new Date().toISOString();
  const established = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asmt_challenge_001',
      scanId: grant.scanId,
      authorizationDecisionId: 'dec_challenge_001',
      authorizedActor: { actorId: 'act_challenge', actorType: 'human' },
      decision: 'authorized',
      decidedAt,
      scopeGrant: grant,
    },
    decidedAt
  );
  if (established.status !== 'established') {
    throw new Error(`authorization was not established: ${established.reasonCode}`);
  }
  const lineage = {
    assessmentId: 'asmt_challenge_001',
    scanId: grant.scanId,
    authorizationGrantId: grant.grantId,
    authorizationDecisionId: 'dec_challenge_001',
    actorId: 'act_challenge',
  };
  const identityA = { identityId: 'user_a', headers: { authorization: 'Bearer operator_token_a' } };

  const wasmResult = await runAuthBypassDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'auth_bypass_detection_request',
    detectionId: 'det_challenge_wasm',
    ...lineage,
    endpointUrl: WASM_URL,
    method: 'GET',
    identityA,
    bypassMechanism: 'header_stripping',
    verifiedAuthorizationDecision: established.decision,
    scopeGrant: grant,
    transport: sameHostTransport(WASM_URL, WASM_BODY, 'application/wasm'),
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(wasmResult.status, 'secure_target_abstained');
  assert.equal(wasmResult.reasonCode, 'public_static_asset_identical_body');
  assert.equal(wasmResult.similarityRatio, 1);
  assert.equal(wasmResult.finding, undefined);
  assert.equal(wasmResult.evidenceDraft, undefined);
  assert.ok(wasmResult.defenseObservations && wasmResult.defenseObservations.length > 0);
  assert.ok(
    wasmResult.defenseObservations.every((obs) => obs.kind === 'defense_observation')
  );
  assert.equal(
    wasmResult.defenseObservations.some((obs) => obs.reasonCode === 'bot_challenge_body'),
    true
  );

  const boundaryCalls: string[] = [];
  const boundary = await runAuthBoundaryDifferentialDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'auth_boundary_differential_detection_request',
    detectionId: 'det_challenge_boundary',
    ...lineage,
    endpointUrl: WASM_URL,
    identityA,
    verifiedAuthorizationDecision: established.decision,
    scopeGrant: grant,
    transport: async (request) => {
      boundaryCalls.push(request.url);
      const parsed = new URL(request.url);
      assert.equal(parsed.hostname, HOST);
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/wasm' },
        bodyText: WASM_BODY,
        responseTimeMs: 1,
      };
    },
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.deepEqual(boundaryCalls, []);
  assert.equal(boundary.investigationOutcome, 'interfered');
  assert.equal(boundary.reasonCode, 'defense_observation');
  assert.ok(boundary.defenseObservations && boundary.defenseObservations.length > 0);
  assert.ok(boundary.defenseObservations.every((obs) => obs.kind === 'defense_observation'));

  const loginResult = await runAuthBypassDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'auth_bypass_detection_request',
    detectionId: 'det_challenge_login',
    ...lineage,
    endpointUrl: LOGIN_URL,
    method: 'GET',
    identityA,
    bypassMechanism: 'header_stripping',
    verifiedAuthorizationDecision: established.decision,
    scopeGrant: grant,
    transport: sameHostTransport(LOGIN_URL, LOGIN_BODY, 'application/json'),
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(loginResult.status, 'pending_human_review');
  assert.ok(loginResult.evidenceDraft);

  const loginDraft: EnrichedEvidenceDraft = {
    ...loginResult.evidenceDraft,
    differentialContext: {
      endpointUrl: LOGIN_URL,
      detectionKind: 'auth_bypass',
      bypassMechanism: loginResult.bypassMechanism,
      bodySimilarityRatio: loginResult.similarityRatio,
      baselineStatusCode: 200,
      validationStatusCode: 200,
    },
  };
  const wasmDraft: EnrichedEvidenceDraft = {
    ...loginResult.evidenceDraft,
    draftId: 'draft_challenge_wasm',
    differentialContext: {
      endpointUrl: WASM_URL,
      detectionKind: 'auth_bypass',
      bypassMechanism: 'header_stripping',
      bodySimilarityRatio: 1,
      baselineStatusCode: 200,
      validationStatusCode: 200,
    },
  };
  const promoted = applyFindingAutoPromotion({
    drafts: [wasmDraft, loginDraft],
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    targetDomain: HOST,
    actorId: lineage.actorId,
    evaluatedAt: decidedAt,
  });
  assert.equal(
    promoted.findings.some(
      (finding) =>
        finding.type === 'BROKEN_AUTHENTICATION' && finding.target.includes('challenge.v2.wasm')
    ),
    false
  );
  assert.ok(promoted.droppedDraftIds.includes('draft_challenge_wasm'));
  const loginFinding = promoted.findings.find((finding) => finding.target === LOGIN_URL);
  assert.ok(loginFinding);
  assert.equal(loginFinding.type, 'BROKEN_AUTHENTICATION');
  assert.equal(loginFinding.verificationState, 'suspected_vulnerability');

  const plans = new AttackPlanGeneratorService().generate({
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    findings: [],
    identities: [{ identityId: 'id_a', hasJwt: false }],
    lineage,
    generatedAt: decidedAt,
    surfaceHints: [
      {
        endpointUrl: WASM_URL,
        path: '/.well-known/vercel/security/static/challenge.v2.wasm',
        signalKind: 'account_boundary',
        resourceClass: 'api_or_protected',
      },
    ],
    deferredSurfaceProbes: {
      originUrl: `https://${HOST}/`,
      applicationUrls: [WASM_URL, LOGIN_URL],
      sessionFixationSuppressed: true,
      scopeGrant: grant,
    },
  }).plans;
  assert.equal(
    plans.some(
      (plan) =>
        (plan.capability === 'auth_bypass_probe' ||
          plan.capability === 'auth_boundary_differential') &&
        (plan.targetUrl ?? '').includes('vercel/security')
    ),
    false
  );
  assert.equal(
    plans.some(
      (plan) =>
        plan.status === 'ready_for_authorization' &&
        (plan.targetUrl ?? '').includes('challenge.v2.wasm')
    ),
    false
  );

  process.stdout.write('[milestone_challenge_not_finding_smoke] passed\n');
}

main().catch(fail);
