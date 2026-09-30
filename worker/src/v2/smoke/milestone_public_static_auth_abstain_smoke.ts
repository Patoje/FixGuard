/**
 * Public static assets with identical bodies must not become
 * BROKEN_AUTHENTICATION findings. App routes keep the existing rule.
 * Hermetic transport only.
 */
import assert from 'node:assert/strict';
import { applyFindingAutoPromotion } from '../finding-auto-promotion/FindingAutoPromotionService.js';
import type { EnrichedEvidenceDraft } from '../application/OrchestratedAssessmentContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type { HttpProbeRequest, HttpProbeResponse, IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import { runAuthBypassDetection } from '../detection/AuthBypassDetectionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';

const HOST = 'app.example.com';
const STATIC_URL = `https://${HOST}/_next/static/chunks/app.js`;
const APP_URL = `https://${HOST}/admin`;
const BODY = 'console.log("public")';
const APP_BODY = JSON.stringify({ role: 'admin', id: 'u_1' });

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
    grantId: 'grant_static_auth_001',
    scanId: 'scan_static_auth_001',
    issuedAt: new Date(now - 3600_000).toISOString(),
    expiresAt: new Date(now + 86400_000).toISOString(),
    subject: { targetKind: 'domain', domain: HOST },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized public-static auth abstention smoke',
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

function identicalTransport(url: string, body: string, contentType: string): IdorHttpProbeTransport {
  return async (request: HttpProbeRequest): Promise<HttpProbeResponse> => {
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
      assessmentId: 'asmt_static_auth_001',
      scanId: grant.scanId,
      authorizationDecisionId: 'dec_static_auth_001',
      authorizedActor: { actorId: 'act_static_auth', actorType: 'human' },
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
    assessmentId: 'asmt_static_auth_001',
    scanId: grant.scanId,
    authorizationGrantId: grant.grantId,
    authorizationDecisionId: 'dec_static_auth_001',
    actorId: 'act_static_auth',
  };

  const staticResult = await runAuthBypassDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'auth_bypass_detection_request',
    detectionId: 'det_static_js',
    ...lineage,
    endpointUrl: STATIC_URL,
    method: 'GET',
    identityA: { identityId: 'user_a', headers: { authorization: 'Bearer operator_token_a' } },
    bypassMechanism: 'header_stripping',
    verifiedAuthorizationDecision: established.decision,
    scopeGrant: grant,
    transport: identicalTransport(STATIC_URL, BODY, 'application/javascript'),
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(staticResult.status, 'secure_target_abstained');
  assert.equal(staticResult.reasonCode, 'public_static_asset_identical_body');
  assert.equal(staticResult.evidenceDraft, undefined);
  assert.equal(staticResult.finding, undefined);
  assert.equal(staticResult.similarityRatio, 1);

  const appResult = await runAuthBypassDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'auth_bypass_detection_request',
    detectionId: 'det_app_admin',
    ...lineage,
    endpointUrl: APP_URL,
    method: 'GET',
    identityA: { identityId: 'user_a', headers: { authorization: 'Bearer operator_token_a' } },
    bypassMechanism: 'header_stripping',
    verifiedAuthorizationDecision: established.decision,
    scopeGrant: grant,
    transport: identicalTransport(APP_URL, APP_BODY, 'application/json'),
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(appResult.status, 'pending_human_review');
  assert.ok(appResult.evidenceDraft);
  const appDraft: EnrichedEvidenceDraft = {
    ...appResult.evidenceDraft,
    differentialContext: {
      endpointUrl: APP_URL,
      detectionKind: 'auth_bypass',
      bypassMechanism: appResult.bypassMechanism,
      bodySimilarityRatio: appResult.similarityRatio,
      baselineStatusCode: 200,
      validationStatusCode: 200,
    },
  };

  const staticDraft: EnrichedEvidenceDraft = {
    ...appResult.evidenceDraft,
    draftId: 'draft_static_identical',
    differentialContext: {
      endpointUrl: STATIC_URL,
      detectionKind: 'auth_bypass',
      bypassMechanism: 'header_stripping',
      bodySimilarityRatio: 1,
      baselineStatusCode: 200,
      validationStatusCode: 200,
    },
  };

  const promoted = applyFindingAutoPromotion({
    drafts: [staticDraft, appDraft],
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    targetDomain: HOST,
    actorId: lineage.actorId,
    evaluatedAt: decidedAt,
  });
  assert.equal(
    promoted.findings.some(
      (finding) => finding.type === 'BROKEN_AUTHENTICATION' && finding.target.includes('/_next/static')
    ),
    false
  );
  assert.ok(promoted.droppedDraftIds.includes('draft_static_identical'));
  const appFinding = promoted.findings.find((finding) => finding.target === APP_URL);
  assert.ok(appFinding);
  assert.equal(appFinding.type, 'BROKEN_AUTHENTICATION');
  assert.equal(appFinding.verificationState, 'suspected_vulnerability');

  process.stdout.write('[milestone_public_static_auth_abstain_smoke] passed\n');
}

main().catch(fail);
