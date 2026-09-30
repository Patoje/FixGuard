/**
 * Etapa 2 · P3 — jsluice discovery adapter smoke (hermetic).
 */
import assert from 'node:assert/strict';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { JsLuiceAdapter, selectJsLuiceTargets, scoreJsAssetForMining } from '../recon/adapters/JsLuiceAdapter.js';
import { evaluateFindingAutoPromotion } from '../finding-auto-promotion/FindingAutoPromotionPolicy.js';
import type { EnrichedEvidenceDraft } from '../application/OrchestratedAssessmentContracts.js';

class MockProcessRunner implements ProcessRunner {
  public calls: ExecutionRequest[] = [];
  public urlsStdout = '';
  public secretsStdout = '';
  public exitCode = 0;

  async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    this.calls.push(request);
    if (request.binary !== 'jsluice') {
      return { stdout: '', stderr: '', exitCode: 127, durationMs: 1, timedOut: false };
    }
    const mode = request.args[0];
    return {
      stdout: mode === 'secrets' ? this.secretsStdout : this.urlsStdout,
      stderr: '',
      exitCode: this.exitCode,
      durationMs: 5,
      timedOut: false,
    };
  }
}

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_jsluice_001',
    scanId: 'scan_jsluice_001',
    issuedAt: '2026-09-24T12:00:00.000Z',
    expiresAt: '2026-09-25T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for jsluice discovery smoke',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: false,
      lightValidation: false,
      activeValidation: false,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: ['example.com'],
      allowedHosts: ['example.com', 'api.example.com'],
      allowedOrigins: ['https://example.com'],
      allowedMethods: ['GET'],
    },
    constraints: {
      allowLoginRequiredAreas: false,
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

async function main(): Promise<void> {
  console.log('=== P3 jsluice discovery smoke ===');
  const scopeGrant = createScopeGrant();
  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'asmt_jsluice_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_jsluice_001',
    actorId: 'act_jsluice_op',
  };
  const auth = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      authorizedActor: { actorId: lineage.actorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt: '2026-09-24T12:00:00.000Z',
      scopeGrant,
    },
    '2026-09-24T12:00:00.000Z'
  );
  if (auth.status !== 'established' || !auth.decision) {
    const msg =
      auth.status === 'failed'
        ? `${auth.reasonCode}: ${auth.safeMessage}`
        : `unexpected status ${auth.status}`;
    throw new Error(`auth failed: ${msg}`);
  }

  {
    const selected = selectJsLuiceTargets({
      inventoryUrls: [
        { url: 'https://example.com/_next/static/chunks/vendor.js' },
        { url: 'https://example.com/_next/static/chunks/framework.js' },
        { url: 'https://example.com/_next/static/chunks/app/dashboard/page-abc.js' },
        { url: 'https://example.com/index.html' },
        { url: 'https://example.com/_next/static/chunks/webpack-123.js' },
        { url: 'https://example.com/_next/static/chunks/polyfills.js' },
      ],
      maxTargets: 2,
    });
    assert.equal(selected.length, 2);
    assert.ok(
      selected[0]?.includes('/chunks/app/dashboard/'),
      `expected app chunk first, got ${selected[0]}`
    );
    assert.ok(
      !selected.some((u) => /vendor|framework|polyfills/i.test(u)),
      'vendor/framework/polyfills must lose to app when budget is tight'
    );
    console.log('[+] selectJsLuiceTargets ranking (app > vendor) OK');
  }

  {
    // Hardened ranking: CRA/Vite app hash + CDN vendor; HTML shells never selected
    const appScore = scoreJsAssetForMining(
      'https://shop.example.com/static/js/main.a1b2c3d4.js'
    );
    const vendorScore = scoreJsAssetForMining(
      'https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js'
    );
    const htmlScore = scoreJsAssetForMining('https://shop.example.com/cart');
    assert.ok(appScore > vendorScore, `app (${appScore}) must beat CDN vendor (${vendorScore})`);
    assert.ok(htmlScore === 0 || htmlScore < appScore);

    const selected = selectJsLuiceTargets({
      inventoryUrls: [
        { url: 'https://shop.example.com/cart' },
        { url: 'https://shop.example.com/index.html' },
        { url: 'https://cdn.jsdelivr.net/npm/react@18/umd/react.production.min.js' },
        { url: 'https://shop.example.com/static/js/main.a1b2c3d4.js' },
        { url: 'https://shop.example.com/_next/static/chunks/framework-abc.js' },
      ],
      maxTargets: 2,
    });
    assert.ok(
      selected.includes('https://shop.example.com/static/js/main.a1b2c3d4.js'),
      'hashed app bundle must be selected'
    );
    assert.ok(
      !selected.some((u) => u.includes('jsdelivr') || u.endsWith('.html') || u.endsWith('/cart')),
      'CDN vendor + HTML shells must not consume jsluice budget'
    );
    console.log('[+] hardened ranking + anti-shell HTML filter OK');
  }

  {
    // Coherence with W1: HTML shell IDOR drafts stay non-promoted (no sola / no invent)
    const shellDraft: EnrichedEvidenceDraft = {
      draftKind: 'non_persisted_comparison_evidence_draft',
      draftId: 'dft_jsluice_shell',
      suggestedEvidenceType: 'http_difference',
      suggestedStrength: 'weak',
      sourceComparisonId: 'cmp_jsluice_shell',
      sourceSnapshotIds: {
        baselineSnapshotId: 'snp_js_b',
        validationSnapshotId: 'snp_js_v',
      },
      requiresHumanReview: true,
      notPersisted: true,
      notARealFinding: true,
      notConfirmedEvidence: true,
      notForExternalDelivery: true,
      notM45EvidenceRecord: true,
      safeRationale: 'SPA shell noise',
      differentialContext: {
        endpointUrl: 'https://shop.example.com/a/b',
        detectionKind: 'idor_access_control',
        resourceParamName: 'b',
        baselineStatusCode: 200,
        validationStatusCode: 404,
        baselineBodyHash: 'h1',
        validationBodyHash: 'h2',
        baselineContentType: 'text/html',
        validationContentType: 'text/html',
        baselineBodyShapeKind: 'html',
        validationBodyShapeKind: 'html',
      },
    };
    assert.equal(evaluateFindingAutoPromotion(shellDraft).decision, 'keep_as_draft');
    console.log('[+] anti-shell promote coherence (IDOR HTML) OK');
  }

  {
    const selected = selectJsLuiceTargets({
      inventoryUrls: [
        { url: 'https://example.com/app.js' },
        { url: 'https://example.com/index.html' },
        { url: 'https://example.com/_next/static/chunks/main.js' },
      ],
      maxTargets: 2,
    });
    assert.equal(selected.length, 2);
    assert.ok(selected.every((u) => u.endsWith('.js') || u.includes('/_next/static/chunks/')));
    console.log('[+] selectJsLuiceTargets OK');
  }

  {
    const runner = new MockProcessRunner();
    runner.urlsStdout = [
      JSON.stringify({
        url: 'https://api.example.com/v1/users?id=1',
        queryParams: ['id'],
        bodyParams: [],
        method: 'GET',
        type: 'fetch',
      }),
      JSON.stringify({
        url: 'https://evil.out-of-scope.test/x',
        queryParams: [],
        bodyParams: [],
      }),
    ].join('\n');
    runner.secretsStdout = JSON.stringify({
      kind: 'AWSAccessKey',
      data: { key: 'AKIAIOSFODNN7EXAMPLE' },
    });

    const adapter = new JsLuiceAdapter(runner);
    const result = await adapter.discoverFromJavaScript({
      targetJsUrlOrPath: '/tmp/fixture.js',
      resolvePathsBase: 'https://example.com/',
      verifiedAuthorizationDecision: auth.decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
    });
    assert.equal(result.status, 'success');
    if (result.status !== 'success') throw new Error('expected success');
    assert.equal(result.urlObservations.length, 1);
    assert.equal(result.urlObservations[0]?.host, 'api.example.com');
    assert.equal(result.parameterObservations.length, 1);
    assert.equal(result.parameterObservations[0]?.parameterName, 'id');
    assert.equal(result.secretObservations.length, 1);
    assert.ok(result.secretObservations[0]?.redactedSecret.includes('…'));
    assert.ok(!result.secretObservations[0]?.redactedSecret.includes('AKIAIOSFODNN7EXAMPLE'));
    assert.ok(runner.calls.some((c) => c.args[0] === 'urls'));
    assert.ok(runner.calls.some((c) => c.args[0] === 'secrets'));
    console.log('[+] jsluice parse + scope filter + redact OK');
  }

  {
    const runner = new MockProcessRunner();
    const adapter = new JsLuiceAdapter(runner);
    const denied = await adapter.discoverFromJavaScript({
      targetJsUrlOrPath: 'https://127.0.0.1/app.js',
      verifiedAuthorizationDecision: auth.decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
    });
    assert.equal(denied.status, 'preflight_denied');
    console.log('[+] SSRF preflight deny OK');
  }

  console.log('=== P3 jsluice discovery smoke: ALL PASSED ===');
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
