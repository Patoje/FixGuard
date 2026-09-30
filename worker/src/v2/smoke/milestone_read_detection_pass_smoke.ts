/**
 * Phase 2 — read detection pass smoke.
 * Hermetic transports only. No public network.
 */
import assert from 'node:assert/strict';
import process from 'node:process';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import {
  ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
  type OrchestratedAssessmentRecord,
} from '../application/OrchestratedAssessmentContracts.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type {
  HttpProbeRequest,
  HttpProbeResponse,
  IdorHttpProbeTransport,
  SourcemapExposureDetectionResult,
} from '../detection/DetectionContracts.js';
import type { Finding } from '../core/Evidence.js';
import { applyFindingAutoPromotion } from '../finding-auto-promotion/FindingAutoPromotionService.js';
import { PROBE_INVENTORY_CONTRACT_VERSION } from '../investigation/ProbeInventoryContracts.js';
import type { ProbeInventory, ProbeInventoryEntry } from '../investigation/ProbeInventoryContracts.js';
import {
  retainSourcemapDetectionResult,
  runReadDetectionPass,
} from '../investigation/ReadDetectionPass.js';
import { runSourcemapExposureDetection } from '../detection/SourcemapExposureDetectionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { validateOrchestratedAssessmentRecord } from '../storage/OrchestratedAssessmentPersistenceValidation.js';

const lineage = {
  assessmentId: 'asmt_read_det_001',
  scanId: 'scan_read_det_001',
  authorizationGrantId: 'grant_read_det_001',
  authorizationDecisionId: 'dec_read_det_001',
  actorId: 'act_read_det_op',
} as const;

const STACK_TRACE = 'java.lang.NullPointerException';

function fail(error: unknown): never {
  const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function scopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: lineage.authorizationGrantId,
    scanId: lineage.scanId,
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'domain',
      domain: 'app.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized read detection pass smoke for app.example.com',
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
      allowedOrigins: ['https://app.example.com'],
      allowedHosts: ['app.example.com'],
      allowedDomains: ['app.example.com'],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
      deniedPathPatterns: [],
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

function authorize(grant: AuthorizedScopeGrant) {
  const nowIso = new Date().toISOString();
  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: lineage.assessmentId,
      scanId: grant.scanId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      authorizedActor: { actorId: lineage.actorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant: grant,
    },
    nowIso
  );
  if (authRes.status !== 'established') {
    throw new Error(`authorization was not established: ${authRes.reasonCode}`);
  }
  return authRes.decision;
}

function entry(
  origin: string,
  path: string,
  parameters: readonly string[] = []
): ProbeInventoryEntry {
  return {
    origin,
    path,
    method: 'GET',
    parameters,
    sources: ['url_discovery'],
  };
}

function inventory(entries: readonly ProbeInventoryEntry[]): ProbeInventory {
  return {
    contractVersion: PROBE_INVENTORY_CONTRACT_VERSION,
    kind: 'probe_inventory',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    authorizationGrantId: lineage.authorizationGrantId,
    authorizationDecisionId: lineage.authorizationDecisionId,
    actorId: lineage.actorId,
    entries,
  };
}

function countingTransport(
  respond: (request: HttpProbeRequest) => HttpProbeResponse
): { readonly transport: IdorHttpProbeTransport; readonly urls: () => readonly string[] } {
  const seen: string[] = [];
  const transport: IdorHttpProbeTransport = async (request) => {
    seen.push(request.url);
    return respond(request);
  };
  return {
    transport,
    urls: () => seen,
  };
}

function dnsResolver(): (host: string) => Promise<readonly string[]> {
  return async () => ['93.184.216.34'];
}

function assessmentRecord(
  findings: readonly Finding[],
  pendingEvidenceDrafts: OrchestratedAssessmentRecord['pendingEvidenceDrafts'],
  probeInventory?: ProbeInventory
): OrchestratedAssessmentRecord {
  return {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    targetDomain: 'app.example.com',
    status: 'completed',
    lineage,
    stages: [],
    timing: { startedAt: '2026-09-30T15:00:00.000Z' },
    errorCount: 0,
    warningCount: 0,
    findings,
    ...(pendingEvidenceDrafts && pendingEvidenceDrafts.length > 0
      ? { pendingEvidenceDrafts }
      : {}),
    recommendations: [],
    ...(probeInventory ? { probeInventory } : {}),
  };
}

async function main(): Promise<void> {
  const grant = scopeGrant();
  const verified = authorize(grant);
  const resolver = dnsResolver();

  {
    const calls = countingTransport((request): HttpProbeResponse => {
      const host = new URL(request.url).hostname;
      if (host !== 'app.example.com') {
        return {
          statusCode: 404,
          headers: {},
          bodyText: 'absent',
          responseTimeMs: 1,
        };
      }
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/plain' },
        bodyText: STACK_TRACE,
        responseTimeMs: 4,
      };
    });
    const storedInventory = inventory([
      entry('https://app.example.com', '/api/debug', ['q']),
    ]);
    const pass = await runReadDetectionPass({
      probeInventory: storedInventory,
      verifiedAuthorizationDecision: verified,
      scopeGrant: grant,
      lineage,
      transport: calls.transport,
      dnsResolver: resolver,
      observedGraphqlUrls: [],
    });
    assert.equal(pass.status, 'completed');
    assert.ok(pass.detectorCallCount > 0);
    assert.ok(pass.invokedDetectors.includes('security_header'));
    assert.ok(pass.invokedDetectors.includes('open_redirect'));
    assert.ok(pass.invokedDetectors.includes('information_disclosure'));
    assert.ok(pass.invokedDetectors.includes('cors_misconfiguration'));
    assert.ok(pass.invokedDetectors.includes('parameter_reflection'));
    assert.equal(pass.invokedDetectors.includes('graphql_surface'), false);
    assert.equal(pass.invokedDetectors.includes('auth_bypass'), false);
    assert.equal(pass.invokedDetectors.includes('idor_differential'), false);
    assert.ok(
      pass.skipped.some(
        (skip) =>
          skip.detector === 'idor_differential' &&
          skip.reasonCode === 'no_single_unauthenticated_read'
      )
    );
    assert.ok(
      pass.skipped.some(
        (skip) => skip.detector === 'auth_bypass' && skip.reasonCode === 'identity_a_absent'
      )
    );
    for (const url of calls.urls()) {
      const parsed = new URL(url);
      assert.equal(parsed.hostname, 'app.example.com');
      assert.notEqual(parsed.pathname, '/graphql');
      assert.notEqual(parsed.pathname, '/api/graphql');
      assert.notEqual(parsed.pathname, '/v1/graphql');
      assert.notEqual(parsed.pathname, '/query');
    }
    const disclosureDraft = pass.pendingEvidenceDrafts.find(
      (draft) => draft.differentialContext?.detectionKind === 'information_disclosure'
    );
    assert.ok(disclosureDraft);
    assert.equal(disclosureDraft.differentialContext?.disclosureKind, 'stack_trace');
    const promoted = applyFindingAutoPromotion({
      drafts: pass.pendingEvidenceDrafts,
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      targetDomain: 'app.example.com',
      actorId: lineage.actorId,
      evaluatedAt: '2026-09-30T15:10:00.000Z',
    });
    const findings = [...pass.findings, ...promoted.findings];
    const stored = findings.find(
      (finding) => finding.metadata.kind === 'information_disclosure_metadata'
    );
    assert.ok(stored);
    assert.equal(stored.verificationState, 'suspected_vulnerability');
    const record = assessmentRecord(findings, promoted.remainingDrafts, storedInventory);
    assert.equal(validateOrchestratedAssessmentRecord(record), true);
    assert.ok(
      record.findings.some((finding) => finding.metadata.kind === 'information_disclosure_metadata')
    );
  }

  {
    const calls = countingTransport(() => {
      throw new Error('transport must not run');
    });
    const pass = await runReadDetectionPass({
      probeInventory: inventory([
        entry('https://evil.example', '/secret'),
        entry('http://169.254.169.254', '/latest/meta-data'),
      ]),
      verifiedAuthorizationDecision: verified,
      scopeGrant: grant,
      lineage,
      transport: calls.transport,
      dnsResolver: resolver,
    });
    assert.equal(pass.status, 'completed');
    assert.equal(calls.urls().length, 0);
    assert.equal(pass.findings.length, 0);
    assert.equal(pass.pendingEvidenceDrafts.length, 0);
  }

  {
    const calls = countingTransport(() => {
      throw new Error('empty inventory must not call transport');
    });
    const pass = await runReadDetectionPass({
      probeInventory: inventory([]),
      verifiedAuthorizationDecision: verified,
      scopeGrant: grant,
      lineage,
      transport: calls.transport,
      dnsResolver: resolver,
    });
    assert.equal(pass.status, 'completed');
    assert.equal(pass.reasonCode, 'empty_probe_inventory');
    assert.equal(pass.detectorCallCount, 0);
    assert.equal(pass.invokedDetectors.length, 0);
    assert.equal(calls.urls().length, 0);
  }

  {
    const calls = countingTransport(() => {
      throw new Error('malformed inventory must not call transport');
    });
    const pass = await runReadDetectionPass({
      probeInventory: {
        ...inventory([entry('https://app.example.com', '/api/debug')]),
        confirmed: true,
      },
      verifiedAuthorizationDecision: verified,
      scopeGrant: grant,
      lineage,
      transport: calls.transport,
      dnsResolver: resolver,
    });
    assert.equal(pass.status, 'rejected');
    assert.equal(pass.reasonCode, 'malformed_probe_inventory');
    assert.equal(pass.detectorCallCount, 0);
    assert.equal(pass.findings.length, 0);
    assert.equal(calls.urls().length, 0);
  }

  {
    const calls = countingTransport((request) => {
      if (request.url === 'https://app.example.com/gql') {
        return {
          statusCode: 404,
          headers: {},
          bodyText: 'absent',
          responseTimeMs: 1,
        };
      }
      return {
        statusCode: 404,
        headers: {},
        bodyText: 'absent',
        responseTimeMs: 1,
      };
    });
    const pass = await runReadDetectionPass({
      probeInventory: inventory([entry('https://app.example.com', '/gql')]),
      verifiedAuthorizationDecision: verified,
      scopeGrant: grant,
      lineage,
      transport: calls.transport,
      dnsResolver: resolver,
      observedGraphqlUrls: ['https://app.example.com/gql'],
    });
    assert.ok(pass.invokedDetectors.includes('graphql_surface'));
    assert.ok(calls.urls().some((url) => new URL(url).pathname === '/gql'));
    for (const url of calls.urls()) {
      const pathname = new URL(url).pathname;
      assert.notEqual(pathname, '/graphql');
      assert.notEqual(pathname, '/api/graphql');
      assert.notEqual(pathname, '/v1/graphql');
      assert.notEqual(pathname, '/query');
    }
  }

  {
    const mapPayload = JSON.stringify({
      version: 3,
      file: 'main.js',
      sources: ['src/App.tsx'],
      names: ['render'],
      mappings: 'AAAA',
    });
    const mapUrl = 'https://app.example.com/static/main.js.map';
    const sourceJsUrl = 'https://app.example.com/static/main.js';
    const transport: IdorHttpProbeTransport = async (request): Promise<HttpProbeResponse> => {
      if (request.url === mapUrl) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: mapPayload,
          responseTimeMs: 5,
        };
      }
      return {
        statusCode: 404,
        headers: {},
        bodyText: 'absent',
        responseTimeMs: 1,
      };
    };
    const detected = await runSourcemapExposureDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'sourcemap_exposure_detection_request',
      detectionId: 'det_smap_read_pass',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      sourceJsUrl,
      jsBodyText: '//# sourceMappingURL=main.js.map',
      verifiedAuthorizationDecision: verified,
      scopeGrant: grant,
      transport,
      dnsResolver: resolver,
    });
    assert.equal(detected.status, 'observed');
    assert.equal(detected.finding, undefined);
    const retained = retainSourcemapDetectionResult(detected);
    assert.equal(retained.findings.length, 0);
    assert.equal(retained.pendingEvidenceDrafts.length, 1);
    assert.equal(retained.pendingEvidenceDrafts[0]?.differentialContext?.exposedMapUrl, mapUrl);
    assert.equal(retained.pendingEvidenceDrafts[0]?.differentialContext?.sourceJsUrl, sourceJsUrl);
    assert.equal(retained.pendingEvidenceDrafts[0]?.notARealFinding, true);
    const promoted = applyFindingAutoPromotion({
      drafts: retained.pendingEvidenceDrafts,
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      targetDomain: 'app.example.com',
      actorId: lineage.actorId,
      evaluatedAt: '2026-09-30T15:10:00.000Z',
    });
    assert.equal(promoted.findings.length, 0);
    assert.equal(promoted.remainingDrafts.length, 1);
    const record = assessmentRecord([], promoted.remainingDrafts);
    assert.equal(validateOrchestratedAssessmentRecord(record), true);
    assert.equal(
      record.pendingEvidenceDrafts?.[0]?.differentialContext?.exposedMapUrl,
      mapUrl
    );

    const supplied: Finding = {
      id: 'fnd_smap_supplied',
      type: 'INFORMATION_DISCLOSURE',
      severity: 'low',
      title: 'Detector-supplied sourcemap finding',
      description: 'Copied from the detector result without a verification upgrade',
      target: mapUrl,
      evidence: '{}',
      confidence: 0.4,
      verificationState: 'observed_anomaly',
      metadata: {
        kind: 'sourcemap_exposure_metadata',
        category: 'INFORMATION_DISCLOSURE',
        exposedMapUrl: mapUrl,
        sourceJsUrl,
        detectionSignal: 'sourcemapping_url_comment',
        observedAt: '2026-09-30T15:10:00.000Z',
      },
    };
    const withFinding: SourcemapExposureDetectionResult = {
      ...detected,
      status: 'potential_weakness',
      finding: supplied,
    };
    const kept = retainSourcemapDetectionResult(withFinding);
    assert.equal(kept.findings.length, 1);
    assert.equal(kept.findings[0], supplied);
    assert.equal(kept.findings[0]?.verificationState, 'observed_anomaly');
    assert.equal(kept.pendingEvidenceDrafts.length, 0);
  }
}

main().catch(fail);
