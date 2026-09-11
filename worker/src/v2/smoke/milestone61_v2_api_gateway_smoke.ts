import assert from 'node:assert';
import process from 'node:process';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createV2App } from '../api/createV2App.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';
import { createStubOrchestrator } from './StubToolRegistry.js';
import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository.js';
import { InMemoryFormalFindingCandidateRepository } from '../finding-candidate-promotion/InMemoryFormalFindingCandidateRepository.js';
import { V2AssessmentRuntime } from '../runtime/V2AssessmentRuntime.js';
import { AssessmentApplicationService } from '../application/AssessmentApplicationService.js';
import { DefensiveReportReadinessService } from '../reporting-boundary/DefensiveReportReadinessService.js';
import {
  PersistenceConflictError,
  RecordCorruptedError,
  StaleStateError
} from '../storage/StorageErrors.js';
import {
  ReportGenerationError,
  type DefensiveAssessmentReport
} from '../reporting-boundary/DefensiveReportContracts.js';
import type { ReviewedEvidenceFormalFindingCandidate } from '../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionContracts.js';
import type { ExecutionLineage } from '../evidence/EvidenceBoundaryContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { EstablishVerifiedAuthorizationDecisionRequest } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import { isRuntimeEstablishedVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface RunningServer {
  server: Server;
  baseUrl: string;
}

async function startAppServer(compositionRoot?: V2CompositionRoot): Promise<RunningServer> {
  const app = createV2App(compositionRoot);
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}/api/v2`;
  return { server, baseUrl };
}

async function stopAppServer(running: RunningServer): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    running.server.close((err) => (err ? reject(err) : resolve()));
  });
}

function buildValidCandidate(
  candidateId: string,
  scanId: string,
  assessmentId: string
): ReviewedEvidenceFormalFindingCandidate {
  const now = new Date().toISOString();
  const lineage: ExecutionLineage = {
    assessmentId,
    scanId,
    authorizationGrantId: 'grt_m61_smoke_001',
    authorizationDecisionId: 'dec_m61_smoke_001',
    actorId: 'usr_m61_auditor',
    validationId: 'val_m61_smoke_001'
  };

  return {
    contractVersion: 'fixguard-reviewed-evidence-formal-finding-candidate/v0',
    kind: 'reviewed_evidence_formal_finding_candidate',
    candidateId,
    scanId,
    createdAt: now,
    lineage,
    sourceDraft: {
      draftId: `drf_${candidateId}`,
      sourceSelectionId: 'sel_m61_001',
      selectedCount: 1,
      candidateKind: 'reviewed_evidence_group',
      triageState: 'requires_human_triage',
      confidenceState: 'evidence_grouped_not_confirmed'
    },
    humanTriage: {
      decisionId: 'dec_triage_m61_001',
      reviewerId: 'usr_m61_auditor',
      reviewedAt: now,
      decision: 'approve_finding_candidate_promotion',
      humanApprovedPromotion: true
    },
    evidenceRefs: {
      selectedRefs: [
        {
          storeRecordId: 'str_m61_ref_001',
          evidenceId: 'evd_m61_ref_001',
          scanId,
          indicatorId: 'ind_m61_diff_001'
        }
      ],
      selectedCount: 1
    },
    observedEvidenceSummary: {
      evidenceTypeCounts: { http_difference: 1 },
      strengthCounts: { strong: 1 },
      indicatorIds: ['ind_m61_diff_001'],
      collectedAtRange: { earliest: now, latest: now },
      savedAtRange: { earliest: now, latest: now }
    },
    candidateState: {
      lifecycleState: 'formal_candidate_created',
      confirmationState: 'not_confirmed',
      reportState: 'not_reported',
      persistenceState: 'not_persisted',
      requiresFurtherHumanReview: true
    },
    storage: {
      persisted: false,
      persistedToDatabase: false,
      externalized: false
    },
    explicitNonClaims: {
      noConfirmedFinding: true,
      noConfirmedVulnerability: true,
      noExploitabilityClaim: true,
      noSeverityRiskOrImpactClaim: true,
      noRemediationAdvice: true,
      noSafeReportItemCreated: true,
      noExternalReportCreated: true,
      noNetworkExecution: true,
      noToolExecution: true,
      noPersistence: true
    },
    classification: {
      createsFormalFindingCandidate: true,
      createsConfirmedFinding: false,
      createsSafeReportItem: false,
      createsExternalReport: false,
      confirmsVulnerabilities: false,
      makesExploitabilityClaims: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      providesRemediationAdvice: false,
      persistsCandidate: false,
      persistsToDatabase: false,
      executesNetwork: false,
      executesTools: false
    }
  };
}

function buildValidScopeGrant(scanId: string): AuthorizedScopeGrant {
  const now = new Date();
  const issuedAt = new Date(now.getTime() - 10000).toISOString();
  const expiresAt = new Date(now.getTime() + 3600000).toISOString();

  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_m61_001',
    scanId,
    issuedAt,
    expiresAt,
    subject: { targetKind: 'origin', normalizedOrigin: 'https://api-test.fixguard.internal' },
    authorizationBasis: { basisKind: 'internal_asset_record', recordedBy: 'human_user', authorizationText: 'M61 Authorized' },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: false,
      authenticatedTesting: false,
      lightValidation: true,
      activeValidation: false,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false
    },
    boundaries: {
      allowedOrigins: ['https://api-test.fixguard.internal'],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
      allowedPathPatterns: [{ match: 'prefix', pathTemplate: '/' }]
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
  };
}

// ---------------------------------------------------------------------------
// Main Smoke Suite
// ---------------------------------------------------------------------------

async function runMilestone61Smoke(): Promise<void> {
  console.log('=== [M61 SMOKE] V2 Application Gateway & Unified Presentation Layer ===\n');

  const activeServers: RunningServer[] = [];

  try {
    // -----------------------------------------------------------------------
    // Setup Primary Composition Root
    // -----------------------------------------------------------------------
    const assessmentRepo = new InMemoryAssessmentRepository();
    const candidateRepo = new InMemoryFormalFindingCandidateRepository();
    const orchestrator = createStubOrchestrator();
    const runtime = new V2AssessmentRuntime(assessmentRepo, orchestrator);
    const assessmentService = new AssessmentApplicationService(runtime);
    const reportService = new DefensiveReportReadinessService(candidateRepo);

    const primaryRoot = V2CompositionRoot.withDependencies({
      assessmentRepository: assessmentRepo,
      candidateRepository: candidateRepo,
      runtime,
      assessmentService,
      reportService
    });

    const primaryApp = await startAppServer(primaryRoot);
    activeServers.push(primaryApp);
    console.log(`[+] Primary V2 Express app listening on: ${primaryApp.baseUrl}`);

    // -----------------------------------------------------------------------
    // Assertion 1: Happy Path Assessment Creation (POST /assessments -> 201)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 1: POST /api/v2/assessments (Happy Path)');
    const createRes = await fetch(`${primaryApp.baseUrl}/assessments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUri: 'https://api-test.fixguard.internal' })
    });

    assert.strictEqual(createRes.status, 201, 'POST /assessments must return 201 Created');
    const createBody = await createRes.json() as Record<string, unknown>;
    assert.strictEqual(createBody.targetUri, 'https://api-test.fixguard.internal');
    assert.strictEqual(createBody.lifecycleStatus, 'initialized');
    assert.ok(typeof createBody.sessionId === 'string', 'sessionId must be returned');
    assert.strictEqual((createBody as Record<string, unknown>).binary, undefined, 'Internal binary key must not leak');
    assert.strictEqual((createBody as Record<string, unknown>).args, undefined, 'Internal args key must not leak');
    console.log(`    -> Session created: ${createBody.sessionId}`);

    const sessionId = createBody.sessionId as string;

    // -----------------------------------------------------------------------
    // Assertion 2: Happy Path Assessment Retrieval (GET /assessments/:sessionId -> 200)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 2: GET /api/v2/assessments/:sessionId (Happy Path)');
    const getRes = await fetch(`${primaryApp.baseUrl}/assessments/${sessionId}`);
    assert.strictEqual(getRes.status, 200, 'GET /assessments/:sessionId must return 200 OK');
    const getBody = await getRes.json() as Record<string, unknown>;
    assert.strictEqual(getBody.sessionId, sessionId);
    assert.strictEqual(getBody.lifecycleStatus, 'initialized');
    console.log('    -> Session details loaded successfully');

    // -----------------------------------------------------------------------
    // Assertion 3: Happy Path Start Initial Recon (POST /assessments/:sessionId/recon -> 200)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 3: POST /api/v2/assessments/:sessionId/recon (Happy Path)');
    const reconRes = await fetch(`${primaryApp.baseUrl}/assessments/${sessionId}/recon`, {
      method: 'POST'
    });
    assert.strictEqual(reconRes.status, 200, 'POST /recon must return 200 OK');
    const reconBody = await reconRes.json() as Record<string, unknown>;
    assert.strictEqual(reconBody.lifecycleStatus, 'profile_updated');
    assert.strictEqual(reconBody.evidenceCount, 1);
    console.log('    -> Initial recon executed through application service');

    // -----------------------------------------------------------------------
    // Assertion 4: Happy Path Defensive Report Generation (POST /reports -> 201)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 4: POST /api/v2/reports (Happy Path)');
    const scanId = 'scan_m61_001';
    const candidate = buildValidCandidate('cand_m61_001', scanId, sessionId);
    await candidateRepo.saveCandidate(candidate);

    const reportPayload = {
      reportId: 'rep_m61_001',
      sessionId,
      scanId,
      requestedAt: new Date().toISOString(),
      operatorSignatureId: 'sig_human_auditor_01',
      operatorVerifiedAt: new Date().toISOString(),
      operatorAttestationText: 'All findings verified against live defensive targets.'
    };

    const reportRes = await fetch(`${primaryApp.baseUrl}/reports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reportPayload)
    });

    assert.strictEqual(reportRes.status, 201, 'POST /reports must return 201 Created');
    const reportBody = await reportRes.json() as DefensiveAssessmentReport;
    assert.strictEqual(reportBody.contractVersion, 'fixguard-defensive-assessment-report/v0');
    assert.strictEqual(reportBody.kind, 'defensive_assessment_report');
    assert.strictEqual(reportBody.reportId, 'rep_m61_001');
    assert.strictEqual(reportBody.candidateCount, 1);
    assert.strictEqual(reportBody.explicitNonClaims.noConfirmedVulnerabilities, true);
    assert.strictEqual(reportBody.explicitNonClaims.noSeverityClaims, true);
    console.log('    -> Defensive Assessment Report compiled and returned');

    // -----------------------------------------------------------------------
    // Assertion 5: Error Mapping — 409 Conflict (PersistenceConflictError)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 5: Error Mapping -> 409 Conflict (PersistenceConflictError)');
    class ConflictMockReportService extends DefensiveReportReadinessService {
      public override async generateReport(): Promise<never> {
        throw new PersistenceConflictError('Report ID rep_duplicate_001 already exists in persistence store', 'rep_duplicate_001');
      }
    }
    const conflictRoot = V2CompositionRoot.withDependencies({
      reportService: new ConflictMockReportService(candidateRepo)
    });
    const conflictApp = await startAppServer(conflictRoot);
    activeServers.push(conflictApp);

    const conflictRes = await fetch(`${conflictApp.baseUrl}/reports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reportPayload)
    });

    assert.strictEqual(conflictRes.status, 409, 'PersistenceConflictError must map strictly to HTTP 409 Conflict');
    const conflictBody = await conflictRes.json() as Record<string, unknown>;
    assert.strictEqual(conflictBody.error, 'Conflict');
    assert.strictEqual(conflictBody.conflictKey, 'rep_duplicate_001');
    assert.strictEqual(conflictBody.stack, undefined, 'Stack traces must never leak');
    console.log('    -> Mapped PersistenceConflictError to 409 Conflict with sanitized payload');

    // 5b: StaleStateError -> 409 Conflict (Optimistic concurrency conflict)
    class StaleMockAssessmentService extends AssessmentApplicationService {
      public override async loadAssessment(): Promise<never> {
        throw new StaleStateError('sess_concurrent_001', 2, 1, 'Stale state detected in storage transaction');
      }
    }
    const staleRoot = V2CompositionRoot.withDependencies({
      assessmentService: new StaleMockAssessmentService(runtime)
    });
    const staleApp = await startAppServer(staleRoot);
    activeServers.push(staleApp);

    const staleRes = await fetch(`${staleApp.baseUrl}/assessments/sess_concurrent_001`);
    assert.strictEqual(staleRes.status, 409, 'StaleStateError must map strictly to HTTP 409 Conflict');
    const staleBody = await staleRes.json() as Record<string, unknown>;
    assert.strictEqual(staleBody.error, 'Conflict');
    assert.strictEqual(staleBody.message, 'Assessment session state is stale due to a concurrent update');
    assert.strictEqual(staleBody.sessionId, 'sess_concurrent_001');
    console.log('    -> Mapped StaleStateError to 409 Conflict with sanitized payload');

    // -----------------------------------------------------------------------
    // Assertion 6: Error Mapping — 404 Not Found (SessionNotFoundError)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 6: Error Mapping -> 404 Not Found (SessionNotFoundError)');
    const notFoundRes = await fetch(`${primaryApp.baseUrl}/assessments/session_does_not_exist_999`);
    assert.strictEqual(notFoundRes.status, 404, 'Non-existent session must return 404 Not Found');
    const notFoundBody = await notFoundRes.json() as Record<string, unknown>;
    assert.strictEqual(notFoundBody.error, 'NotFound');
    assert.strictEqual(notFoundBody.sessionId, 'session_does_not_exist_999');
    console.log('    -> Mapped SessionNotFoundError to 404 Not Found');

    // -----------------------------------------------------------------------
    // Assertion 7: Error Mapping — 400 Bad Request (ReportGenerationError, Closed-World & Invalid Params)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 7: Error Mapping -> 400 Bad Request');
    // 7a: Missing signature in report request
    const missingSigPayload = { ...reportPayload, operatorSignatureId: '   ' };
    const badSigRes = await fetch(`${primaryApp.baseUrl}/reports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(missingSigPayload)
    });
    assert.strictEqual(badSigRes.status, 400, 'Missing operator signature must return 400 Bad Request');
    const badSigBody = await badSigRes.json() as Record<string, unknown>;
    assert.strictEqual(badSigBody.error, 'missing_operator_signature');
    assert.strictEqual(badSigBody.stack, undefined, 'Stack trace must not leak');

    // 7b: Closed-world violation (unexpected extra key)
    const extraKeyPayload = { targetUri: 'https://api-test.fixguard.internal', maliciousKey: 'attack' };
    const extraKeyRes = await fetch(`${primaryApp.baseUrl}/assessments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(extraKeyPayload)
    });
    assert.strictEqual(extraKeyRes.status, 400, 'Unknown key must fail closed with 400 Bad Request');
    const extraKeyBody = await extraKeyRes.json() as Record<string, unknown>;
    assert.strictEqual(extraKeyBody.error, 'BadRequest');
    assert.ok((extraKeyBody.message as string).includes('unexpected field'), 'Must explain closed-world failure');

    // 7c: Malformed JSON syntax
    const malformedJsonRes = await fetch(`${primaryApp.baseUrl}/assessments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{ "targetUri": broken json'
    });
    assert.strictEqual(malformedJsonRes.status, 400, 'Malformed JSON must return 400 Bad Request');
    const malformedJsonBody = await malformedJsonRes.json() as Record<string, unknown>;
    assert.strictEqual(malformedJsonBody.error, 'BadRequest');

    // 7d: Invalid :sessionId route parameter format
    const badParamRes = await fetch(`${primaryApp.baseUrl}/assessments/invalid@session!id`);
    assert.strictEqual(badParamRes.status, 400, 'Invalid sessionId format must return 400 Bad Request');
    const badParamBody = await badParamRes.json() as Record<string, unknown>;
    assert.strictEqual(badParamBody.error, 'BadRequest');
    assert.strictEqual(badParamBody.message, 'sessionId parameter has invalid format');
    console.log('    -> Mapped validation, malformed JSON, and invalid route params to 400 Bad Request');

    // -----------------------------------------------------------------------
    // Assertion 8: Error Mapping — 403 Forbidden (RecordCorruptedError & Candidate Corruption)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 8: Error Mapping -> 403 Forbidden (RecordCorruptedError)');
    class CorruptedRecordReportService extends DefensiveReportReadinessService {
      public override async generateReport(): Promise<never> {
        throw new RecordCorruptedError('Candidate integrity checksum failed: tampered findings', 'rec_tampered_001');
      }
    }
    const corruptedRoot = V2CompositionRoot.withDependencies({
      reportService: new CorruptedRecordReportService(candidateRepo)
    });
    const corruptedApp = await startAppServer(corruptedRoot);
    activeServers.push(corruptedApp);

    const corruptedRes = await fetch(`${corruptedApp.baseUrl}/reports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reportPayload)
    });
    assert.strictEqual(corruptedRes.status, 403, 'RecordCorruptedError must map to 403 Forbidden');
    const corruptedBody = await corruptedRes.json() as Record<string, unknown>;
    assert.strictEqual(corruptedBody.error, 'Forbidden');
    assert.strictEqual(corruptedBody.recordId, 'rec_tampered_001');
    console.log('    -> Mapped RecordCorruptedError to 403 Forbidden');

    // -----------------------------------------------------------------------
    // Assertion 9: Information Disclosure Protection & 500 Sanitization
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 9: Information Disclosure Protection (Sanitized 500)');
    class DatabaseCrashReportService extends DefensiveReportReadinessService {
      public override async generateReport(): Promise<never> {
        throw new Error('Database connection lost: postgresql://admin:supersecret@10.0.0.15:5432/fixguard_db failed in pg_query()');
      }
    }
    const crashRoot = V2CompositionRoot.withDependencies({
      reportService: new DatabaseCrashReportService(candidateRepo)
    });
    const crashApp = await startAppServer(crashRoot);
    activeServers.push(crashApp);

    const crashRes = await fetch(`${crashApp.baseUrl}/reports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reportPayload)
    });

    assert.strictEqual(crashRes.status, 500, 'Unhandled infrastructure failure must map to 500 Internal Server Error');
    const rawCrashText = await crashRes.text();
    const crashBody = JSON.parse(rawCrashText) as Record<string, unknown>;

    assert.strictEqual(crashBody.error, 'InternalServerError');
    assert.strictEqual(crashBody.message, 'An unexpected error occurred');

    // Assert absolute non-leakage of internal information
    const lowerText = rawCrashText.toLowerCase();
    assert.strictEqual(lowerText.includes('database'), false, 'Response must NOT contain "database"');
    assert.strictEqual(lowerText.includes('postgres'), false, 'Response must NOT contain "postgres"');
    assert.strictEqual(lowerText.includes('supersecret'), false, 'Response must NOT contain secrets');
    assert.strictEqual(lowerText.includes('10.0.0.15'), false, 'Response must NOT contain internal IPs');
    assert.strictEqual(lowerText.includes('pg_query'), false, 'Response must NOT contain SQL query function names');
    assert.strictEqual(lowerText.includes('stack'), false, 'Response must NOT contain stack traces');
    console.log('    -> Verified strict sanitization: 500 response contains ZERO database or infra leaks');

    // -----------------------------------------------------------------------
    // Assertion 10: Runtime-Branded Authorization Decision at Request Perimeter
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 10: Runtime-Branded Authorization at Perimeter (POST /auth/decisions)');
    const authScanId = 'scan_auth_m61_001';
    const scopeGrant = buildValidScopeGrant(authScanId);

    const authPayload: EstablishVerifiedAuthorizationDecisionRequest = {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'sess_auth_001',
      scanId: authScanId,
      authorizationDecisionId: 'dec_auth_001',
      authorizedActor: {
        actorId: 'usr_sec_lead',
        actorType: 'human'
      },
      decision: 'authorized',
      decidedAt: new Date().toISOString(),
      scopeGrant
    };

    const authRes = await fetch(`${primaryApp.baseUrl}/auth/decisions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(authPayload)
    });

    assert.strictEqual(authRes.status, 201, 'Valid establishment request must return 201 Created');
    const authBody = await authRes.json() as {
      status: string;
      reasonCode: string;
      decision: { kind: string; contractVersion: string; authorizationDecisionId: string };
    };

    assert.strictEqual(authBody.status, 'established');
    assert.strictEqual(authBody.reasonCode, 'verified_authorization_decision_established');
    assert.strictEqual(authBody.decision.kind, 'verified_authorization_decision');
    assert.strictEqual(authBody.decision.authorizationDecisionId, 'dec_auth_001');

    // Structural Lookalike Defense (ADR-001):
    // Deserialized JSON received by external client is NOT in the module-private WeakSet brand.
    assert.strictEqual(
      isRuntimeEstablishedVerifiedAuthorizationDecision(authBody.decision),
      false,
      'Deserialized JSON copy must NOT carry the runtime brand (structural lookalikes must fail closed)'
    );

    // Negative case: unauthorized actor type
    const invalidActorPayload = {
      ...authPayload,
      authorizedActor: { actorId: 'bot_runner', actorType: 'machine' }
    };
    const deniedAuthRes = await fetch(`${primaryApp.baseUrl}/auth/decisions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(invalidActorPayload)
    });
    assert.strictEqual(deniedAuthRes.status, 403, 'Invalid actor must return 403 Forbidden');
    const deniedAuthBody = await deniedAuthRes.json() as Record<string, unknown>;
    assert.strictEqual(deniedAuthBody.error, 'Forbidden');
    assert.strictEqual(deniedAuthBody.reasonCode, 'actor_invalid');
    console.log('    -> Verified runtime-branded authorization minting and rejection at boundary');

    console.log('\n[✔] ALL MILESTONE 61 GATEWAY SMOKE ASSERTIONS PASSED SUCCESSFULLY.');
  } finally {
    // Cleanup all ephemeral servers
    for (const serverItem of activeServers) {
      await stopAppServer(serverItem);
    }
  }
}

// ---------------------------------------------------------------------------
// Execution Entry Point
// ---------------------------------------------------------------------------

runMilestone61Smoke()
  .then(() => {
    process.exit(0);
  })
  .catch((err: unknown) => {
    console.error('\n[FATAL] Milestone 61 Smoke Test Failed:', err);
    process.exit(1);
  });
