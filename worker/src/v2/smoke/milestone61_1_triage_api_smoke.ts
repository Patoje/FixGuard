import assert from 'node:assert';
import process from 'node:process';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createV2App } from '../api/createV2App.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';
import { createStubOrchestrator } from './StubToolRegistry.js';
import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository.js';
import { InMemoryFormalFindingCandidateRepository } from '../finding-candidate-promotion/InMemoryFormalFindingCandidateRepository.js';
import { InMemoryEvidenceDraftRepository } from '../finding-candidate-draft/InMemoryEvidenceDraftRepository.js';
import { V2AssessmentRuntime } from '../runtime/V2AssessmentRuntime.js';
import { AssessmentApplicationService } from '../application/AssessmentApplicationService.js';
import { DefensiveReportReadinessService } from '../reporting-boundary/DefensiveReportReadinessService.js';
import type { ReviewedEvidenceFindingCandidateDraft } from '../finding-candidate-draft/ReviewedEvidenceFindingCandidateDraftContracts.js';
import type { DefensiveAssessmentReport } from '../reporting-boundary/DefensiveReportContracts.js';

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

function buildValidDraft(draftId: string, scanId: string): ReviewedEvidenceFindingCandidateDraft {
  const now = new Date().toISOString();
  return {
    contractVersion: 'fixguard-reviewed-evidence-finding-candidate-draft/v0',
    kind: 'reviewed_evidence_finding_candidate_draft',
    draftId,
    scanId,
    createdAt: now,
    sourceSelection: {
      selectionId: `sel_${draftId}`,
      selectionMode: 'explicit_store_record_ids',
      selectedCount: 1,
      selectedRefs: [
        { storeRecordId: `str_${draftId}_01`, evidenceId: `evd_${draftId}_01`, scanId, indicatorId: 'ind_diff_01' }
      ]
    },
    observedEvidenceSummary: {
      evidenceTypeCounts: { http_difference: 1 },
      strengthCounts: { strong: 1 },
      indicatorIds: ['ind_diff_01'],
      collectedAtRange: { earliest: now, latest: now },
      savedAtRange: { earliest: now, latest: now }
    },
    draftTriage: {
      triageState: 'requires_human_triage',
      confidenceState: 'evidence_grouped_not_confirmed',
      humanReviewRequired: true
    },
    draftLabels: {
      candidateKind: 'reviewed_evidence_group',
      labelSource: 'closed_boundary_generated'
    },
    storage: { persisted: false, persistedToDatabase: false, externalized: false },
    explicitNonClaims: {
      noFindingCandidateCreated: true,
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
      createsFindingCandidateDraft: true,
      createsFindingCandidate: false,
      createsConfirmedFinding: false,
      createsSafeReportItem: false,
      createsExternalReport: false,
      confirmsVulnerabilities: false,
      makesExploitabilityClaims: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      providesRemediationAdvice: false,
      persistsDraft: false,
      persistsToDatabase: false,
      executesNetwork: false,
      executesTools: false
    }
  };
}

async function runMilestone61_1Smoke(): Promise<void> {
  console.log('=== [M61.1 SMOKE] Triage & Candidate Promotion Gateway Endpoints ===\n');

  const activeServers: RunningServer[] = [];

  try {
    const assessmentRepo = new InMemoryAssessmentRepository();
    const candidateRepo = new InMemoryFormalFindingCandidateRepository();
    const draftRepo = new InMemoryEvidenceDraftRepository();
    const orchestrator = createStubOrchestrator();
    const runtime = new V2AssessmentRuntime(assessmentRepo, orchestrator);
    const assessmentService = new AssessmentApplicationService(runtime);
    const reportService = new DefensiveReportReadinessService(candidateRepo);

    const compositionRoot = V2CompositionRoot.withDependencies({
      assessmentRepository: assessmentRepo,
      candidateRepository: candidateRepo,
      draftRepository: draftRepo,
      runtime,
      assessmentService,
      reportService
    });

    const appInstance = await startAppServer(compositionRoot);
    activeServers.push(appInstance);
    console.log(`[+] M61.1 V2 Express app listening on: ${appInstance.baseUrl}`);

    // -----------------------------------------------------------------------
    // Assertion 1: Create Assessment and Pre-seed Authentic Draft
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 1: Seed Assessment and Evidence Draft in backend');
    const createRes = await fetch(`${appInstance.baseUrl}/assessments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUri: 'https://triage-test.fixguard.internal' })
    });
    assert.strictEqual(createRes.status, 201);
    const createBody = await createRes.json() as Record<string, unknown>;
    const sessionId = createBody.sessionId as string;
    assert.ok(sessionId);

    const draftId = 'draft_triage_m61_001';
    const draft = buildValidDraft(draftId, sessionId);
    await draftRepo.saveDraft(draft);
    console.log(`    -> Assessment: ${sessionId}, Authentic Draft Seeded: ${draftId}`);

    // -----------------------------------------------------------------------
    // Assertion 2: GET /scans/:scanId/evidence-drafts (Happy Path)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 2: GET /api/v2/scans/:scanId/evidence-drafts');
    const listRes = await fetch(`${appInstance.baseUrl}/scans/${sessionId}/evidence-drafts`);
    assert.strictEqual(listRes.status, 200, 'Must return 200 OK');
    const listBody = await listRes.json() as { scanId: string; draftCount: number; drafts: unknown[] };
    assert.strictEqual(listBody.scanId, sessionId);
    assert.strictEqual(listBody.draftCount, 1);
    assert.strictEqual((listBody.drafts[0] as { draftId: string }).draftId, draftId);
    console.log('    -> Draft listed successfully with authentic backend state');

    // -----------------------------------------------------------------------
    // Assertion 2b: ScanId Independence (sessionId !== scanId)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 2b: ScanId Independence Test (sessionId !== scanId)');
    const distinctScanId = 'scn_beta_02';
    const distinctDraftId = 'draft_distinct_scan_001';
    const distinctDraft = buildValidDraft(distinctDraftId, distinctScanId);
    await draftRepo.saveDraft(distinctDraft);

    // Querying with distinctScanId returns distinctDraft
    const distinctListRes = await fetch(`${appInstance.baseUrl}/scans/${distinctScanId}/evidence-drafts`);
    assert.strictEqual(distinctListRes.status, 200);
    const distinctListBody = await distinctListRes.json() as { scanId: string; draftCount: number; drafts: Array<{ draftId: string; scanId: string }> };
    assert.strictEqual(distinctListBody.scanId, distinctScanId);
    assert.strictEqual(distinctListBody.draftCount, 1);
    assert.strictEqual(distinctListBody.drafts[0].draftId, distinctDraftId);
    assert.strictEqual(distinctListBody.drafts[0].scanId, distinctScanId);

    // Querying with an unrelated scanId returns empty array
    const emptyListRes = await fetch(`${appInstance.baseUrl}/scans/scn_unrelated_99/evidence-drafts`);
    assert.strictEqual(emptyListRes.status, 200);
    const emptyListBody = await emptyListRes.json() as { scanId: string; draftCount: number; drafts: unknown[] };
    assert.strictEqual(emptyListBody.draftCount, 0);

    // Malformed scanId parameter fails closed with 400 Bad Request
    const invalidScanRes = await fetch(`${appInstance.baseUrl}/scans/bad%20id!/evidence-drafts`);
    assert.strictEqual(invalidScanRes.status, 400);
    console.log('    -> Distinct scanId accurately resolved independently of session IDs');

    // -----------------------------------------------------------------------
    // Assertion 3: POST /candidates/promote (Happy Path Promotion)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 3: POST /api/v2/candidates/promote (Happy Path)');
    const candidateId = 'cand_triage_m61_001';
    const promotePayload = {
      candidateId,
      scanId: sessionId,
      draftId,
      reviewerId: 'usr_sec_analyst_01',
      triageDecisionId: 'dec_triage_001'
    };

    const promoteRes = await fetch(`${appInstance.baseUrl}/candidates/promote`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(promotePayload)
    });

    assert.strictEqual(promoteRes.status, 201, 'POST /candidates/promote must return 201 Created');
    const promoteBody = await promoteRes.json() as { status: string; reasonCode: string; candidate: { candidateId: string } };
    assert.strictEqual(promoteBody.status, 'candidate_created');
    assert.strictEqual(promoteBody.reasonCode, 'formal_finding_candidate_created');
    assert.strictEqual(promoteBody.candidate.candidateId, candidateId);
    console.log('    -> Draft successfully promoted to formal finding candidate');

    // -----------------------------------------------------------------------
    // Assertion 4: End-to-End Report Discovery of Promoted Candidate
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 4: POST /api/v2/reports discovers promoted candidate');
    const reportRes = await fetch(`${appInstance.baseUrl}/reports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        reportId: 'rep_triage_m61_001',
        sessionId,
        scanId: sessionId,
        requestedAt: new Date().toISOString(),
        operatorSignatureId: 'sig_analyst_01',
        operatorVerifiedAt: new Date().toISOString(),
        operatorAttestationText: 'All findings verified against live defensive targets.'
      })
    });

    assert.strictEqual(reportRes.status, 201, 'Report must be generated successfully');
    const reportBody = await reportRes.json() as DefensiveAssessmentReport;
    assert.strictEqual(reportBody.candidateCount, 1, 'Report must contain exactly 1 candidate promoted via API');
    assert.strictEqual(reportBody.candidates[0].candidateId, candidateId);
    console.log('    -> End-to-end integration verified: promoted candidate compiled into report');

    // -----------------------------------------------------------------------
    // Assertion 5: Anti-Fabrication Security Test (Rejection of Injected Draft)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 5: Anti-Fabrication Boundary (Reject injected draft payload)');
    const tamperedPayload = {
      candidateId: 'cand_fake_001',
      scanId: sessionId,
      draftId: 'draft_fake_001',
      reviewerId: 'usr_malicious',
      triageDecisionId: 'dec_fake',
      draft: {
        ...draft,
        injectedSeverity: 'CRITICAL',
        maliciousFinding: true
      }
    };

    const tamperedRes = await fetch(`${appInstance.baseUrl}/candidates/promote`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(tamperedPayload)
    });

    assert.strictEqual(tamperedRes.status, 400, 'Must reject request with injected draft object with 400 Bad Request');
    const tamperedBody = await tamperedRes.json() as Record<string, unknown>;
    assert.strictEqual(tamperedBody.error, 'BadRequest');
    assert.ok((tamperedBody.message as string).includes('unexpected field \'draft\''), 'Must identify draft as forbidden field');
    console.log('    -> Anti-fabrication boundary confirmed: client-supplied draft rejected fail-closed');

    // -----------------------------------------------------------------------
    // Assertion 6: Missing Draft from Backend Repository (404 Not Found)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 6: POST /candidates/promote with non-existent draftId -> 404');
    const missingDraftPayload = {
      candidateId: 'cand_missing_001',
      scanId: sessionId,
      draftId: 'draft_does_not_exist_999',
      reviewerId: 'usr_sec_analyst_01',
      triageDecisionId: 'dec_triage_002'
    };

    const missingDraftRes = await fetch(`${appInstance.baseUrl}/candidates/promote`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(missingDraftPayload)
    });

    assert.strictEqual(missingDraftRes.status, 404, 'Non-existent draft must return 404 Not Found');
    const missingDraftBody = await missingDraftRes.json() as Record<string, unknown>;
    assert.strictEqual(missingDraftBody.error, 'NotFound');
    console.log('    -> Missing draft handled cleanly with 404 Not Found');

    // -----------------------------------------------------------------------
    // Assertion 7: Recommendation Approval (Happy Path & Closed-World)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 7: POST /assessments/:sessionId/recommendations/approve');
    // Start initial recon
    const reconRes = await fetch(`${appInstance.baseUrl}/assessments/${sessionId}/recon`, { method: 'POST' });
    assert.strictEqual(reconRes.status, 200, 'POST /recon must succeed');

    // Run intelligence via runtime to populate pending recommendations
    const intelState = await runtime.runIntelligence(sessionId);
    assert.ok(intelState.pendingRecommendations.length > 0, 'Intelligence should yield pending recommendations in stub');
    const recommendationId = intelState.pendingRecommendations[0].id;

    // Approve recommendation
    const approveRes = await fetch(`${appInstance.baseUrl}/assessments/${sessionId}/recommendations/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        recommendationId,
        operatorId: 'op_human_lead_01'
      })
    });
    assert.strictEqual(approveRes.status, 200, 'Must return 200 OK on successful recommendation approval');
    const approveBody = await approveRes.json() as { approvedRequestCount: number };
    assert.strictEqual(approveBody.approvedRequestCount, 1);
    console.log('    -> Recommendation approved successfully through application service');

    // 7b: Closed-world rejection of extra key in approve
    const extraKeyApproveRes = await fetch(`${appInstance.baseUrl}/assessments/${sessionId}/recommendations/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        recommendationId,
        operatorId: 'op_human_lead_01',
        injectedPayload: 'malicious'
      })
    });
    assert.strictEqual(extraKeyApproveRes.status, 400, 'Must reject unexpected keys with 400 Bad Request');
    console.log('    -> Closed-world validation on recommendation approval confirmed');

    // -----------------------------------------------------------------------
    // Assertion 8: Duplicate Candidate Conflict (409 Conflict)
    // -----------------------------------------------------------------------
    console.log('[*] Assertion 8: POST /candidates/promote with duplicate candidateId -> 409 Conflict');
    // Seed second draft
    const secondDraftId = 'draft_second_001';
    await draftRepo.saveDraft(buildValidDraft(secondDraftId, sessionId));

    // Promote with same candidateId as Assertion 3
    const dupRes = await fetch(`${appInstance.baseUrl}/candidates/promote`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        candidateId, // duplicate!
        scanId: sessionId,
        draftId: secondDraftId,
        reviewerId: 'usr_sec_analyst_01',
        triageDecisionId: 'dec_triage_003'
      })
    });
    assert.strictEqual(dupRes.status, 409, 'Duplicate candidateId must return 409 Conflict');
    const dupBody = await dupRes.json() as Record<string, unknown>;
    assert.strictEqual(dupBody.error, 'Conflict');
    console.log('    -> Duplicate candidate ID properly mapped to 409 Conflict');

    console.log('\n[✔] ALL MILESTONE 61.1 TRIAGE API SMOKE ASSERTIONS PASSED SUCCESSFULLY.');
  } finally {
    for (const serverItem of activeServers) {
      await stopAppServer(serverItem);
    }
  }
}

runMilestone61_1Smoke()
  .then(() => {
    process.exit(0);
  })
  .catch((err: unknown) => {
    console.error('\n[FATAL] Milestone 61.1 Smoke Test Failed:', err);
    process.exit(1);
  });
