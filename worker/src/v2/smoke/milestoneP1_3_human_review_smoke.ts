/**
 * FixGuard V2 — Milestone P1-3 Smoke Test Suite
 *
 * Product correction: confirmed attack-valuable detections auto-promote to Findings.
 * HITL remains for leftover soft/cosmetic drafts and for AttackPlan execute.
 *
 * Verifies:
 * 1. CORS + parameter reflection with confirmed signals auto-promote to Findings.
 * 2. Soft drafts (e.g. missing security headers) remain pending for optional HITL.
 * 3. GET evidence-drafts returns leftover drafts with differential context.
 * 4. POST review approve_evidence promotes a soft draft to Finding.
 * 5. POST review reject_evidence discards a draft with 0 additional findings.
 * 6. Anti-bypass gate rejects synthetic reviewerIds with HTTP 400.
 */

import assert from 'node:assert';
import process from 'node:process';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createV2App, DEFAULT_V2_HOST } from '../api/createV2App.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import type { ReconToolAdapters } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import { SUBDOMAIN_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SubdomainDiscoveryContracts.js';
import { DNS_RESOLUTION_NON_CLAIMS } from '../recon/adapters/DnsResolutionContracts.js';
import { PORT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/PortDiscoveryContracts.js';
import { WEB_INSPECTION_NON_CLAIMS } from '../recon/adapters/WebInspectionContracts.js';
import { TLS_INSPECTION_NON_CLAIMS } from '../recon/adapters/TlsInspectionContracts.js';
import { URL_DISCOVERY_NON_CLAIMS } from '../recon/adapters/UrlDiscoveryContracts.js';
import { CONTENT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ContentDiscoveryContracts.js';
import { PARAMETER_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ParameterDiscoveryContracts.js';
import { SECRET_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SecretDiscoveryContracts.js';
import type { IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import type {
  GetEvidenceDraftsResult,
  ReviewEvidenceDraftResult,
} from '../application/OrchestratedAssessmentContracts.js';

interface RunningServer {
  server: Server;
  baseUrl: string;
  orchestratedService: OrchestratedAssessmentApplicationService;
  repository: InMemoryOrchestratedAssessmentRepository;
}

const TEST_SECRET = 'fixguard_secret_token_p1_3_test_human_review';

function createMockAdapters(): ReconToolAdapters {
  return {
    subdomainTool: {
      async discoverSubdomains(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-subdomain-discovery/v0',
          targetDomain: req.targetDomain,
          observations: [],
          explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    dnsTool: {
      async resolveDns(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-dns-resolution/v0',
          targetDomain: req.targetDomain,
          observations: [
            {
              domain: req.targetDomain,
              recordType: 'A',
              values: ['93.184.216.34'],
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    portTool: {
      async discoverPorts(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-port-discovery/v0',
          targetHostOrIp: req.targetHostOrIp,
          observations: [
            {
              host: req.targetHostOrIp,
              ip: req.targetHostOrIp,
              port: 443,
              protocol: 'tcp',
              state: 'open',
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    webTool: {
      async inspectWeb(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-web-inspection/v0',
          targetUrl: req.targetUrl,
          observations: [
            {
              url: req.targetUrl,
              method: 'GET',
              statusCode: 200,
              webServer: 'nginx/1.24.0',
              technologies: ['Nginx', 'Express'],
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    tlsTool: {
      async inspectTls(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-tls-inspection/v0',
          targetHost: req.targetHostOrUrl,
          observations: [],
          explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    urlTool: {
      async discoverUrls(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-url-discovery/v0',
          targetUrlOrDomain: req.targetUrlOrDomain,
          observations: [],
          explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    contentTool: {
      async discoverContent(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-content-discovery/v0',
          targetUrl: req.targetUrl,
          wordlistPath: req.wordlistPath,
          observations: [],
          explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    parameterTool: {
      async discoverParameters(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-parameter-discovery/v0',
          targetUrl: req.targetUrl,
          observations: [
            {
              url: req.targetUrl,
              method: 'GET',
              parameterName: 'q',
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    secretTool: {
      async scanSecrets(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-secret-discovery/v0',
          targetUrlOrPath: req.targetUrlOrPath,
          observations: [],
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
  };
}

/**
 * Mock HTTP Transport that reflects CORS origin and reflects parameter 'q'
 * to produce confirmed attack-valuable signals (auto-Findings) plus soft header gaps.
 */
const mockDetectionTransport: IdorHttpProbeTransport = async (req) => {
  const origin = req.headers['origin'];
  const urlObj = new URL(req.url);
  const qParam = urlObj.searchParams.get('q');

  const headers: Record<string, string> = {
    'content-type': 'application/json',
  };

  // CORS reflection behavior: untrusted origin reflected with credentials
  if (origin && origin.includes('untrusted')) {
    headers['access-control-allow-origin'] = origin;
    headers['access-control-allow-credentials'] = 'true';
  }

  // Parameter reflection behavior: canary in parameter q reflected in body
  let bodyText = JSON.stringify({ status: 'ok', authenticated: true });
  if (qParam) {
    bodyText = `<html><body><div>Search results for: ${qParam}</div></body></html>`;
  }

  return {
    statusCode: 200,
    headers,
    bodyText,
    responseTimeMs: 15,
  };
};


async function startTestServer(): Promise<RunningServer> {
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const reconAdapters = createMockAdapters();
  const mockAvailabilityService = new ReconToolAvailabilityService({
    async execute() {
      return {
        stdout: 'version: 1.0.0\n',
        stderr: '',
        exitCode: 0,
        durationMs: 1,
        timedOut: false,
      };
    },
  });

  const mockDnsResolver = async (host: string): Promise<string[]> => {
    return ['93.184.216.34'];
  };

  const orchestratedService = new OrchestratedAssessmentApplicationService({
    repository,
    reconAdapters,
    httpTransport: mockDetectionTransport,
    dnsResolver: mockDnsResolver,
    availabilityService: mockAvailabilityService,
  });

  const root = V2CompositionRoot.withDependencies({
    orchestratedRepository: repository,
    orchestratedService,
    availabilityService: mockAvailabilityService,
  });

  const app = createV2App(root, {
    apiSecret: TEST_SECRET,
  });

  return new Promise((resolve) => {
    const server = app.listen(0, DEFAULT_V2_HOST, () => {
      const address = server.address() as AddressInfo;
      const baseUrl = `http://${DEFAULT_V2_HOST}:${address.port}/api/v2`;
      resolve({ server, baseUrl, orchestratedService, repository });
    });
  });
}


async function runSmokeTests(): Promise<void> {
  console.log('[milestoneP1_3_human_review_smoke] Starting Milestone P1-3 smoke suite...');
  const { server, baseUrl, orchestratedService, repository } = await startTestServer();

  try {
    console.log('[milestoneP1_3_human_review_smoke] Phase 1: Launching assessment...');
    const startRes = await fetch(`${baseUrl}/orchestrated/assessments/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`,
      },
      body: JSON.stringify({
        targetDomain: 'authorized-review-target.com',
        actorId: 'usr_secops_analyst',
      }),
    });

    assert.strictEqual(startRes.status, 202, 'Start must return HTTP 202 Accepted');
    const startData = (await startRes.json()) as { assessmentId: string; scanId: string };
    const assessmentId = startData.assessmentId;
    assert(assessmentId, 'assessmentId must be returned');

    const completedRecord = await orchestratedService.awaitAssessment(assessmentId);
    assert(completedRecord, 'Assessment record must exist');
    assert.strictEqual(completedRecord.status, 'completed', 'Assessment should complete cleanly');

    const autoFindings = completedRecord.findings;
    assert(
      !autoFindings.some((f) => f.metadata.kind === 'credentialed_cors_metadata'),
      'Generic CORS must not promote credentialed_cors_metadata'
    );
    const seededPlans = await orchestratedService.getAttackPlans(assessmentId);
    const corsPlan = seededPlans.plans.find((plan) => plan.capability === 'cors_misconfiguration_probe');
    assert(corsPlan, 'Pipeline must seed a non-executing CORS plan');
    assert.equal(corsPlan.executable, false);
    assert(
      autoFindings.some(
        (f) =>
          f.metadata.kind === 'input_validation_flaw_metadata' ||
          f.type === 'INPUT_VALIDATION_FLAW' ||
          f.type === 'PARAMETER_REFLECTION'
      ),
      'Parameter reflection should be auto-promoted to autoFindings with observed_anomaly state'
    );
    assert.ok(
      autoFindings.every((f) => f.verificationState !== 'exploitability_confirmed'),
      'Auto findings must not claim exploitability_confirmed'
    );

    const pendingDrafts = completedRecord.pendingEvidenceDrafts ?? [];
    assert(
      pendingDrafts.length >= 1,
      `Expected at least 1 leftover soft draft for HITL, got ${pendingDrafts.length}`
    );
    assert(
      !pendingDrafts.some((d) => d.differentialContext?.detectionKind === 'cors_misconfiguration'),
      'CORS must not be auto-drafted by the pipeline'
    );
    assert(
      !pendingDrafts.some((d) => d.differentialContext?.detectionKind === 'parameter_reflection'),
      'Parameter reflection must not remain as pending draft after auto-promotion'
    );

    const softDrafts = pendingDrafts.filter(
      (d) =>
        d.differentialContext?.detectionKind === 'missing_security_headers' ||
        d.differentialContext?.detectionKind === 'wordpress_surface' ||
        d.differentialContext?.detectionKind === 'graphql_surface' ||
        d.differentialContext?.detectionKind === 'api_versioning_sprawl' ||
        d.differentialContext?.detectionKind === 'manifest_exposure' ||
        d.differentialContext?.detectionKind === 'information_disclosure'
    );
    assert(softDrafts.length >= 1, 'Need soft drafts for HITL approve/reject coverage');
    const approveTarget = softDrafts[0]!;

    console.log(
      `[milestoneP1_3_human_review_smoke] Phase 1: ${autoFindings.length} auto findings, ${pendingDrafts.length} leftover drafts.`
    );

    console.log('[milestoneP1_3_human_review_smoke] Phase 2: Fetching evidence drafts via API...');
    const getDraftsRes = await fetch(`${baseUrl}/orchestrated/assessments/${assessmentId}/evidence-drafts`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${TEST_SECRET}`,
      },
    });

    assert.strictEqual(getDraftsRes.status, 200, 'GET evidence-drafts must return HTTP 200');
    const draftsData = (await getDraftsRes.json()) as GetEvidenceDraftsResult;
    assert.strictEqual(draftsData.assessmentId, assessmentId);
    assert.strictEqual(draftsData.draftCount, pendingDrafts.length);
    assert.strictEqual(draftsData.drafts.length, pendingDrafts.length);

    const fetchedHeaderDraft = draftsData.drafts.find((d) => d.draftId === approveTarget.draftId);
    assert(fetchedHeaderDraft, 'Fetched drafts must include the HITL draft');
    assert(fetchedHeaderDraft.differentialContext, 'Draft must include differentialContext');
    assert.strictEqual(
      fetchedHeaderDraft.differentialContext.detectionKind,
      approveTarget.differentialContext?.detectionKind
    );
    console.log('[milestoneP1_3_human_review_smoke] Phase 2: Leftover draft differential context verified.');

    console.log('[milestoneP1_3_human_review_smoke] Phase 3: Testing Anti-Bypass Gate against banned synthetic reviewer IDs...');

    const bypassRes1 = await fetch(`${baseUrl}/orchestrated/assessments/${assessmentId}/evidence/${approveTarget.draftId}/review`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`,
      },
      body: JSON.stringify({
        decision: 'approve_evidence',
        reviewerId: 'reviewer_lead_sec',
        reviewedAt: new Date().toISOString(),
      }),
    });
    assert.strictEqual(bypassRes1.status, 400, "Reviewer 'reviewer_lead_sec' must be rejected with HTTP 400");
    const bypassErr1 = (await bypassRes1.json()) as { error: string; message: string };
    assert(bypassErr1.message.includes('forbidden synthetic or unauthenticated reviewer pattern'), 'Error must identify synthetic pattern');

    const bypassRes2 = await fetch(`${baseUrl}/orchestrated/assessments/${assessmentId}/evidence/${approveTarget.draftId}/review`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`,
      },
      body: JSON.stringify({
        decision: 'approve_evidence',
        reviewerId: 'synthetic_operator_mock',
        reviewedAt: new Date().toISOString(),
      }),
    });
    assert.strictEqual(bypassRes2.status, 400, "Reviewer 'synthetic_operator_mock' must be rejected with HTTP 400");
    console.log('[milestoneP1_3_human_review_smoke] Phase 3: Anti-Bypass Gate strictly active and rejecting synthetic bypasses.');

    console.log('[milestoneP1_3_human_review_smoke] Phase 4: Approving soft leftover draft with authorized operator...');
    const findingsBeforeApprove = (await repository.findById(assessmentId))!.findings.length;
    const approveRes = await fetch(`${baseUrl}/orchestrated/assessments/${assessmentId}/evidence/${approveTarget.draftId}/review`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`,
      },
      body: JSON.stringify({
        decision: 'approve_evidence',
        reviewerId: 'usr_secops_lead_auditor',
        reviewedAt: new Date().toISOString(),
        notes: 'Operator reviewed soft leftover draft and approved promotion.',
      }),
    });

    assert.strictEqual(approveRes.status, 200, 'Approval must return HTTP 200 OK');
    const approveData = (await approveRes.json()) as ReviewEvidenceDraftResult;
    assert.strictEqual(approveData.decision, 'approve_evidence');
    assert.strictEqual(approveData.draftId, approveTarget.draftId);
    assert.strictEqual(approveData.reviewerId, 'usr_secops_lead_auditor');
    assert(approveData.findingCreated, 'Promoted Finding must be returned');
    assert.ok(approveData.findingCreated.id, 'Finding id required');
    assert.ok(approveData.findingCreated.type, 'Finding type required');

    const afterApproveRecord = await repository.findById(assessmentId);
    assert(afterApproveRecord, 'Record must exist');
    assert.strictEqual(
      afterApproveRecord.findings.length,
      findingsBeforeApprove + 1,
      'Assessment findings must include HITL-promoted finding'
    );
    assert.strictEqual(
      afterApproveRecord.pendingEvidenceDrafts?.some((d) => d.draftId === approveTarget.draftId),
      false,
      'Approved draft must be removed from pending evidence drafts'
    );
    console.log('[milestoneP1_3_human_review_smoke] Phase 4: Soft draft promoted to typed Finding via HITL.');

    let rejectDraftId = (afterApproveRecord.pendingEvidenceDrafts ?? []).find(
      (d) => d.draftId !== approveTarget.draftId
    )?.draftId;

    if (!rejectDraftId) {
      const seededDraftId = 'dft_hitl_reject_seed_001';
      await repository.update(assessmentId, (prev) => ({
        ...prev,
        pendingEvidenceDrafts: [
          ...(prev.pendingEvidenceDrafts ?? []),
          {
            draftKind: 'non_persisted_comparison_evidence_draft',
            draftId: seededDraftId,
            suggestedEvidenceType: 'http_difference',
            suggestedStrength: 'moderate',
            sourceComparisonId: 'cmp_hitl_reject_seed',
            sourceSnapshotIds: {
              baselineSnapshotId: 'snp_hitl_reject_base',
              validationSnapshotId: 'snp_hitl_reject_val',
            },
            requiresHumanReview: true,
            notPersisted: true,
            notARealFinding: true,
            notConfirmedEvidence: true,
            notForExternalDelivery: true,
            notM45EvidenceRecord: true,
            safeRationale: 'Seeded soft draft for HITL reject coverage',
            differentialContext: {
              endpointUrl: 'https://authorized-review-target.com/',
              detectionKind: 'missing_security_headers',
              missingHeaders: ['x-frame-options'],
              presentHeaders: [],
            },
          },
        ],
      }));
      rejectDraftId = seededDraftId;
    }

    console.log('[milestoneP1_3_human_review_smoke] Phase 5: Rejecting leftover soft evidence draft...');
    const findingsBeforeReject = (await repository.findById(assessmentId))!.findings.length;
    const rejectRes = await fetch(`${baseUrl}/orchestrated/assessments/${assessmentId}/evidence/${rejectDraftId}/review`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`,
      },
      body: JSON.stringify({
        decision: 'reject_evidence',
        reviewerId: 'usr_secops_lead_auditor',
        reviewedAt: new Date().toISOString(),
        notes: 'Soft signal determined not to warrant a finding.',
      }),
    });

    assert.strictEqual(rejectRes.status, 200, 'Rejection must return HTTP 200 OK');
    const rejectData = (await rejectRes.json()) as ReviewEvidenceDraftResult;
    assert.strictEqual(rejectData.decision, 'reject_evidence');
    assert.strictEqual(rejectData.draftId, rejectDraftId);
    assert.strictEqual(rejectData.findingCreated, undefined, 'No finding should be created on rejection');

    const afterRejectRecord = await repository.findById(assessmentId);
    assert(afterRejectRecord, 'Record must exist');
    assert.strictEqual(
      afterRejectRecord.findings.length,
      findingsBeforeReject,
      'Findings count must remain unchanged on rejection'
    );
    assert.strictEqual(
      afterRejectRecord.pendingEvidenceDrafts?.some((d) => d.draftId === rejectDraftId),
      false,
      'Rejected draft must be removed from pending drafts'
    );
    console.log('[milestoneP1_3_human_review_smoke] Phase 5: Draft cleanly discarded with 0 additional findings.');

    console.log('[milestoneP1_3_human_review_smoke] Phase 6: Testing validation edge cases...');

    const notFoundDraftRes = await fetch(`${baseUrl}/orchestrated/assessments/${assessmentId}/evidence/${approveTarget.draftId}/review`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`,
      },
      body: JSON.stringify({
        decision: 'approve_evidence',
        reviewerId: 'usr_secops_lead_auditor',
        reviewedAt: new Date().toISOString(),
      }),
    });
    assert.strictEqual(notFoundDraftRes.status, 400, 'Reviewing already processed draft must fail');

    const invalidDecisionRes = await fetch(`${baseUrl}/orchestrated/assessments/${assessmentId}/evidence/dft_unknown/review`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`,
      },
      body: JSON.stringify({
        decision: 'auto_promote_exploit',
        reviewerId: 'usr_secops_lead_auditor',
        reviewedAt: new Date().toISOString(),
      }),
    });
    assert.strictEqual(invalidDecisionRes.status, 400, 'Invalid decision value must return HTTP 400');

    const missingFieldsRes = await fetch(`${baseUrl}/orchestrated/assessments/${assessmentId}/evidence/dft_unknown/review`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`,
      },
      body: JSON.stringify({
        decision: 'approve_evidence',
      }),
    });
    assert.strictEqual(missingFieldsRes.status, 400, 'Missing reviewerId/reviewedAt must return HTTP 400');

    console.log('[milestoneP1_3_human_review_smoke] Phase 6: Validation edge cases verified.');

    console.log('----------------------------------------------------------------');
    console.log('[milestoneP1_3_human_review_smoke] ALL SMOKE TESTS PASSED (100%)');
    console.log('----------------------------------------------------------------');
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

runSmokeTests().catch((err) => {
  console.error('[milestoneP1_3_human_review_smoke] FATAL TEST FAILURE:', err);
  process.exit(1);
});
