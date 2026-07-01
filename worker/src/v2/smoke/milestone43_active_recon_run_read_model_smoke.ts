import assert from 'node:assert';
import process from 'node:process';
import { executeAndPersistActiveReconOriginRun } from '../recon/active/ActiveReconRunExecutionPersistenceService.js';
import { InMemoryActiveReconOriginRunRepository } from '../recon/active/InMemoryActiveReconOriginRunRepository.js';
import type { ActiveReconDocumentProbeAdapters } from '../recon/active/ActiveReconDocumentProbeRunner.js';
import type { ActiveReconOriginRunRequest } from '../recon/active/ActiveReconOriginRunContracts.js';
import {
  listActiveReconRunSummaryViews,
  getActiveReconRunDetailView
} from '../recon/active/ActiveReconRunReadModelService.js';
import { buildActiveReconRunSafeReportSnapshot } from '../recon/active/ActiveReconRunSafeReportService.js';

async function runTests() {
  console.log('--- V2 Active Recon Run Read Model + Safe Report Snapshot Smoke Test ---');

  let robotsCallCount = 0;
  let securityTxtCallCount = 0;

  const createMockAdapters = (): ActiveReconDocumentProbeAdapters => {
    return {
      robots: {
        async probe(request) {
          robotsCallCount++;
          assert(request.targetUrl.endsWith('/robots.txt'), 'Robots adapter invoked for non-robots target');
          return [{ kind: 'robots_metadata', safeSummary: 'fake robots', confidence: 'high', metadata: { reachable: true, hasUserAgentDirective: true } }];
        }
      },
      securityTxt: {
        async probe(request) {
          securityTxtCallCount++;
          assert(request.targetUrl.endsWith('/.well-known/security.txt'), 'Security.txt adapter invoked for non-security target');
          return [{ kind: 'security_txt_metadata', safeSummary: 'fake security.txt', confidence: 'high', metadata: { reachable: true, hasContactField: true } }];
        }
      }
    };
  };

  const createValidRequest = (id: string, probes: ('http.robots.inspect' | 'http.security_txt.inspect')[] = ['http.robots.inspect', 'http.security_txt.inspect']): ActiveReconOriginRunRequest => ({
    contractVersion: 'active-recon-origin-run/v0',
    requestId: id,
    origin: 'https://example.com',
    authorization: { confirmed: true, scopeLabel: 'auth_1' },
    authorizedScope: { allowedOrigins: ['https://example.com'], allowSameHostPaths: true, allowSubdomains: false },
    probes: probes.map(p => ({ family: 'document', probe: p })) as any
  });

  const repo = new InMemoryActiveReconOriginRunRepository();

  console.log('[*] Executing M42 DB-free flow to populate in-memory repository...');
  const res1 = await executeAndPersistActiveReconOriginRun({
    request: createValidRequest('req_1'),
    adapters: createMockAdapters(),
    repository: repo
  });
  assert.strictEqual(res1.status, 'completed');
  assert.ok(res1.persistedRecord);
  const runId = res1.persistedRecord.runId;

  console.log('[*] Testing list summaries...');
  const summaries = await listActiveReconRunSummaryViews({ repository: repo });
  assert.strictEqual(summaries.length, 1);
  const summary = summaries[0];
  assert.strictEqual(summary.runId, runId);
  assert.strictEqual(summary.counts.probesCompleted, 2);
  assert.strictEqual(summary.documentProbeSummary.robots.present, true);
  assert.strictEqual(summary.documentProbeSummary.robots.reachable, true);
  assert.strictEqual(summary.documentProbeSummary.robots.hasUserAgentDirective, true);
  assert.strictEqual(summary.documentProbeSummary.securityTxt.present, true);
  assert.strictEqual(summary.documentProbeSummary.securityTxt.reachable, true);
  assert.strictEqual(summary.documentProbeSummary.securityTxt.hasContactField, true);
  console.log('[+] Summary mapped successfully with safe fixed fields.');

  console.log('[*] Testing get detail...');
  const detail = await getActiveReconRunDetailView({ repository: repo, runId });
  assert.ok(detail);
  assert.strictEqual(detail.summary.runId, runId);
  assert.strictEqual(detail.safeItems.length, 2);
  assert.strictEqual(detail.safeObservations.length, 2);
  assert.strictEqual(detail.safeObservations[0].kind, 'robots_metadata');
  assert.strictEqual(detail.safeObservations[1].kind, 'security_txt_metadata');
  console.log('[+] Detail mapped successfully with safe fixed fields.');

  console.log('[*] Testing build safe report snapshot...');
  const report = buildActiveReconRunSafeReportSnapshot(detail);
  assert.strictEqual(report.reportKind, 'active-recon.safe-run-report');
  assert.strictEqual(report.run.runId, runId);
  assert.strictEqual(report.explicitNonClaims.noFindingsGenerated, true);
  assert.strictEqual(report.explicitNonClaims.noEvidenceRecordsGenerated, true);
  assert.strictEqual(report.explicitNonClaims.noVulnerabilitiesConfirmed, true);
  assert.strictEqual(report.explicitNonClaims.noRiskSeverityOrImpactClaims, true);
  assert.strictEqual(report.explicitNonClaims.noRawHttpDataIncluded, true);
  console.log('[+] Safe report built successfully with explicit non-claims.');

  console.log('[*] Testing safety invariants (forbidden terms absent)...');
  const serialized = JSON.stringify({ summary, detail, report }, null, 2);
  const forbiddenTerms = [
    'targetUrl', 'headers', 'body', 'raw', 'request', 'response', 'payload',
    'cookie', 'authorization', 'password', 'api_key', 'apikey', 'token', 'secret',
    'vulnerable', 'severity', 'exploit', 'impact', 'confirmed issue', 'high severity',
    'target is safe', 'target is vulnerable', 'weak security'
  ];

  const stringToSearch = serialized
    .replace(/noEvidenceRecordsGenerated/g, 'REDACTED_NON_CLAIM')
    .replace(/noRawHttpDataIncluded/g, 'REDACTED_NON_CLAIM')
    .replace(/noRiskSeverityOrImpactClaims/g, 'REDACTED_NON_CLAIM');
  for (const term of forbiddenTerms) {
    if (stringToSearch.toLowerCase().includes(term.toLowerCase())) {
      assert.fail(`Forbidden term found in read model or report output: ${term}`);
    }
  }
  console.log('[+] No forbidden raw or claim terms found in serialized output.');

  console.log('[*] Testing limits and deterministic ordering...');
  // Add a second record after a tiny delay to ensure distinct createdAt
  await new Promise(resolve => setTimeout(resolve, 10));
  const res2 = await executeAndPersistActiveReconOriginRun({
    request: createValidRequest('req_2'),
    adapters: createMockAdapters(),
    repository: repo
  });
  assert.ok(res2.persistedRecord);
  const runId2 = res2.persistedRecord.runId;

  const limitSummaries = await listActiveReconRunSummaryViews({ repository: repo, limit: 1 });
  assert.strictEqual(limitSummaries.length, 1);
  // res2 should be first because it's newer
  assert.strictEqual(limitSummaries[0].runId, runId2);
  console.log('[+] Limit and deterministic ordering (createdAt DESC) work correctly.');

  console.log('[*] Testing filters...');
  const filteredSummaries = await listActiveReconRunSummaryViews({
    repository: repo,
    filter: { normalizedOrigin: 'https://example.com' }
  });
  assert.strictEqual(filteredSummaries.length, 2);
  console.log('[+] Filters passed correctly to repository.');

  console.log('[*] Testing missing run...');
  const missingDetail = await getActiveReconRunDetailView({ repository: repo, runId: 'does_not_exist' });
  assert.strictEqual(missingDetail, null);
  console.log('[+] Missing run returns null.');

  console.log('[*] Testing failed run mapping...');
  const emptyRes = await executeAndPersistActiveReconOriginRun({
    request: createValidRequest('req_empty', []),
    adapters: createMockAdapters(),
    repository: repo
  });
  assert.ok(emptyRes.persistedRecord);
  const failedSummaryList = await listActiveReconRunSummaryViews({ repository: repo });
  const failedSummary = failedSummaryList.find(s => s.runId === emptyRes.persistedRecord?.runId);
  assert.ok(failedSummary);
  assert.strictEqual(failedSummary.status, 'failed');
  assert.strictEqual(failedSummary.counts.runErrors, 1);
  console.log('[+] Failed run counts and mapping are correct.');

  const completedSummaries = await listActiveReconRunSummaryViews({
    repository: repo,
    filter: { status: 'completed' }
  });
  assert.strictEqual(completedSummaries.length, 2);
  assert.strictEqual(completedSummaries.every(s => s.status === 'completed'), true);
  
  const failedSummaries = await listActiveReconRunSummaryViews({
    repository: repo,
    filter: { status: 'failed' }
  });
  assert.strictEqual(failedSummaries.length, 1);
  assert.strictEqual(failedSummaries.every(s => s.status === 'failed'), true);
  console.log('[+] Status filters work correctly and return expected lengths.');

  console.log('[*] Testing hard limit cap of 100...');
  if (res1.persistedRecord) {
    for (let i = 0; i < 105; i++) {
      const clone = structuredClone(res1.persistedRecord);
      clone.runId = `test_bulk_${i}`;
      await repo.saveRun(clone);
    }
  }
  const largeLimitSummaries = await listActiveReconRunSummaryViews({ repository: repo, limit: 150 });
  assert.strictEqual(largeLimitSummaries.length, 100);
  console.log('[+] Limit cap is strictly enforced to 100.');

  console.log('[*] Testing runId ASC tie-breaker...');
  if (res1.persistedRecord) {
    const cloneA = structuredClone(res1.persistedRecord);
    cloneA.runId = 'same-time-a';
    cloneA.createdAt = '2099-01-01T00:00:00Z';
    
    const cloneB = structuredClone(res1.persistedRecord);
    cloneB.runId = 'same-time-b';
    cloneB.createdAt = '2099-01-01T00:00:00Z';
    
    await repo.saveRun(cloneB);
    await repo.saveRun(cloneA);

    const tieBreakSummaries = await listActiveReconRunSummaryViews({ repository: repo, limit: 100 });
    const idxA = tieBreakSummaries.findIndex(s => s.runId === 'same-time-a');
    const idxB = tieBreakSummaries.findIndex(s => s.runId === 'same-time-b');
    assert.ok(idxA !== -1 && idxB !== -1);
    assert.ok(idxA < idxB, 'same-time-a should sort before same-time-b');
    console.log('[+] Equal timestamps fall back to runId ASC sorting.');
  }

  console.log('[*] Testing probe no-reinvocation...');
  const preCountRobots = robotsCallCount;
  const preCountSecTxt = securityTxtCallCount;
  await listActiveReconRunSummaryViews({ repository: repo });
  const freshDetail = await getActiveReconRunDetailView({ repository: repo, runId });
  if (freshDetail) buildActiveReconRunSafeReportSnapshot(freshDetail);
  assert.strictEqual(robotsCallCount, preCountRobots);
  assert.strictEqual(securityTxtCallCount, preCountSecTxt);
  console.log('[+] Probes were not re-invoked during read model generation.');

  console.log('--- Read Model Smoke Completed Successfully ---');
}

runTests().catch(err => {
  console.error(err);
  process.exit(1);
});
