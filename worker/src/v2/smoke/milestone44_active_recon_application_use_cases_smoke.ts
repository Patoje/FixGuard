import assert from 'node:assert';
import process from 'node:process';
import { InMemoryActiveReconOriginRunRepository } from '../recon/active/InMemoryActiveReconOriginRunRepository.js';
import type { ActiveReconDocumentProbeAdapters } from '../recon/active/ActiveReconDocumentProbeRunner.js';
import {
  startAuthorizedActiveReconRun,
  listActiveReconRunSummaries,
  getActiveReconRunDetail,
  buildActiveReconRunSafeReport
} from '../recon/active/ActiveReconApplicationUseCaseService.js';

async function runTests() {
  console.log('--- V2 Active Recon Application Use Cases Boundary Smoke Test ---');

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

  const repo = new InMemoryActiveReconOriginRunRepository();
  const adapters = createMockAdapters();

  console.log('[*] Testing invalid inputs...');
  const invalidCommandRes = await startAuthorizedActiveReconRun({
    command: { contractVersion: 'active-recon-application-use-cases/v0', kind: 'invalid' } as any,
    adapters,
    repository: repo
  });
  assert.strictEqual(invalidCommandRes.status, 'failed');
  assert.strictEqual(invalidCommandRes.errorCode, 'invalid_command');

  const invalidQueryRes = await getActiveReconRunDetail({
    query: { contractVersion: 'active-recon-application-use-cases/v0', kind: 'invalid', runId: '' } as any,
    repository: repo
  });
  assert.strictEqual(invalidQueryRes.status, 'failed');
  assert.strictEqual(invalidQueryRes.errorCode, 'invalid_query');
  console.log('[+] Invalid inputs rejected safely.');

  console.log('[*] Testing Happy Path (Start Run)...');
  const startRes = await startAuthorizedActiveReconRun({
    command: {
      contractVersion: 'active-recon-application-use-cases/v0',
      kind: 'start_authorized_active_recon_run_command',
      normalizedOrigin: 'https://example.com'
    },
    adapters,
    repository: repo
  });

  assert.strictEqual(startRes.status, 'completed');
  assert.ok(startRes.runId);
  assert.strictEqual(startRes.createsFindings, false);
  assert.strictEqual(startRes.createsEvidence, false);
  assert.strictEqual(startRes.confirmsVulnerabilities, false);
  assert.strictEqual(startRes.makesRiskClaims, false);
  assert.strictEqual(startRes.makesSeverityClaims, false);
  assert.strictEqual(startRes.makesImpactClaims, false);
  console.log('[+] Run started and persisted successfully. Classification flags are safe.');

  const runId = startRes.runId!;

  console.log('[*] Testing No Re-Execution Invariants...');
  const preRobots = robotsCallCount;
  const preSecTxt = securityTxtCallCount;

  console.log('[*] Testing List Summaries...');
  const listRes = await listActiveReconRunSummaries({
    query: {
      contractVersion: 'active-recon-application-use-cases/v0',
      kind: 'list_active_recon_run_summaries_query'
    },
    repository: repo
  });
  assert.strictEqual(listRes.status, 'completed');
  assert.strictEqual(listRes.summaries.length, 1);
  assert.strictEqual(listRes.summaries[0].runId, runId);
  assert.strictEqual(listRes.createsFindings, false);
  console.log('[+] List summaries works and respects boundary.');

  console.log('[*] Testing Get Detail...');
  const detailRes = await getActiveReconRunDetail({
    query: {
      contractVersion: 'active-recon-application-use-cases/v0',
      kind: 'get_active_recon_run_detail_query',
      runId
    },
    repository: repo
  });
  assert.strictEqual(detailRes.status, 'completed');
  assert.ok(detailRes.detail);
  assert.strictEqual(detailRes.detail?.summary.runId, runId);
  assert.strictEqual(detailRes.createsFindings, false);
  console.log('[+] Get detail works and respects boundary.');

  console.log('[*] Testing Build Safe Report...');
  const reportRes = await buildActiveReconRunSafeReport({
    query: {
      contractVersion: 'active-recon-application-use-cases/v0',
      kind: 'build_active_recon_run_safe_report_query',
      runId
    },
    repository: repo
  });
  assert.strictEqual(reportRes.status, 'completed');
  assert.ok(reportRes.report);
  assert.strictEqual(reportRes.report?.run.runId, runId);
  assert.strictEqual(reportRes.createsFindings, false);
  console.log('[+] Build safe report works and respects boundary.');

  assert.strictEqual(robotsCallCount, preRobots, 'Robots adapter was re-invoked unexpectedly');
  assert.strictEqual(securityTxtCallCount, preSecTxt, 'SecurityTxt adapter was re-invoked unexpectedly');
  console.log('[+] No-re-execution invariant passed. Readers do not execute tools.');

  console.log('[*] Testing Not Found...');
  const notFoundDetail = await getActiveReconRunDetail({
    query: {
      contractVersion: 'active-recon-application-use-cases/v0',
      kind: 'get_active_recon_run_detail_query',
      runId: 'does_not_exist'
    },
    repository: repo
  });
  assert.strictEqual(notFoundDetail.status, 'not_found');
  assert.strictEqual(notFoundDetail.errorCode, 'run_not_found');

  const notFoundReport = await buildActiveReconRunSafeReport({
    query: {
      contractVersion: 'active-recon-application-use-cases/v0',
      kind: 'build_active_recon_run_safe_report_query',
      runId: 'does_not_exist'
    },
    repository: repo
  });
  assert.strictEqual(notFoundReport.status, 'not_found');
  assert.strictEqual(notFoundReport.errorCode, 'run_not_found');
  console.log('[+] Not found cases handled safely.');

  const errorThrowingRepo = {
    async saveRun() { throw new Error('Simulated execution failure with secret_token_123'); },
    async listRuns() { throw new Error('Simulated read failure with auth_bearer_abc'); },
    async getRun() { throw new Error('Simulated report failure with raw_body_content'); }
  } as unknown as InMemoryActiveReconOriginRunRepository;

  const executionFailureRes = await startAuthorizedActiveReconRun({
    command: {
      contractVersion: 'active-recon-application-use-cases/v0',
      kind: 'start_authorized_active_recon_run_command',
      normalizedOrigin: 'https://example.com'
    },
    adapters,
    repository: errorThrowingRepo
  });
  assert.strictEqual(executionFailureRes.status, 'failed');
  assert.strictEqual(executionFailureRes.errorCode, 'execution_failed');

  const readFailureRes = await listActiveReconRunSummaries({
    query: {
      contractVersion: 'active-recon-application-use-cases/v0',
      kind: 'list_active_recon_run_summaries_query'
    },
    repository: errorThrowingRepo
  });
  assert.strictEqual(readFailureRes.status, 'failed');
  assert.strictEqual(readFailureRes.errorCode, 'read_failed');

  const getFailureRes = await getActiveReconRunDetail({
    query: {
      contractVersion: 'active-recon-application-use-cases/v0',
      kind: 'get_active_recon_run_detail_query',
      runId: 'any_id'
    },
    repository: errorThrowingRepo
  });
  assert.strictEqual(getFailureRes.status, 'failed');
  assert.strictEqual(getFailureRes.errorCode, 'read_failed');

  const reportFailureRes = await buildActiveReconRunSafeReport({
    query: {
      contractVersion: 'active-recon-application-use-cases/v0',
      kind: 'build_active_recon_run_safe_report_query',
      runId: 'any_id'
    },
    repository: errorThrowingRepo
  });
  assert.strictEqual(reportFailureRes.status, 'failed');
  assert.strictEqual(reportFailureRes.errorCode, 'report_failed');

  console.log('[*] Testing Failure Safety (No raw leaks)...');
  const serialized = JSON.stringify({ 
    invalidCommandRes, startRes, listRes, detailRes, reportRes, notFoundDetail, notFoundReport,
    executionFailureRes, readFailureRes, getFailureRes, reportFailureRes
  }, null, 2);
  const forbiddenTerms = [
    'targetUrl', 'headers', 'body', 'raw', 'request', 'response', 'payload',
    'cookie', 'authorization', 'password', 'api_key', 'apikey', 'token', 'secret',
    'vulnerable', 'severity', 'exploit', 'impact', 'confirmed issue', 'high severity',
    'target is safe', 'target is vulnerable', 'weak security'
  ];

  const stringToSearch = serialized
    .replace(/noEvidenceRecordsGenerated/g, 'REDACTED_NON_CLAIM')
    .replace(/noRawHttpDataIncluded/g, 'REDACTED_NON_CLAIM')
    .replace(/noRiskSeverityOrImpactClaims/g, 'REDACTED_NON_CLAIM')
    .replace(/makesSeverityClaims/g, 'REDACTED_NON_CLAIM')
    .replace(/makesImpactClaims/g, 'REDACTED_NON_CLAIM')
    .replace(/confirmsVulnerabilities/g, 'REDACTED_NON_CLAIM');
    
  for (const term of forbiddenTerms) {
    if (stringToSearch.toLowerCase().includes(term.toLowerCase())) {
      assert.fail(`Forbidden term found in application use case boundary: ${term}`);
    }
  }
  console.log('[+] Application use case boundary leaks no raw data or claims.');

  console.log('--- M44 Application Use Cases Boundary Smoke Completed Successfully ---');
}

runTests().catch(err => {
  console.error(err);
  process.exit(1);
});
