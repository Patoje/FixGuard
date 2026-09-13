import assert from 'node:assert';
import process from 'node:process';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createV2App, DEFAULT_V2_HOST } from '../api/createV2App.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';
import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository.js';
import { InMemoryFormalFindingCandidateRepository } from '../finding-candidate-promotion/InMemoryFormalFindingCandidateRepository.js';
import { InMemoryEvidenceDraftRepository } from '../finding-candidate-draft/InMemoryEvidenceDraftRepository.js';
import { V2AssessmentRuntime } from '../runtime/V2AssessmentRuntime.js';
import { AssessmentApplicationService } from '../application/AssessmentApplicationService.js';
import { DefensiveReportReadinessService } from '../reporting-boundary/DefensiveReportReadinessService.js';
import { createStubOrchestrator } from './StubToolRegistry.js';

interface RunningServer {
  server: Server;
  baseUrl: string;
  host: string;
  port: number;
}

const TEST_SECRET = 'fixguard_secret_token_f0_992147aabbcc';

async function startServer(apiSecret?: string): Promise<RunningServer> {
  const assessmentRepo = new InMemoryAssessmentRepository();
  const candidateRepo = new InMemoryFormalFindingCandidateRepository();
  const draftRepo = new InMemoryEvidenceDraftRepository();
  const orchestrator = createStubOrchestrator();
  const runtime = new V2AssessmentRuntime(assessmentRepo, orchestrator);
  const assessmentService = new AssessmentApplicationService(runtime);
  const reportService = new DefensiveReportReadinessService(candidateRepo);

  const root = V2CompositionRoot.withDependencies({
    assessmentRepository: assessmentRepo,
    candidateRepository: candidateRepo,
    draftRepository: draftRepo,
    runtime,
    assessmentService,
    reportService
  });

  const app = createV2App(root, {
    apiSecret,
    allowedOrigins: ['http://localhost:3000', 'http://127.0.0.1:3000']
  });

  // Explicit host binding to 127.0.0.1
  const server = app.listen(0, DEFAULT_V2_HOST);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const address = server.address() as AddressInfo;
  const baseUrl = `http://${address.address}:${address.port}/api/v2`;

  return {
    server,
    baseUrl,
    host: address.address,
    port: address.port
  };
}

async function stopServer(running: RunningServer): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    running.server.close((err) => (err ? reject(err) : resolve()));
  });
}



async function runMilestoneF0SmokeTests(): Promise<void> {
  console.log('=== [M-F0 SMOKE] API Security, Approval Containment & Foundations Verification ===\n');

  let serverInstance: RunningServer | null = null;

  try {
    serverInstance = await startServer(TEST_SECRET);
    const { baseUrl, host } = serverInstance;

    // -------------------------------------------------------------------------
    // Assertion 1: Explicit Host Binding to 127.0.0.1
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 1: Explicit Host Binding (Strictly 127.0.0.1, never 0.0.0.0)');
    assert.strictEqual(DEFAULT_V2_HOST, '127.0.0.1', 'DEFAULT_V2_HOST must be strictly 127.0.0.1');
    assert.strictEqual(host, '127.0.0.1', 'Server must be bound strictly to 127.0.0.1');
    assert.notStrictEqual(host, '0.0.0.0', 'Server MUST NOT bind to wildcard 0.0.0.0');
    console.log('    -> Server host confirmed bound strictly to 127.0.0.1');

    // -------------------------------------------------------------------------
    // Assertion 2: Strict CORS Allowed Origin (Authorized Local Interfaces)
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 2: Strict CORS Allowed Origin (http://localhost:3000)');
    const corsOkRes = await fetch(`${baseUrl}/assessments`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'http://localhost:3000',
        'Access-Control-Request-Method': 'POST'
      }
    });
    assert.strictEqual(corsOkRes.headers.get('access-control-allow-origin'), 'http://localhost:3000');
    assert.strictEqual(corsOkRes.headers.get('access-control-allow-credentials'), 'true');
    console.log('    -> Authorized origin http://localhost:3000 admitted with credentials');

    // -------------------------------------------------------------------------
    // Assertion 3: Strict CORS Rejected Origin (Unauthorized External Origins)
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 3: Strict CORS Rejected Origin (http://evil-attacker.example)');
    const corsBlockRes = await fetch(`${baseUrl}/assessments`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'http://evil-attacker.example',
        'Access-Control-Request-Method': 'POST'
      }
    });
    // Disallowed origins must NOT receive Access-Control-Allow-Origin header
    assert.strictEqual(
      corsBlockRes.headers.get('access-control-allow-origin'),
      null,
      'Unauthorized origin must not receive Access-Control-Allow-Origin header'
    );
    console.log('    -> Unauthorized external origin strictly rejected by CORS policy');

    // -------------------------------------------------------------------------
    // Assertion 4: Bearer Authentication Missing -> 401 Unauthorized
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 4: Bearer Authentication Missing -> 401 Unauthorized');
    const noAuthRes = await fetch(`${baseUrl}/assessments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUri: 'https://example.com' })
    });
    assert.strictEqual(noAuthRes.status, 401, 'Request without Authorization header must return 401');
    const noAuthBody = (await noAuthRes.json()) as Record<string, unknown>;
    assert.strictEqual(noAuthBody.error, 'Unauthorized');
    console.log('    -> Unauthenticated request fail-closed with 401 Unauthorized');

    // -------------------------------------------------------------------------
    // Assertion 5: Invalid Bearer Token -> 403 Forbidden
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 5: Invalid Bearer Token -> 403 Forbidden');
    const badTokenRes = await fetch(`${baseUrl}/assessments`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer wrong_token_sample_123'
      },
      body: JSON.stringify({ targetUri: 'https://example.com' })
    });
    assert.strictEqual(badTokenRes.status, 403, 'Request with invalid Bearer token must return 403');
    const badTokenBody = (await badTokenRes.json()) as Record<string, unknown>;
    assert.strictEqual(badTokenBody.error, 'Forbidden');
    console.log('    -> Invalid Bearer token fail-closed with 403 Forbidden');

    // -------------------------------------------------------------------------
    // Assertion 6: Valid Bearer Token -> Authorized (201 Created)
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 6: Valid Bearer Token -> Authorized (201 Created)');
    const validAuthRes = await fetch(`${baseUrl}/assessments`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`
      },
      body: JSON.stringify({ targetUri: 'https://example.com' })
    });
    assert.strictEqual(validAuthRes.status, 201, 'Request with valid Bearer token must return 201');
    const validAuthBody = (await validAuthRes.json()) as Record<string, unknown>;
    assert.strictEqual(validAuthBody.targetUri, 'https://example.com');
    assert.ok(typeof validAuthBody.sessionId === 'string');
    const sessionId = validAuthBody.sessionId as string;
    console.log(`    -> Valid Bearer token authenticated successfully (sessionId: ${sessionId})`);

    // -------------------------------------------------------------------------
    // Assertion 7: Critical Human Approval Gate (/recommendations/approve)
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 7: Critical Approval Boundary Protection (/recommendations/approve)');
    const unauthApproveRes = await fetch(`${baseUrl}/assessments/${sessionId}/recommendations/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recommendationId: 'rec_001', approved: true })
    });
    assert.strictEqual(
      unauthApproveRes.status,
      401,
      'Unauthenticated call to /recommendations/approve must return 401'
    );

    const badApproveRes = await fetch(`${baseUrl}/assessments/${sessionId}/recommendations/approve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer invalid_secret'
      },
      body: JSON.stringify({ recommendationId: 'rec_001', approved: true })
    });
    assert.strictEqual(badApproveRes.status, 403, 'Invalid token to /recommendations/approve must return 403');
    console.log('    -> /recommendations/approve strictly shielded against unauthenticated/forged calls');

    // -------------------------------------------------------------------------
    // Assertion 8: Critical Candidate Promotion Gate (/candidates/promote)
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 8: Critical Candidate Promotion Gate (/candidates/promote)');
    const unauthPromoteRes = await fetch(`${baseUrl}/candidates/promote`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        candidateId: 'cand_f0_001',
        scanId: sessionId,
        draftId: 'drf_f0_001',
        reviewerId: 'usr_sec_analyst_01',
        triageDecisionId: 'dec_triage_001'
      })
    });
    assert.strictEqual(unauthPromoteRes.status, 401, 'Unauthenticated call to /candidates/promote must return 401');

    const badPromoteRes = await fetch(`${baseUrl}/candidates/promote`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer invalid_secret'
      },
      body: JSON.stringify({
        candidateId: 'cand_f0_001',
        scanId: sessionId,
        draftId: 'drf_f0_001',
        reviewerId: 'usr_sec_analyst_01',
        triageDecisionId: 'dec_triage_001'
      })
    });
    assert.strictEqual(badPromoteRes.status, 403, 'Invalid token to /candidates/promote must return 403');
    console.log('    -> /candidates/promote strictly shielded against unauthenticated/forged calls');

    console.log('\n[✔] ALL MILESTONE F0 API SECURITY & BOUNDARY ASSERTIONS PASSED SUCCESSFULLY.');
  } finally {
    if (serverInstance) {
      await stopServer(serverInstance);
    }
  }
}

runMilestoneF0SmokeTests().catch((err) => {
  console.error('[!] Milestone F0 Smoke Test FAILED:', err);
  process.exit(1);
});
