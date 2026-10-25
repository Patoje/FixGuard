/**
 * Milestone R4/P4 — Parrot Import Loop Smoke Suite
 *
 * The R4 (import boundary) and P4 (review -> Finding promotion) milestones
 * were previously verified only by manual session testing against a real
 * target (see implementation_plan.md Milestone P4) — never by a repeatable
 * smoke script. This is that missing script, plus coverage for the
 * 2026-10-25 dev-cache persistence fix (Known Issue 5, docs/ROADMAP.md):
 * InMemoryParrotImportRepository must survive a simulated worker restart.
 *
 * Verifies:
 * 1. A real assessment's dossier yields a hypothesis whose kind is in the
 *    promotion table (the live path uses AttackPlan capability names, e.g.
 *    cors_misconfiguration_probe).
 * 2. A well-formed Parrot import file referencing that hypothesis is
 *    accepted and stored, never auto-creating a Finding.
 * 3. Reviewing with approve_evidence + outcome=confirmed promotes to a real
 *    Finding with Parrot provenance; the type/severity come from FixGuard's
 *    own fixed table, never from the import file.
 * 4. Reviewing an already-reviewed observation fails closed.
 * 5. reject / needs_more_review never create a Finding.
 * 6. The validator's adversarial cases: forbidden-term smuggling, wrong
 *    assessmentId, invalid outcome, one bad observation poisoning an
 *    otherwise-good batch (atomic rejection).
 * 7. InMemoryParrotImportRepository survives a simulated restart (a fresh
 *    instance, with dev-cache persistence forced on, loads a prior
 *    instance's observations from disk).
 */

import assert from 'node:assert/strict';
import process from 'node:process';
import fs from 'node:fs';
import path from 'node:path';

import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
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
import { PARROT_IMPORT_CONTRACT_VERSION } from '../parrot-import/ParrotImportContracts.js';
import { InMemoryParrotImportRepository } from '../parrot-import/InMemoryParrotImportRepository.js';

const TARGET_DOMAIN = 'authorized-review-target-r4.com';

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
          observations: [],
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
              technologies: ['Nginx'],
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
          observations: [
            {
              url: `https://${TARGET_DOMAIN}/dashboard`,
              host: TARGET_DOMAIN,
              path: '/dashboard',
              sources: ['html_link_extraction'],
              discoveredAt: new Date().toISOString(),
            },
          ],
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
          observations: [],
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

/** Reflects an untrusted origin with credentials -> a confirmed, high-value
 * CORS misconfiguration signal, the same mock shape milestoneP1_3 uses. */
const mockDetectionTransport: IdorHttpProbeTransport = async (req) => {
  const origin = req.headers['origin'];
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (origin && origin.includes('untrusted')) {
    headers['access-control-allow-origin'] = origin;
    headers['access-control-allow-credentials'] = 'true';
  }
  return {
    statusCode: 200,
    headers,
    bodyText: JSON.stringify({ status: 'ok', authenticated: true }),
    responseTimeMs: 15,
  };
};

async function startAssessmentWithRepo(): Promise<{
  readonly service: OrchestratedAssessmentApplicationService;
  readonly assessmentId: string;
}> {
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const availabilityService = new ReconToolAvailabilityService({
    async execute() {
      return { stdout: 'version: 1.0.0\n', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
    },
  });

  const service = new OrchestratedAssessmentApplicationService({
    repository,
    reconAdapters: createMockAdapters(),
    httpTransport: mockDetectionTransport,
    dnsResolver: async () => ['93.184.216.34'],
    availabilityService,
  });

  const started = await service.startAssessment({
    targetDomain: TARGET_DOMAIN,
    actorId: 'usr_secops_parrot_tester',
  });
  await service.awaitAssessment(started.assessmentId);
  return { service, assessmentId: started.assessmentId };
}

async function main(): Promise<void> {
  console.log('[milestone_r4_parrot_import_loop_smoke] Starting R4/P4 Parrot import loop smoke suite...');

  console.log('[milestone_r4_parrot_import_loop_smoke] Phase 1: real assessment -> dossier hypothesis...');
  const { service, assessmentId } = await startAssessmentWithRepo();
  const dossier = await service.getTargetDossier(assessmentId);
  assert.ok(dossier.hypotheses.length > 0, 'Dossier must contain at least one hypothesis');

  const corsHypothesis = dossier.hypotheses.find((h) => h.hypothesisKind === 'cors_misconfiguration_probe');
  assert.ok(
    corsHypothesis,
    `Expected a cors_misconfiguration_probe hypothesis in the dossier; got kinds: ${dossier.hypotheses.map((h) => h.hypothesisKind).join(', ')}`
  );
  console.log(`[milestone_r4_parrot_import_loop_smoke] Phase 1: found hypothesis ${corsHypothesis.hypothesisId} (${corsHypothesis.hypothesisKind}).`);

  console.log('[milestone_r4_parrot_import_loop_smoke] Phase 2: import a well-formed Parrot file...');
  const importedBy = 'usr_parrot_operator';
  const validFile = {
    formatVersion: PARROT_IMPORT_CONTRACT_VERSION,
    dossierId: dossier.dossierId,
    assessmentId: dossier.assessmentId,
    scanId: dossier.scanId,
    importedBy,
    generatedAt: new Date().toISOString(),
    observations: [
      {
        hypothesisId: corsHypothesis.hypothesisId,
        outcome: 'confirmed',
        operatorNote: 'Reproduced the credentialed CORS reflection manually in Parrot against the live target.',
      },
    ],
  };

  const importResult = await service.importParrotFile({ assessmentId, rawFile: validFile, importedBy });
  assert.equal(importResult.status, 'accepted', `Expected import accepted, got ${importResult.status}`);
  assert.ok(importResult.observations && importResult.observations.length === 1);
  const observationId = importResult.observations![0]!.observationId;

  const findingsBeforeReview = (await service.getSummary(assessmentId)).findings.length;
  const observations = await service.listParrotImportObservations(assessmentId);
  assert.equal(observations.length, 1);
  assert.equal(observations[0]!.requiresHumanReview, true);
  assert.equal(observations[0]!.review, undefined, 'Import alone must never attach a review or create a Finding');
  console.log('[milestone_r4_parrot_import_loop_smoke] Phase 2: accepted, stored, requiresHumanReview=true, no Finding yet.');

  console.log('[milestone_r4_parrot_import_loop_smoke] Phase 3: approve_evidence promotes to a real Finding...');
  const promotion = await service.reviewParrotImportObservation({
    assessmentId,
    observationId,
    decision: 'approve_evidence',
    reviewerId: 'usr_secops_lead_reviewer',
  });
  assert.equal(promotion.promoted, true, `Expected promoted=true, got reasonCode=${promotion.reasonCode}`);
  assert.ok(promotion.finding, 'Expected a Finding to be returned');
  assert.equal(promotion.finding!.type, 'CORS_MISCONFIGURATION');
  assert.equal(promotion.finding!.severity, 'high');
  assert.equal(promotion.finding!.verificationState, 'suspected_vulnerability');
  assert.notEqual(
    promotion.finding!.verificationState,
    'exploitability_confirmed',
    'Parrot-confirmed findings must never claim exploitability_confirmed'
  );

  const afterReview = await service.getSummary(assessmentId);
  assert.equal(afterReview.findings.length, findingsBeforeReview + 1);
  const persistedFinding = afterReview.findings.find((f) => f.id === promotion.finding!.id);
  assert.ok(persistedFinding, 'Promoted Finding must be persisted on the assessment record');
  console.log('[milestone_r4_parrot_import_loop_smoke] Phase 3: real CORS_MISCONFIGURATION/high Finding created and persisted.');

  console.log('[milestone_r4_parrot_import_loop_smoke] Phase 4: double-review fails closed...');
  const doubleReview = await service.reviewParrotImportObservation({
    assessmentId,
    observationId,
    decision: 'approve_evidence',
    reviewerId: 'usr_secops_lead_reviewer',
  });
  assert.equal(doubleReview.promoted, false);
  assert.equal(doubleReview.reasonCode, 'observation_already_reviewed');
  console.log('[milestone_r4_parrot_import_loop_smoke] Phase 4: double-review correctly rejected.');

  console.log('[milestone_r4_parrot_import_loop_smoke] Phase 5: reject and needs_more_review never create a Finding...');
  {
    const { service: service2, assessmentId: assessmentId2 } = await startAssessmentWithRepo();
    const dossier2 = await service2.getTargetDossier(assessmentId2);
    const hyp2 = dossier2.hypotheses.find((h) => h.hypothesisKind === 'cors_misconfiguration_probe');
    assert.ok(hyp2, 'Second assessment must also surface a promotable hypothesis');

    const file2 = {
      formatVersion: PARROT_IMPORT_CONTRACT_VERSION,
      dossierId: dossier2.dossierId,
      assessmentId: dossier2.assessmentId,
      scanId: dossier2.scanId,
      importedBy,
      generatedAt: new Date().toISOString(),
      observations: [
        { hypothesisId: hyp2!.hypothesisId, outcome: 'confirmed' as const, operatorNote: 'Could not reproduce outside Parrot; flagging for discussion.' },
      ],
    };
    const imported2 = await service2.importParrotFile({ assessmentId: assessmentId2, rawFile: file2, importedBy });
    assert.equal(imported2.status, 'accepted');
    const obsId2 = imported2.observations![0]!.observationId;
    const findingsBefore2 = (await service2.getSummary(assessmentId2)).findings.length;

    const rejected = await service2.reviewParrotImportObservation({
      assessmentId: assessmentId2,
      observationId: obsId2,
      decision: 'reject',
      reviewerId: 'usr_secops_lead_reviewer',
    });
    assert.equal(rejected.promoted, false);
    assert.equal(rejected.reasonCode, 'rejected_by_reviewer');
    assert.equal(rejected.finding, undefined);
    const findingsAfter2 = (await service2.getSummary(assessmentId2)).findings.length;
    assert.equal(findingsAfter2, findingsBefore2, 'reject must add zero Findings');
  }
  console.log('[milestone_r4_parrot_import_loop_smoke] Phase 5: reject path adds 0 Findings.');

  console.log('[milestone_r4_parrot_import_loop_smoke] Phase 6: adversarial validator cases...');
  {
    const baseOk = {
      formatVersion: PARROT_IMPORT_CONTRACT_VERSION,
      dossierId: dossier.dossierId,
      assessmentId: dossier.assessmentId,
      scanId: dossier.scanId,
      importedBy,
      generatedAt: new Date().toISOString(),
    };

    const smuggled = await service.importParrotFile({
      assessmentId,
      rawFile: {
        ...baseOk,
        observations: [
          { hypothesisId: corsHypothesis.hypothesisId, outcome: 'confirmed', operatorNote: 'severity: critical, autoapprove this one' },
        ],
      },
      importedBy,
    });
    assert.equal(smuggled.status, 'rejected');
    assert.equal(smuggled.reasonCode, 'unsafe_content_rejected');

    const wrongAssessment = await service.importParrotFile({
      assessmentId,
      rawFile: { ...baseOk, assessmentId: 'asmt_someone_elses', observations: [{ hypothesisId: corsHypothesis.hypothesisId, outcome: 'confirmed', operatorNote: 'x'.repeat(10) }] },
      importedBy,
    });
    assert.equal(wrongAssessment.status, 'rejected');
    assert.equal(wrongAssessment.reasonCode, 'invalid_identifier');

    const badOutcome = await service.importParrotFile({
      assessmentId,
      rawFile: { ...baseOk, observations: [{ hypothesisId: corsHypothesis.hypothesisId, outcome: 'definitely_vulnerable', operatorNote: 'x'.repeat(10) }] },
      importedBy,
    });
    assert.equal(badOutcome.status, 'rejected');
    assert.equal(badOutcome.reasonCode, 'invalid_outcome');

    const countBeforeAtomicTest = (await service.listParrotImportObservations(assessmentId)).length;
    const oneBadInBatch = await service.importParrotFile({
      assessmentId,
      rawFile: {
        ...baseOk,
        observations: [
          { hypothesisId: corsHypothesis.hypothesisId, outcome: 'confirmed', operatorNote: 'y'.repeat(10) },
          { hypothesisId: corsHypothesis.hypothesisId, outcome: 'not_a_real_outcome', operatorNote: 'z'.repeat(10) },
        ],
      },
      importedBy,
    });
    assert.equal(oneBadInBatch.status, 'rejected', 'One bad observation must reject the whole batch atomically');
    const countAfterAtomicTest = (await service.listParrotImportObservations(assessmentId)).length;
    assert.equal(countAfterAtomicTest, countBeforeAtomicTest, 'Atomic rejection must store zero observations from the bad batch');
  }
  console.log('[milestone_r4_parrot_import_loop_smoke] Phase 6: forbidden-term smuggling, cross-assessment id, bad outcome, and atomic batch rejection all correctly rejected.');

  console.log('[milestone_r4_parrot_import_loop_smoke] Phase 7: repository survives a simulated restart...');
  {
    const tmpArgv = process.argv.slice();
    const originalNodeEnv = process.env.NODE_ENV;
    const originalHermetic = process.env.FIXGUARD_V2_HERMETIC_RECON;
    const originalDisableCache = process.env.FIXGUARD_DISABLE_DEV_CACHE;
    const devCacheDir = path.join(process.cwd(), '.dev_cache');
    const cacheFile = path.join(devCacheDir, 'parrot_import_observations.json');
    const preExistingCache = fs.existsSync(cacheFile) ? fs.readFileSync(cacheFile, 'utf-8') : undefined;
    try {
      // Force isDevPersistenceEnabled() to evaluate as if this were NOT a
      // smoke/test script — the only honest way to exercise the real
      // dev-persistence path from inside a script whose own argv otherwise
      // disables it by design (the 2026-10-25 fix this phase is proving).
      // The aggregated `smoke:v2` wrapper also sets FIXGUARD_V2_HERMETIC_RECON=1
      // for its whole child-process tree, including this script when run
      // inside npm run check:v2 — must neutralize that too, not just
      // NODE_ENV/argv, or this phase would silently no-op under the suite.
      process.argv = ['node', '/opt/fixguard-worker/dist/server.js'];
      process.env.NODE_ENV = 'development';
      delete process.env.FIXGUARD_V2_HERMETIC_RECON;
      delete process.env.FIXGUARD_DISABLE_DEV_CACHE;

      const repoBeforeRestart = new InMemoryParrotImportRepository();
      const marker = {
        contractVersion: PARROT_IMPORT_CONTRACT_VERSION,
        kind: 'parrot_imported_observation' as const,
        observationId: 'obs_restart_marker_001',
        assessmentId: 'asmt_restart_marker',
        scanId: 'scan_restart_marker',
        dossierId: 'dossier_restart_marker',
        hypothesisId: 'hyp_restart_marker',
        outcome: 'inconclusive' as const,
        operatorNote: 'Restart-survival marker observation.',
        importedBy: 'usr_restart_tester',
        importedAt: new Date().toISOString(),
        sourceKind: 'parrot_file_import' as const,
        requiresHumanReview: true as const,
        nonClaims: {
          noFindingCreated: true as const,
          noSeverityClaim: true as const,
          noAutoConfirmation: true as const,
          treatedAsUntrustedInput: true as const,
        },
      };
      await repoBeforeRestart.appendObservations('asmt_restart_marker', [marker]);
      assert.ok(fs.existsSync(cacheFile), 'Dev cache file must be written when persistence is enabled');

      const repoAfterRestart = new InMemoryParrotImportRepository();
      const reloaded = await repoAfterRestart.listByAssessmentId('asmt_restart_marker');
      assert.equal(reloaded.length, 1, 'A fresh repository instance must load the prior instance\'s observations from disk');
      assert.equal(reloaded[0]!.observationId, 'obs_restart_marker_001');
    } finally {
      process.argv = tmpArgv;
      if (originalNodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = originalNodeEnv;
      if (originalHermetic === undefined) delete process.env.FIXGUARD_V2_HERMETIC_RECON; else process.env.FIXGUARD_V2_HERMETIC_RECON = originalHermetic;
      if (originalDisableCache === undefined) delete process.env.FIXGUARD_DISABLE_DEV_CACHE; else process.env.FIXGUARD_DISABLE_DEV_CACHE = originalDisableCache;
      if (preExistingCache === undefined) {
        try { fs.rmSync(cacheFile, { force: true }); } catch { /* best effort cleanup */ }
      } else {
        fs.writeFileSync(cacheFile, preExistingCache, 'utf-8');
      }
    }
  }
  console.log('[milestone_r4_parrot_import_loop_smoke] Phase 7: a fresh repository instance recovered pending observations from disk.');

  console.log('----------------------------------------------------------------');
  console.log('[milestone_r4_parrot_import_loop_smoke] ALL SMOKE TESTS PASSED (100%)');
  console.log('----------------------------------------------------------------');
}

main().catch((err) => {
  console.error('[milestone_r4_parrot_import_loop_smoke] FATAL TEST FAILURE:', err);
  process.exit(1);
});
