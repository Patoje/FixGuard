/**
 * R10 — One operator starts, reads, cancels, and authorizes the same assessment.
 */
import assert from 'node:assert/strict';
import { ACTIVE_INVESTIGATION_CONTRACT_VERSION } from '../active-investigation/ActiveInvestigationContracts.js';
import { ActiveInvestigationRuntimeService } from '../active-investigation/ActiveInvestigationRuntimeService.js';
import type {
  ReadOnlyLoopRequest,
  ReadOnlyLoopResult,
} from '../active-investigation/ActiveInvestigationRuntimeService.js';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import type { AuthorizableBlastRadiusClass } from '../attack-authorization/AttackAuthorizationContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

const ACTOR_ID = 'usr_secops_api';
const TOKEN = 'session-bearer-must-not-enter-fact';
const ENDPOINT = 'https://app.example.com/api/orders/ord_123';
const VERSION = 'Next.js 14.2.5';
const ATTESTATION = 'I reviewed the observed facts and the advisory plans before signing this document.';

class CancellingInvestigationRuntime extends ActiveInvestigationRuntimeService {
  readonly loopRequests: ReadOnlyLoopRequest[] = [];
  readonly loopResults: ReadOnlyLoopResult[] = [];

  public override async runReadOnlyLoop(request: ReadOnlyLoopRequest): Promise<ReadOnlyLoopResult> {
    this.loopRequests.push(request);
    const snapshot = this.getSnapshot(request.investigationId);
    assert.ok(snapshot);
    const cancelled = this.cancelInvestigation({
      contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
      kind: 'cancel_active_investigation_request',
      investigationId: request.investigationId,
      operatorId: snapshot.lineage.actorId,
      mode: 'cancel',
    });
    assert.equal(cancelled.status, 'cancelled');
    assert.equal(snapshot.lineage.actorId, ACTOR_ID);
    const result = await super.runReadOnlyLoop(request);
    this.loopResults.push(result);
    return result;
  }
}

function blastFor(plan: { readonly capabilityGained: string }): AuthorizableBlastRadiusClass {
  if (plan.capabilityGained === 'read_authenticated' || plan.capabilityGained === 'read_escalated') {
    return plan.capabilityGained;
  }
  throw new Error(`read child capabilityGained is ${plan.capabilityGained}`);
}

function transport(request: HttpProbeRequest): Promise<HttpProbeResponse> {
  const url = new URL(request.url);
  const apex = url.hostname === 'app.example.com' && url.pathname === '/';
  const headers: Record<string, string> = {
    'content-type': apex ? 'text/html' : 'application/json',
  };
  if (apex) headers['x-powered-by'] = VERSION;
  const showOrder = apex || url.pathname.includes('/api/orders/');
  return Promise.resolve({
    statusCode: apex || request.headers['authorization'] ? 200 : 401,
    headers,
    bodyText: showOrder ? 'fetch("/api/orders/ord_123")' : '{"error":"unauthorized"}',
    responseTimeMs: 1,
  });
}

async function main(): Promise<void> {
  process.env.FIXGUARD_V2_HERMETIC_RECON = '1';
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('', { status: 404 });
  try {
    const runtime = new CancellingInvestigationRuntime();
    const plans = new InMemoryAttackPlanRepository();
    const service = new OrchestratedAssessmentApplicationService({
      repository: new InMemoryOrchestratedAssessmentRepository(),
      attackPlanRepository: plans,
      activeInvestigationRuntime: runtime,
      dnsResolver: async () => ['93.184.216.34'],
      httpTransport: transport,
    });

    const started = await service.startAssessment({
      targetDomain: 'app.example.com',
      actorId: ACTOR_ID,
      seedUrls: [ENDPOINT],
      sessionIdentities: {
        identityA: {
          identityId: 'id_session_a',
          injectHeaders: { authorization: `Bearer ${TOKEN}` },
        },
      },
      config: {
        enableByotHarvest: true,
        byotHarvestHttpOnly: true,
        deepReconMaxRequests: 50,
        enableDeepRecon: true,
        enableSpaDiscovery: false,
        skipStages: [
          'stage_1_domain_zone',
          'stage_2_port_service',
          'stage_4_crawling_parameters',
          'stage_5_secret_inspection',
        ],
      },
    });

    const record = await service.awaitAssessment(started.assessmentId);
    assert.ok(record);
    if (record.status !== 'completed') {
      throw new Error(`assessment status ${record.status}: ${record.error ?? ''}`);
    }
    assert.ok(record.stages.some((stage) => stage.status === 'completed'));
    const facts = record.observedFacts ?? [];
    assert.ok(facts.some((fact) => fact.factKind === 'observed_tech_version' && fact.value === VERSION));
    assert.equal(record.findings.length, 0);

    const saved = await plans.listByAssessmentId(started.assessmentId);
    const child = saved.find(
      (plan) => plan.capability === 'auth_boundary_differential' && plan.executable === false
    );
    assert.ok(child);
    const idor = saved.find((plan) => plan.capability === 'idor_read_differential');
    assert.ok(idor);
    assert.equal(idor.status, 'prerequisite_missing');

    assert.equal(runtime.loopRequests.length, 0);
    assert.ok(record.readInvestigationLoop);
    assert.equal(
      record.readInvestigationLoop.executedSteps.some(
        (step) => step.capability === 'idor_read_differential'
      ),
      false
    );
    for (const step of record.readInvestigationLoop.executedSteps) {
      assert.equal(
        step.blastRadiusClass === 'read_public' ||
          step.blastRadiusClass === 'read_authenticated' ||
          step.blastRadiusClass === 'read_escalated',
        true
      );
    }

    const authorized = await new AttackAuthorizationService(plans).authorizePlan(
      child.planId,
      started.assessmentId,
      blastFor(child),
      ACTOR_ID
    );
    assert.equal(authorized.status, 'established');

    const html = await service.generateHtmlReport(started.assessmentId, ACTOR_ID, ATTESTATION);
    assert.equal(html.includes('observed_tech_version'), true);
    assert.equal(html.includes(VERSION), true);
    assert.equal(html.includes(child.planId), true);
    assert.equal(record.findings.length, 0);
    assert.equal(JSON.stringify(record).includes(TOKEN), false);
  } finally {
    globalThis.fetch = originalFetch;
  }

  console.log('[milestone_r10_operator_run_smoke] ALL PASSED');
}

main().catch((err: unknown) => {
  console.error('[milestone_r10_operator_run_smoke] FAILED', err);
  process.exit(1);
});
