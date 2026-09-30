/**
 * R4 — The signed HTML document lists observed facts and plan dependencies.
 * An empty candidate still aborts the other report generator.
 */
import assert from 'node:assert/strict';
import { ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION } from '../application/OrchestratedAssessmentContracts.js';
import type { OrchestratedAssessmentRecord } from '../application/OrchestratedAssessmentContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { ATTACK_PLANNING_CONTRACT_VERSION } from '../attack-planning/AttackPlanContracts.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import type { ExecutionLineage } from '../evidence/EvidenceBoundaryContracts.js';
import type { ReviewedEvidenceFormalFindingCandidate } from '../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionContracts.js';
import type { FormalFindingCandidateRepository } from '../finding-candidate-promotion/FindingCandidatePersistenceContracts.js';
import { OBSERVED_FACT_CONTRACT_VERSION } from '../observation/ObservedFactContracts.js';
import type { ObservedFact } from '../observation/ObservedFactContracts.js';
import { ReportGenerationError } from '../reporting-boundary/DefensiveReportContracts.js';
import { DefensiveReportReadinessService } from '../reporting-boundary/DefensiveReportReadinessService.js';
import { ReportGeneratorService } from '../reporting-boundary/ReportGeneratorService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

const ASSESSMENT_ID = 'asmt_r4_doc';
const SCAN_ID = 'scan_r4_doc';
const ACTOR_ID = 'usr_secops_api';
const PLAN_ID = 'plan_r4_child';
const DEPENDS_ON = 'plan_r4_surface';
const VERSION_VALUE = 'Next.js 14.2.5';
const COOKIE_SECRET = 'fg_cookie_secret_r4';
const ATTESTATION = 'I reviewed the observed facts and the advisory plans before signing this document.';

const LINEAGE = {
  assessmentId: ASSESSMENT_ID,
  scanId: SCAN_ID,
  authorizationGrantId: 'grn_r4_001',
  authorizationDecisionId: 'dec_r4_001',
  actorId: ACTOR_ID,
} as const;

function buildFact(): ObservedFact & { readonly observationText: string } {
  return {
    contractVersion: OBSERVED_FACT_CONTRACT_VERSION,
    kind: 'observed_fact',
    factId: 'fact_r4_version',
    factKind: 'observed_tech_version',
    assessmentId: ASSESSMENT_ID,
    scanId: SCAN_ID,
    epistemicStatus: 'OBSERVED',
    value: VERSION_VALUE,
    sourceUrl: 'https://app.example.com/',
    observationKind: 'http_header',
    sourceLabel: 'response_header',
    lineage: LINEAGE,
    observedAt: '2026-09-28T12:00:00.000Z',
    observationText: `set-cookie session=${COOKIE_SECRET}`,
  };
}

function buildRecord(facts: readonly ObservedFact[]): OrchestratedAssessmentRecord {
  const nowIso = '2026-09-28T12:00:00.000Z';
  return {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId: ASSESSMENT_ID,
    scanId: SCAN_ID,
    targetDomain: 'app.example.com',
    status: 'completed',
    lineage: LINEAGE,
    stages: [],
    timing: { startedAt: nowIso, completedAt: nowIso, durationMs: 4 },
    errorCount: 0,
    warningCount: 0,
    findings: [],
    recommendations: [],
    ...(facts.length > 0 ? { observedFacts: facts } : {}),
  };
}

function buildPlan(): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: PLAN_ID,
    assessmentId: ASSESSMENT_ID,
    scanId: SCAN_ID,
    capability: 'auth_boundary_differential',
    title: 'Read the observed endpoint as identity A',
    reasoning: 'Advisory GET until the same actor authorizes this plan.',
    status: 'ready_for_authorization',
    blastRadius: 'single_endpoint',
    capabilityGained: 'read_authenticated',
    sourceFindingIds: [],
    sourceFindingTypes: ['observed_surface'],
    prerequisites: [],
    steps: [
      {
        stepId: 'step_r4_1',
        ordinal: 1,
        title: 'GET as identity A',
        description: 'Advisory read step',
        status: 'ready',
        requiredPermissions: ['activeValidation'],
      },
    ],
    planOrigin: 'observed_surface',
    dependsOn: [DEPENDS_ON],
    lineage: LINEAGE,
    createdAt: '2026-09-28T12:00:00.000Z',
    executable: false,
  };
}

function hollowCandidate(): ReviewedEvidenceFormalFindingCandidate {
  const now = '2026-09-28T12:00:00.000Z';
  const lineage: ExecutionLineage = {
    assessmentId: ASSESSMENT_ID,
    scanId: SCAN_ID,
    authorizationGrantId: 'grn_r4_001',
    authorizationDecisionId: 'dec_r4_001',
    actorId: ACTOR_ID,
    validationId: 'val_r4_001',
  };
  return {
    contractVersion: 'fixguard-reviewed-evidence-formal-finding-candidate/v0',
    kind: 'reviewed_evidence_formal_finding_candidate',
    candidateId: 'cnd_r4_hollow',
    scanId: SCAN_ID,
    createdAt: now,
    lineage,
    sourceDraft: {
      draftId: 'drf_r4_hollow',
      sourceSelectionId: 'sel_r4_001',
      selectedCount: 0,
      candidateKind: 'reviewed_evidence_group',
      triageState: 'requires_human_triage',
      confidenceState: 'evidence_grouped_not_confirmed',
    },
    humanTriage: {
      decisionId: 'dec_triage_r4_001',
      reviewerId: ACTOR_ID,
      reviewedAt: now,
      decision: 'approve_finding_candidate_promotion',
      humanApprovedPromotion: true,
    },
    evidenceRefs: {
      selectedRefs: [],
      selectedCount: 0,
    },
    observedEvidenceSummary: {
      evidenceTypeCounts: {},
      strengthCounts: {},
      indicatorIds: [],
      collectedAtRange: { earliest: now, latest: now },
      savedAtRange: { earliest: now, latest: now },
    },
    candidateState: {
      lifecycleState: 'formal_candidate_created',
      confirmationState: 'not_confirmed',
      reportState: 'not_reported',
      persistenceState: 'not_persisted',
      requiresFurtherHumanReview: true,
    },
    storage: {
      persisted: false,
      persistedToDatabase: false,
      externalized: false,
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
      noPersistence: true,
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
      executesTools: false,
    },
  };
}

async function main(): Promise<void> {
  const fact = buildFact();
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const plans = new InMemoryAttackPlanRepository();
  await repository.save(buildRecord([fact]));
  await plans.savePlan(buildPlan());
  const service = new OrchestratedAssessmentApplicationService({
    repository,
    attackPlanRepository: plans,
  });

  const summary = await service.getSummary(ASSESSMENT_ID);
  assert.ok(summary.observedFacts.some((item) => item.factKind === 'observed_tech_version' && item.value === VERSION_VALUE));

  const html = await service.generateHtmlReport(ASSESSMENT_ID, ACTOR_ID, ATTESTATION);
  assert.ok(html.includes('observed_tech_version'));
  assert.ok(html.includes(VERSION_VALUE));
  assert.ok(html.includes('OBSERVED'));
  assert.ok(html.includes('https://app.example.com/'));
  assert.ok(html.includes(PLAN_ID));
  assert.ok(html.includes(DEPENDS_ON));
  assert.ok(html.includes('Executable: false'));
  assert.equal(html.includes(COOKIE_SECRET), false);
  assert.equal(html.includes('observationText'), false);
  assert.equal(html.includes('class="epistemic-badge'), false);
  assert.ok(html.includes('No attack chains were recorded'));
  assert.equal(html.includes(`Kind: observed_tech_version`), true);

  const emptyHtml = new ReportGeneratorService().generateHtmlReport({
    assessmentRecord: buildRecord([]),
    operatorId: ACTOR_ID,
    attestationText: ATTESTATION,
  });
  assert.ok(emptyHtml.includes('No observed facts were recorded'));
  assert.equal(emptyHtml.includes(COOKIE_SECRET), false);

  const hollowRepo: FormalFindingCandidateRepository = {
    saveCandidate: async (candidate) => candidate,
    getCandidate: async () => null,
    getCandidateByDraftId: async () => null,
    listCandidatesByScanId: async () => [hollowCandidate()],
  };
  const reports = new DefensiveReportReadinessService(hollowRepo);
  await assert.rejects(
    () =>
      reports.generateReport({
        reportId: 'rpt_r4_hollow',
        sessionId: ASSESSMENT_ID,
        scanId: SCAN_ID,
        requestedAt: '2026-09-28T12:05:00.000Z',
        operatorSignatureId: ACTOR_ID,
        operatorVerifiedAt: '2026-09-28T12:05:00.000Z',
        operatorAttestationText: ATTESTATION,
      }),
    (err: unknown) =>
      err instanceof ReportGenerationError &&
      err.code === 'report_generation_aborted_insufficient_substance'
  );

  console.log('[milestone_r4_signed_document_smoke] ALL PASSED');
}

main().catch((err) => {
  console.error('[milestone_r4_signed_document_smoke] FAILED', err);
  process.exit(1);
});
