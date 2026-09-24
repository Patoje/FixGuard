import { Router } from 'express';
import type { V2CompositionRoot } from '../V2CompositionRoot.js';
import { AssessmentController } from '../controllers/AssessmentController.js';
import { ReportController } from '../controllers/ReportController.js';
import { AuthorizationController } from '../controllers/AuthorizationController.js';
import { TriageController } from '../controllers/TriageController.js';
import { OrchestratedAssessmentController } from '../controllers/OrchestratedAssessmentController.js';
import { CapabilityStatusController } from '../controllers/CapabilityStatusController.js';

export function createV2Router(root: V2CompositionRoot): Router {
  const router = Router();

  const assessmentController = new AssessmentController(root.assessmentService);
  const reportController = new ReportController(root.reportService);
  const authController = new AuthorizationController();
  const triageController = new TriageController(root.candidateRepository, root.draftRepository);
  const orchestratedController = new OrchestratedAssessmentController(
    root.orchestratedService,
    root.attackAuthorizationService,
    root.attackExecutionService
  );
  const capabilityController = new CapabilityStatusController(root.availabilityService);

  // Capability Status endpoint (Milestone P0-3)
  router.get('/capabilities/status', capabilityController.getStatus);

  // Assessment endpoints
  router.post('/assessments', assessmentController.createAssessment);
  router.get('/assessments/:sessionId', assessmentController.getAssessment);
  router.post('/assessments/:sessionId/recon', assessmentController.startInitialRecon);
  router.post('/assessments/:sessionId/recommendations/approve', assessmentController.approveRecommendation);

  // Milestone A2 — Attack Surface Graph read model
  router.get('/assessments/:assessmentId/attack-surface', orchestratedController.getAttackSurface);
  // Milestone A3 — Attack Plans read model (advisory only)
  router.get('/assessments/:assessmentId/attack-plans', orchestratedController.getAttackPlans);
  // Milestone A6 — Attack Chain Tracker read model
  router.get('/assessments/:assessmentId/attack-chains', orchestratedController.getAttackChains);
  // Milestone A10 — Post-exploitation snapshot (no secrets)
  router.get(
    '/assessments/:assessmentId/post-exploitation',
    orchestratedController.getPostExploitation
  );
  // Milestone A4 — Graduated attack-plan authorization (runtime brand; not execution)
  router.post(
    '/assessments/:assessmentId/attack-plans/:planId/authorize',
    orchestratedController.authorizeAttackPlan
  );
  // Milestone A5 — Attack plan execution (7 safety gates + branded token)
  router.post(
    '/assessments/:assessmentId/attack-plans/:planId/execute',
    orchestratedController.executeAttackPlan
  );

  // Triage & Candidate Promotion endpoints (M61.1)
  router.get('/scans/:scanId/evidence-drafts', triageController.listEvidenceDrafts);
  router.post('/candidates/promote', triageController.promoteCandidate);

  // Defensive Report endpoint
  router.post('/reports', reportController.generateReport);

  // Authorization establishment endpoint
  router.post('/auth/decisions', authController.establishDecision);

  // Orchestrated Assessment endpoints (Milestone F6 & P1-3 & P2-6)
  router.post('/orchestrated/assessments/start', orchestratedController.startAssessment);
  router.get('/orchestrated/assessments/:assessmentId/summary', orchestratedController.getSummary);
  router.get('/orchestrated/assessments/:assessmentId/status', orchestratedController.getStatus);
  router.get('/orchestrated/assessments/:assessmentId/evidence-drafts', orchestratedController.getEvidenceDrafts);
  router.get('/orchestrated/assessments/:assessmentId/attack-surface', orchestratedController.getAttackSurface);
  router.get('/orchestrated/assessments/:assessmentId/attack-plans', orchestratedController.getAttackPlans);
  router.get('/orchestrated/assessments/:assessmentId/attack-chains', orchestratedController.getAttackChains);
  router.get(
    '/orchestrated/assessments/:assessmentId/post-exploitation',
    orchestratedController.getPostExploitation
  );
  router.post('/orchestrated/assessments/:assessmentId/evidence/:draftId/review', orchestratedController.reviewEvidenceDraft);
  router.post('/orchestrated/assessments/:assessmentId/report/html', orchestratedController.generateHtmlReport);

  return router;
}

