import { Router } from 'express';
import type { V2CompositionRoot } from '../V2CompositionRoot.js';
import { AssessmentController } from '../controllers/AssessmentController.js';
import { ReportController } from '../controllers/ReportController.js';
import { AuthorizationController } from '../controllers/AuthorizationController.js';
import { TriageController } from '../controllers/TriageController.js';

export function createV2Router(root: V2CompositionRoot): Router {
  const router = Router();

  const assessmentController = new AssessmentController(root.assessmentService);
  const reportController = new ReportController(root.reportService);
  const authController = new AuthorizationController();
  const triageController = new TriageController(root.candidateRepository, root.draftRepository);

  // Assessment endpoints
  router.post('/assessments', assessmentController.createAssessment);
  router.get('/assessments/:sessionId', assessmentController.getAssessment);
  router.post('/assessments/:sessionId/recon', assessmentController.startInitialRecon);
  router.post('/assessments/:sessionId/recommendations/approve', assessmentController.approveRecommendation);

  // Triage & Candidate Promotion endpoints (M61.1)
  router.get('/scans/:scanId/evidence-drafts', triageController.listEvidenceDrafts);
  router.post('/candidates/promote', triageController.promoteCandidate);

  // Defensive Report endpoint
  router.post('/reports', reportController.generateReport);

  // Authorization establishment endpoint
  router.post('/auth/decisions', authController.establishDecision);

  return router;
}
