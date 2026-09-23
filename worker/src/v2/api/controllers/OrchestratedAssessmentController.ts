/**
 * FixGuard V2 — Orchestrated Assessment Controller
 *
 * Presentation controller handling HTTP requests for orchestrated assessments:
 * - POST /api/v2/orchestrated/assessments/start
 * - GET /api/v2/orchestrated/assessments/:assessmentId/summary
 * - GET /api/v2/orchestrated/assessments/:assessmentId/status
 * - GET /api/v2/assessments/:assessmentId/attack-surface (Milestone A2)
 * - GET /api/v2/assessments/:assessmentId/attack-plans (Milestone A3)
 * - POST /api/v2/assessments/:assessmentId/attack-plans/:planId/authorize (Milestone A4)
 *
 * Responsibilities:
 * 1) Extract and validate path parameters and request body.
 * 2) Delegate to OrchestratedAssessmentApplicationService / AttackAuthorizationService.
 * 3) Return appropriate HTTP status codes (202 Accepted, 200 OK, 201 Created).
 */

import type { Request, Response, NextFunction } from 'express';
import type { OrchestratedAssessmentApplicationService } from '../../application/OrchestratedAssessmentApplicationService.js';
import type { AttackAuthorizationService } from '../../attack-authorization/AttackAuthorizationService.js';
import { ATTACK_AUTHORIZATION_CONTRACT_VERSION } from '../../attack-authorization/AttackAuthorizationContracts.js';
import {
  parseStartOrchestratedAssessmentBody,
  parseReviewEvidenceDraftBody,
  parseGenerateHtmlReportHttpBody,
} from '../validation/ApiRequestValidators.js';
import { isStrictSafeId } from '../../reporting-boundary/DefensiveReportContracts.js';
import { ApiValidationError, UnauthorizedGatewayError } from '../ApiErrors.js';

export class OrchestratedAssessmentController {
  constructor(
    private readonly service: OrchestratedAssessmentApplicationService,
    private readonly attackAuthorizationService?: AttackAuthorizationService
  ) {}

  public startAssessment = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const command = parseStartOrchestratedAssessmentBody(req.body);
      const result = await this.service.startAssessment(command);
      res.status(202).json(result);
    } catch (err) {
      next(err);
    }
  };

  public getStatus = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const status = await this.service.getStatus(assessmentId);
      res.status(200).json(status);
    } catch (err) {
      next(err);
    }
  };

  public getSummary = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const summary = await this.service.getSummary(assessmentId);
      res.status(200).json(summary);
    } catch (err) {
      next(err);
    }
  };

  public getAttackSurface = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const result = await this.service.getAttackSurface(assessmentId);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };

  public getAttackPlans = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const result = await this.service.getAttackPlans(assessmentId);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };

  public getEvidenceDrafts = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const drafts = await this.service.getEvidenceDrafts(assessmentId);
      res.status(200).json(drafts);
    } catch (err) {
      next(err);
    }
  };

  public reviewEvidenceDraft = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      const draftId = req.params.draftId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }
      if (!draftId || typeof draftId !== 'string' || !isStrictSafeId(draftId)) {
        throw new ApiValidationError('Field draftId must satisfy strict identifier format');
      }

      const body = parseReviewEvidenceDraftBody(req.body);
      const result = await this.service.reviewEvidenceDraft({
        assessmentId,
        draftId,
        decision: body.decision,
        reviewerId: body.reviewerId,
        reviewedAt: body.reviewedAt,
        ...(body.notes ? { notes: body.notes } : {}),
      });

      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };

  public generateHtmlReport = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const body = parseGenerateHtmlReportHttpBody(req.body);
      const html = await this.service.generateHtmlReport(
        assessmentId,
        body.operatorId,
        body.attestationText
      );

      res.setHeader('Content-Type', 'text/html; charset=utf-8').status(200).send(html);
    } catch (err) {
      next(err);
    }
  };

  /**
   * Milestone A4 — mint a runtime-branded AttackAuthorizationToken for a plan.
   * Does not execute attacks. Self-authorization flags are rejected by the service.
   */
  public authorizeAttackPlan = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      if (!this.attackAuthorizationService) {
        throw new ApiValidationError('Attack authorization service is not configured');
      }

      const assessmentId = req.params.assessmentId;
      const planId = req.params.planId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }
      if (!planId || typeof planId !== 'string' || !isStrictSafeId(planId)) {
        throw new ApiValidationError('Field planId must satisfy strict identifier format');
      }

      if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        throw new ApiValidationError('Authorization request body must be a non-empty object');
      }

      const body = req.body as Record<string, unknown>;
      const operatorId = body.operatorId;
      const blastRadiusClass = body.blastRadiusClass;
      if (typeof operatorId !== 'string' || !isStrictSafeId(operatorId)) {
        throw new ApiValidationError('Field operatorId must satisfy strict identifier format');
      }
      if (typeof blastRadiusClass !== 'string') {
        throw new ApiValidationError('Field blastRadiusClass must be a closed-world string');
      }

      const result = this.attackAuthorizationService.establishAttackAuthorization({
        contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
        kind: 'establish_attack_authorization_request',
        planId,
        assessmentId,
        blastRadiusClass,
        operatorId,
        ...(typeof body.authorizedAt === 'string' ? { authorizedAt: body.authorizedAt } : {}),
      });

      if (result.status === 'failed') {
        if (result.reasonCode === 'blast_radius_class_prohibited') {
          throw new UnauthorizedGatewayError(result.safeMessage, result.reasonCode);
        }
        throw new ApiValidationError(result.safeMessage);
      }

      res.status(201).json({
        status: 'established',
        reasonCode: result.reasonCode,
        token: {
          planId: result.token.planId,
          assessmentId: result.token.assessmentId,
          blastRadiusClass: result.token.blastRadiusClass,
          authorizationLevel: result.token.authorizationLevel,
          authorizedBy: result.token.authorizedBy,
          authorizedAt: result.token.authorizedAt,
        },
      });
    } catch (err) {
      next(err);
    }
  };
}

