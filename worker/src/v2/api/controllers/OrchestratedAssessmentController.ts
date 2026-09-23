/**
 * FixGuard V2 — Orchestrated Assessment Controller
 *
 * Presentation controller handling HTTP requests for orchestrated assessments:
 * - POST /api/v2/orchestrated/assessments/start
 * - GET /api/v2/orchestrated/assessments/:assessmentId/summary
 * - GET /api/v2/orchestrated/assessments/:assessmentId/status
 * - GET /api/v2/assessments/:assessmentId/attack-surface (Milestone A2)
 * - GET /api/v2/assessments/:assessmentId/attack-plans (Milestone A3)
 *
 * Responsibilities:
 * 1) Extract and validate path parameters and request body.
 * 2) Delegate to OrchestratedAssessmentApplicationService.
 * 3) Return appropriate HTTP status codes (202 Accepted, 200 OK).
 */

import type { Request, Response, NextFunction } from 'express';
import type { OrchestratedAssessmentApplicationService } from '../../application/OrchestratedAssessmentApplicationService.js';
import {
  parseStartOrchestratedAssessmentBody,
  parseReviewEvidenceDraftBody,
  parseGenerateHtmlReportHttpBody,
} from '../validation/ApiRequestValidators.js';
import { isStrictSafeId } from '../../reporting-boundary/DefensiveReportContracts.js';
import { ApiValidationError } from '../ApiErrors.js';

export class OrchestratedAssessmentController {
  constructor(private readonly service: OrchestratedAssessmentApplicationService) {}

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
}

