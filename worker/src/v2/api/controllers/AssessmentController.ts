import type { Request, Response, NextFunction } from 'express';
import type { AssessmentApplicationService } from '../../application/AssessmentApplicationService.js';
import { parseCreateAssessmentBody, parseApproveRecommendationBody } from '../validation/ApiRequestValidators.js';
import { SessionNotFoundError } from '../../storage/StorageErrors.js';
import { ApiValidationError } from '../ApiErrors.js';
import { isStrictSafeId } from '../../reporting-boundary/DefensiveReportContracts.js';

/**
 * AssessmentController
 *
 * Thin HTTP presentation controller for FixGuard V2 assessments.
 * Responsibilities are strictly limited to:
 * 1) Extracting parameters and request body.
 * 2) Calling AssessmentApplicationService.
 * 3) Returning JSON responses.
 *
 * Zero domain logic, zero speculation, zero direct DB access.
 */
export class AssessmentController {
  constructor(private readonly service: AssessmentApplicationService) {}

  public createAssessment = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const command = parseCreateAssessmentBody(req.body);
      const summary = await this.service.createAssessment(command);
      res.status(201).json(summary);
    } catch (err) {
      next(err);
    }
  };

  public getAssessment = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const sessionId = req.params.sessionId;
      if (!sessionId || typeof sessionId !== 'string' || !isStrictSafeId(sessionId)) {
        throw new ApiValidationError('sessionId parameter has invalid format');
      }

      const details = await this.service.loadAssessment({ sessionId });
      if (!details) {
        throw new SessionNotFoundError(`Assessment session '${sessionId}' was not found`, sessionId);
      }

      res.status(200).json(details);
    } catch (err) {
      next(err);
    }
  };

  public startInitialRecon = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const sessionId = req.params.sessionId;
      if (!sessionId || typeof sessionId !== 'string' || !isStrictSafeId(sessionId)) {
        throw new ApiValidationError('sessionId parameter has invalid format');
      }

      const details = await this.service.startInitialRecon({ sessionId });
      res.status(200).json(details);
    } catch (err) {
      next(err);
    }
  };

  public approveRecommendation = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const sessionId = req.params.sessionId;
      if (!sessionId || typeof sessionId !== 'string' || !isStrictSafeId(sessionId)) {
        throw new ApiValidationError('sessionId parameter has invalid format');
      }

      const body = parseApproveRecommendationBody(req.body);
      const details = await this.service.approveRecommendation({
        sessionId,
        recommendationId: body.recommendationId,
        operatorId: body.operatorId
      });

      res.status(200).json(details);
    } catch (err) {
      next(err);
    }
  };
}
