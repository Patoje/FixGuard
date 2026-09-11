import type { Request, Response, NextFunction } from 'express';
import type { DefensiveReportReadinessService } from '../../reporting-boundary/DefensiveReportReadinessService.js';
import { parseGenerateReportBody } from '../validation/ApiRequestValidators.js';

/**
 * ReportController
 *
 * Thin HTTP presentation controller for Defensive Assessment Reports (M60).
 * Strictly extracts parameters, delegates to DefensiveReportReadinessService,
 * and returns the validated defensive report artifact.
 */
export class ReportController {
  constructor(private readonly service: DefensiveReportReadinessService) {}

  public generateReport = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const command = parseGenerateReportBody(req.body);
      const report = await this.service.generateReport(command);
      res.status(201).json(report);
    } catch (err) {
      next(err);
    }
  };
}
