/**
 * FixGuard V2 — Capability Status Controller (Milestone P0-3)
 *
 * Presentation controller handling HTTP requests for capability status:
 * - GET /api/v2/capabilities/status
 *
 * Exposes the execution environment's binary capability matrix.
 */

import type { Request, Response, NextFunction } from 'express';
import type { ReconToolAvailabilityService } from '../../capabilities/ReconToolAvailabilityService.js';

export class CapabilityStatusController {
  constructor(private readonly service: ReconToolAvailabilityService) {}

  public getStatus = async (
    _req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const result = await this.service.checkAllTools();
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };
}
