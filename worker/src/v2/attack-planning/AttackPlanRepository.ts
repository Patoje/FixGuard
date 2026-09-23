/**
 * Milestone A3 — AttackPlanRepository port
 *
 * Persistence boundary for advisory AttackPlan records.
 * Implementations must deep-clone on write/read to prevent shared mutation.
 */

import type { AttackPlan } from './AttackPlanContracts.js';

export interface AttackPlanRepository {
  savePlan(plan: AttackPlan): Promise<AttackPlan>;
  savePlans(plans: readonly AttackPlan[]): Promise<readonly AttackPlan[]>;
  getPlan(planId: string): Promise<AttackPlan | null>;
  listByAssessmentId(assessmentId: string): Promise<readonly AttackPlan[]>;
  deleteByAssessmentId(assessmentId: string): Promise<number>;
}
