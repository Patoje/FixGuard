/**
 * Milestone A3 — In-memory AttackPlanRepository
 *
 * Hermetic, mutation-safe persistence for advisory attack plans.
 */

import type { AttackPlan } from './AttackPlanContracts.js';
import type { AttackPlanRepository } from './AttackPlanRepository.js';
import { PersistenceConflictError } from '../storage/StorageErrors.js';

function isAttackPlanShape(value: unknown): value is AttackPlan {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const rec = value as Record<string, unknown>;
  return (
    rec.contractVersion === 'fixguard-attack-planning/v0' &&
    rec.kind === 'attack_plan' &&
    typeof rec.planId === 'string' &&
    typeof rec.assessmentId === 'string' &&
    typeof rec.scanId === 'string' &&
    rec.executable === false &&
    Array.isArray(rec.prerequisites) &&
    Array.isArray(rec.steps) &&
    typeof rec.status === 'string' &&
    typeof rec.capability === 'string'
  );
}

export class InMemoryAttackPlanRepository implements AttackPlanRepository {
  private readonly plans = new Map<string, AttackPlan>();

  private clone(plan: AttackPlan): AttackPlan {
    return JSON.parse(JSON.stringify(plan)) as AttackPlan;
  }

  async savePlan(plan: AttackPlan): Promise<AttackPlan> {
    if (!isAttackPlanShape(plan)) {
      throw new Error('Invalid AttackPlan: failed exact-key shape validation');
    }
    if (plan.executable !== false) {
      throw new Error('Invalid AttackPlan: executable must be false');
    }
    if (this.plans.has(plan.planId)) {
      throw new PersistenceConflictError(`Duplicate planId: ${plan.planId}`, plan.planId);
    }
    const cloned = this.clone(plan);
    this.plans.set(cloned.planId, cloned);
    return this.clone(cloned);
  }

  async savePlans(plans: readonly AttackPlan[]): Promise<readonly AttackPlan[]> {
    const saved: AttackPlan[] = [];
    for (const plan of plans) {
      saved.push(await this.savePlan(plan));
    }
    return saved;
  }

  async getPlan(planId: string): Promise<AttackPlan | null> {
    const plan = this.plans.get(planId);
    return plan ? this.clone(plan) : null;
  }

  async listByAssessmentId(assessmentId: string): Promise<readonly AttackPlan[]> {
    const matched = Array.from(this.plans.values()).filter((p) => p.assessmentId === assessmentId);
    matched.sort((a, b) => {
      const t = a.createdAt.localeCompare(b.createdAt);
      if (t !== 0) return t;
      return a.planId.localeCompare(b.planId);
    });
    return matched.map((p) => this.clone(p));
  }

  async deleteByAssessmentId(assessmentId: string): Promise<number> {
    let removed = 0;
    for (const [id, plan] of this.plans.entries()) {
      if (plan.assessmentId === assessmentId) {
        this.plans.delete(id);
        removed += 1;
      }
    }
    return removed;
  }
}
