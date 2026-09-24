/**
 * Phase D2 Step 2 — Postgres-backed AttackPlanRepository.
 *
 * Insert-only save (duplicate planId → PersistenceConflictError),
 * defensive deserialization, lineage continuity, non-executable invariant.
 */

import { eq, asc } from 'drizzle-orm';
import type { AttackPlan } from '../../attack-planning/AttackPlanContracts.js';
import type { AttackPlanRepository } from '../../attack-planning/AttackPlanRepository.js';
import {
  PersistenceConflictError,
  RecordCorruptedError,
} from '../StorageErrors.js';
import {
  cloneForPersistence,
  validateAttackPlan,
} from '../AttackPlanChainPersistenceValidation.js';
import { v2_attack_plans, type V2AttackPlanRow } from './schema.js';

/**
 * Minimal query surface used by this repository.
 * Implemented by drizzle clients and hermetic mock DBs (no `any`).
 */
export interface AttackPlanDb {
  insert(table: unknown): {
    values(data: unknown): {
      onConflictDoUpdate(config: {
        target: unknown;
        set: Record<string, unknown>;
      }): PromiseLike<unknown>;
    };
  };
  select(): {
    from(table: unknown): {
      where(expr: unknown): {
        limit(n: number): PromiseLike<unknown[]>;
        orderBy(...args: unknown[]): PromiseLike<unknown[]>;
      };
      orderBy(...args: unknown[]): PromiseLike<unknown[]>;
    };
  };
  delete(table: unknown): {
    where(expr: unknown): PromiseLike<unknown>;
  };
}

export function adaptAttackPlanDb(client: {
  readonly insert: AttackPlanDb['insert'];
  readonly select: AttackPlanDb['select'];
  readonly delete: AttackPlanDb['delete'];
}): AttackPlanDb {
  return {
    insert: (table) => client.insert(table),
    select: () => client.select(),
    delete: (table) => client.delete(table),
  };
}

export class PostgresAttackPlanRepository implements AttackPlanRepository {
  constructor(private readonly db: AttackPlanDb) {}

  public async savePlan(plan: AttackPlan): Promise<AttackPlan> {
    if (!validateAttackPlan(plan)) {
      throw new Error(
        'Invalid AttackPlan: failed persistence-boundary validation'
      );
    }
    if (plan.executable !== false) {
      throw new Error('Invalid AttackPlan: executable must be false');
    }

    const existing = await this.getPlan(plan.planId);
    if (existing) {
      throw new PersistenceConflictError(
        `Duplicate planId: ${plan.planId}`,
        plan.planId
      );
    }

    const cloned = cloneForPersistence(plan);
    const now = new Date();
    const createdAt = new Date(cloned.createdAt);

    // Insert-only semantics: existence is checked above (PersistenceConflictError).
    // onConflictDoUpdate matches the shared drizzle/mock adapter surface used by chains.
    await this.db
      .insert(v2_attack_plans)
      .values({
        plan_id: cloned.planId,
        assessment_id: cloned.assessmentId,
        scan_id: cloned.scanId,
        status: cloned.status,
        capability: cloned.capability,
        contract_version: cloned.contractVersion,
        actor_id: cloned.lineage.actorId,
        authorization_grant_id: cloned.lineage.authorizationGrantId,
        authorization_decision_id: cloned.lineage.authorizationDecisionId,
        executable: false,
        created_at: createdAt,
        updated_at: now,
        plan_json: cloned,
      })
      .onConflictDoUpdate({
        target: v2_attack_plans.plan_id,
        set: {
          assessment_id: cloned.assessmentId,
          scan_id: cloned.scanId,
          status: cloned.status,
          capability: cloned.capability,
          contract_version: cloned.contractVersion,
          actor_id: cloned.lineage.actorId,
          authorization_grant_id: cloned.lineage.authorizationGrantId,
          authorization_decision_id: cloned.lineage.authorizationDecisionId,
          executable: false,
          created_at: createdAt,
          updated_at: now,
          plan_json: cloned,
        },
      });

    return cloneForPersistence(cloned);
  }

  public async savePlans(
    plans: readonly AttackPlan[]
  ): Promise<readonly AttackPlan[]> {
    const saved: AttackPlan[] = [];
    for (const plan of plans) {
      saved.push(await this.savePlan(plan));
    }
    return saved;
  }

  public async getPlan(planId: string): Promise<AttackPlan | null> {
    const rows = (await this.db
      .select()
      .from(v2_attack_plans)
      .where(eq(v2_attack_plans.plan_id, planId))
      .limit(1)) as V2AttackPlanRow[];

    if (rows.length === 0) {
      return null;
    }
    return this.deserializePlan(rows[0]!);
  }

  public async listByAssessmentId(
    assessmentId: string
  ): Promise<readonly AttackPlan[]> {
    const rows = (await this.db
      .select()
      .from(v2_attack_plans)
      .where(eq(v2_attack_plans.assessment_id, assessmentId))
      .orderBy(
        asc(v2_attack_plans.created_at),
        asc(v2_attack_plans.plan_id)
      )) as V2AttackPlanRow[];

    return rows.map((row) => this.deserializePlan(row));
  }

  public async deleteByAssessmentId(assessmentId: string): Promise<number> {
    const existing = await this.listByAssessmentId(assessmentId);
    if (existing.length === 0) {
      return 0;
    }
    await this.db
      .delete(v2_attack_plans)
      .where(eq(v2_attack_plans.assessment_id, assessmentId));
    return existing.length;
  }

  private deserializePlan(row: V2AttackPlanRow): AttackPlan {
    const raw = row.plan_json;
    let isValid = false;
    try {
      isValid = validateAttackPlan(raw);
    } catch {
      isValid = false;
    }
    if (!isValid) {
      throw new RecordCorruptedError(
        'Attack plan failed defensive domain deserialization validation',
        row.plan_id
      );
    }

    const entity = raw;
    if (
      row.plan_id !== entity.planId ||
      row.assessment_id !== entity.assessmentId ||
      row.scan_id !== entity.scanId ||
      row.status !== entity.status ||
      row.capability !== entity.capability ||
      row.contract_version !== entity.contractVersion ||
      row.actor_id !== entity.lineage.actorId ||
      row.authorization_grant_id !== entity.lineage.authorizationGrantId ||
      row.authorization_decision_id !== entity.lineage.authorizationDecisionId ||
      row.executable !== false ||
      entity.executable !== false
    ) {
      throw new RecordCorruptedError(
        `Relational cross-column consistency check failed for plan ${row.plan_id}`,
        row.plan_id
      );
    }

    return cloneForPersistence(entity);
  }
}
