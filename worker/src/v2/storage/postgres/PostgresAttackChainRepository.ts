/**
 * Phase D2 Step 2 — Postgres-backed AttackChainRepository.
 *
 * Insert-only save + replace update; defensive deserialization;
 * overallEpistemicStatus and status preserved with cross-column checks.
 */

import { eq, asc } from 'drizzle-orm';
import type { AttackChain } from '../../attack-chain/AttackChainContracts.js';
import type { AttackChainRepository } from '../../attack-chain/AttackChainRepository.js';
import {
  PersistenceConflictError,
  RecordCorruptedError,
} from '../StorageErrors.js';
import {
  cloneForPersistence,
  validateAttackChain,
} from '../AttackPlanChainPersistenceValidation.js';
import { v2_attack_chains, type V2AttackChainRow } from './schema.js';

/**
 * Minimal query surface used by this repository.
 * Implemented by drizzle clients and hermetic mock DBs (no `any`).
 */
export interface AttackChainDb {
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

export function adaptAttackChainDb(client: {
  readonly insert: AttackChainDb['insert'];
  readonly select: AttackChainDb['select'];
  readonly delete: AttackChainDb['delete'];
}): AttackChainDb {
  return {
    insert: (table) => client.insert(table),
    select: () => client.select(),
    delete: (table) => client.delete(table),
  };
}

export class PostgresAttackChainRepository implements AttackChainRepository {
  constructor(private readonly db: AttackChainDb) {}

  public async saveChain(chain: AttackChain): Promise<AttackChain> {
    if (!validateAttackChain(chain)) {
      throw new Error(
        'Invalid AttackChain: failed persistence-boundary validation'
      );
    }

    const existing = await this.getChain(chain.chainId);
    if (existing) {
      throw new PersistenceConflictError(
        `Duplicate chainId: ${chain.chainId}`,
        chain.chainId
      );
    }

    const cloned = cloneForPersistence(chain);
    await this.upsertChainRow(cloned);
    return cloneForPersistence(cloned);
  }

  public async updateChain(chain: AttackChain): Promise<AttackChain> {
    if (!validateAttackChain(chain)) {
      throw new Error(
        'Invalid AttackChain: failed persistence-boundary validation'
      );
    }

    const existing = await this.getChain(chain.chainId);
    if (!existing) {
      throw new Error(`AttackChain not found: ${chain.chainId}`);
    }
    if (
      existing.assessmentId !== chain.assessmentId ||
      existing.scanId !== chain.scanId
    ) {
      throw new Error(
        'AttackChain update rejected: assessmentId/scanId isolation violation'
      );
    }

    const cloned = cloneForPersistence(chain);
    await this.upsertChainRow(cloned);
    return cloneForPersistence(cloned);
  }

  public async getChain(chainId: string): Promise<AttackChain | null> {
    const rows = (await this.db
      .select()
      .from(v2_attack_chains)
      .where(eq(v2_attack_chains.chain_id, chainId))
      .limit(1)) as V2AttackChainRow[];

    if (rows.length === 0) {
      return null;
    }
    return this.deserializeChain(rows[0]!);
  }

  public async listByAssessmentId(
    assessmentId: string
  ): Promise<readonly AttackChain[]> {
    const rows = (await this.db
      .select()
      .from(v2_attack_chains)
      .where(eq(v2_attack_chains.assessment_id, assessmentId))
      .orderBy(
        asc(v2_attack_chains.created_at),
        asc(v2_attack_chains.chain_id)
      )) as V2AttackChainRow[];

    return rows.map((row) => this.deserializeChain(row));
  }

  public async deleteByAssessmentId(assessmentId: string): Promise<number> {
    const existing = await this.listByAssessmentId(assessmentId);
    if (existing.length === 0) {
      return 0;
    }
    await this.db
      .delete(v2_attack_chains)
      .where(eq(v2_attack_chains.assessment_id, assessmentId));
    return existing.length;
  }

  private async upsertChainRow(cloned: AttackChain): Promise<void> {
    const now = new Date();
    const createdAt = new Date(cloned.createdAt);
    const completedAt = cloned.completedAt
      ? new Date(cloned.completedAt)
      : null;

    await this.db
      .insert(v2_attack_chains)
      .values({
        chain_id: cloned.chainId,
        assessment_id: cloned.assessmentId,
        scan_id: cloned.scanId,
        status: cloned.status,
        overall_epistemic_status: cloned.overallEpistemicStatus,
        impact_level: cloned.impactLevel,
        declared_impact_level: cloned.declaredImpactLevel,
        objective_kind: cloned.objectiveKind,
        contract_version: cloned.contractVersion,
        step_count: cloned.steps.length,
        actor_id: cloned.lineage.actorId,
        authorization_grant_id: cloned.lineage.authorizationGrantId,
        authorization_decision_id: cloned.lineage.authorizationDecisionId,
        created_at: createdAt,
        completed_at: completedAt,
        updated_at: now,
        chain_json: cloned,
      })
      .onConflictDoUpdate({
        target: v2_attack_chains.chain_id,
        set: {
          assessment_id: cloned.assessmentId,
          scan_id: cloned.scanId,
          status: cloned.status,
          overall_epistemic_status: cloned.overallEpistemicStatus,
          impact_level: cloned.impactLevel,
          declared_impact_level: cloned.declaredImpactLevel,
          objective_kind: cloned.objectiveKind,
          contract_version: cloned.contractVersion,
          step_count: cloned.steps.length,
          actor_id: cloned.lineage.actorId,
          authorization_grant_id: cloned.lineage.authorizationGrantId,
          authorization_decision_id: cloned.lineage.authorizationDecisionId,
          created_at: createdAt,
          completed_at: completedAt,
          updated_at: now,
          chain_json: cloned,
        },
      });
  }

  private deserializeChain(row: V2AttackChainRow): AttackChain {
    const raw = row.chain_json;
    let isValid = false;
    try {
      isValid = validateAttackChain(raw);
    } catch {
      isValid = false;
    }
    if (!isValid) {
      throw new RecordCorruptedError(
        'Attack chain failed defensive domain deserialization validation',
        row.chain_id
      );
    }

    const entity = raw;
    if (
      row.chain_id !== entity.chainId ||
      row.assessment_id !== entity.assessmentId ||
      row.scan_id !== entity.scanId ||
      row.status !== entity.status ||
      row.overall_epistemic_status !== entity.overallEpistemicStatus ||
      row.impact_level !== entity.impactLevel ||
      row.declared_impact_level !== entity.declaredImpactLevel ||
      row.objective_kind !== entity.objectiveKind ||
      row.contract_version !== entity.contractVersion ||
      row.step_count !== entity.steps.length ||
      row.actor_id !== entity.lineage.actorId ||
      row.authorization_grant_id !== entity.lineage.authorizationGrantId ||
      row.authorization_decision_id !== entity.lineage.authorizationDecisionId
    ) {
      throw new RecordCorruptedError(
        `Relational cross-column consistency check failed for chain ${row.chain_id}`,
        row.chain_id
      );
    }

    return cloneForPersistence(entity);
  }
}
