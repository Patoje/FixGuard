/**
 * Phase D2 — Postgres-backed OrchestratedAssessmentRepository.
 *
 * Persists assessment records and Attack Surface Graph projections with
 * defensive deserialization, lineage continuity, and epistemic preservation.
 */

import { eq, asc } from 'drizzle-orm';
import type {
  OrchestratedAssessmentRecord,
  OrchestratedAssessmentRepository,
} from '../../application/OrchestratedAssessmentContracts.js';
import type { AttackSurfaceGraph } from '../../attack-surface/AttackSurfaceContracts.js';
import { RecordCorruptedError, RecordNotFoundError } from '../StorageErrors.js';
import {
  cloneForPersistence,
  countEpistemicByStatus,
  validateAttackSurfaceGraph,
  validateOrchestratedAssessmentRecord,
} from '../OrchestratedAssessmentPersistenceValidation.js';
import {
  v2_attack_surface_graphs,
  v2_orchestrated_assessments,
  type V2AttackSurfaceGraphRow,
  type V2OrchestratedAssessmentRow,
} from './schema.js';

/**
 * Minimal query surface used by this repository.
 * Implemented by drizzle clients and hermetic mock DBs (no `any`).
 */
export interface OrchestratedAssessmentDb {
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

/**
 * Adapt a drizzle (or drizzle-like) client without `as` casts in call sites.
 * Structural forwarding keeps production free of `any` / force-cast shortcuts.
 */
export function adaptOrchestratedAssessmentDb(client: {
  readonly insert: OrchestratedAssessmentDb['insert'];
  readonly select: OrchestratedAssessmentDb['select'];
  readonly delete: OrchestratedAssessmentDb['delete'];
}): OrchestratedAssessmentDb {
  return {
    insert: (table) => client.insert(table),
    select: () => client.select(),
    delete: (table) => client.delete(table),
  };
}

export class PostgresOrchestratedAssessmentRepository
  implements OrchestratedAssessmentRepository
{
  constructor(private readonly db: OrchestratedAssessmentDb) {}

  public async save(record: OrchestratedAssessmentRecord): Promise<void> {
    if (!validateOrchestratedAssessmentRecord(record)) {
      throw new Error(
        'Invalid OrchestratedAssessmentRecord: failed persistence-boundary validation'
      );
    }

    const cloned = cloneForPersistence(record);
    const now = new Date();
    const startedAt = new Date(cloned.timing.startedAt);
    const completedAt = cloned.timing.completedAt
      ? new Date(cloned.timing.completedAt)
      : null;
    const hasGraph = cloned.attackSurfaceGraph !== undefined;
    const graphId = cloned.attackSurfaceGraph?.graphId ?? null;

    await this.db
      .insert(v2_orchestrated_assessments)
      .values({
        assessment_id: cloned.assessmentId,
        scan_id: cloned.scanId,
        target_domain: cloned.targetDomain,
        status: cloned.status,
        contract_version: cloned.contractVersion,
        actor_id: cloned.lineage.actorId,
        authorization_grant_id: cloned.lineage.authorizationGrantId,
        authorization_decision_id: cloned.lineage.authorizationDecisionId,
        has_attack_surface_graph: hasGraph,
        graph_id: graphId,
        started_at: startedAt,
        completed_at: completedAt,
        updated_at: now,
        record_json: cloned,
      })
      .onConflictDoUpdate({
        target: v2_orchestrated_assessments.assessment_id,
        set: {
          scan_id: cloned.scanId,
          target_domain: cloned.targetDomain,
          status: cloned.status,
          contract_version: cloned.contractVersion,
          actor_id: cloned.lineage.actorId,
          authorization_grant_id: cloned.lineage.authorizationGrantId,
          authorization_decision_id: cloned.lineage.authorizationDecisionId,
          has_attack_surface_graph: hasGraph,
          graph_id: graphId,
          started_at: startedAt,
          completed_at: completedAt,
          updated_at: now,
          record_json: cloned,
        },
      });

    if (cloned.attackSurfaceGraph) {
      await this.upsertAttackSurfaceGraph(cloned.attackSurfaceGraph, now);
    } else {
      await this.db
        .delete(v2_attack_surface_graphs)
        .where(eq(v2_attack_surface_graphs.assessment_id, cloned.assessmentId));
    }
  }

  public async findById(
    assessmentId: string
  ): Promise<OrchestratedAssessmentRecord | null> {
    const rows = (await this.db
      .select()
      .from(v2_orchestrated_assessments)
      .where(eq(v2_orchestrated_assessments.assessment_id, assessmentId))
      .limit(1)) as V2OrchestratedAssessmentRow[];

    if (rows.length === 0) {
      return null;
    }
    return this.deserializeAssessment(rows[0]!);
  }

  public async list(): Promise<readonly OrchestratedAssessmentRecord[]> {
    const rows = (await this.db
      .select()
      .from(v2_orchestrated_assessments)
      .orderBy(asc(v2_orchestrated_assessments.assessment_id))) as V2OrchestratedAssessmentRow[];

    return rows.map((row) => this.deserializeAssessment(row));
  }

  public async update(
    assessmentId: string,
    updater: (prev: OrchestratedAssessmentRecord) => OrchestratedAssessmentRecord
  ): Promise<OrchestratedAssessmentRecord> {
    const existing = await this.findById(assessmentId);
    if (!existing) {
      throw new RecordNotFoundError(
        `Orchestrated assessment '${assessmentId}' not found`,
        assessmentId
      );
    }
    const updated = updater(cloneForPersistence(existing));
    await this.save(updated);
    const reloaded = await this.findById(assessmentId);
    if (!reloaded) {
      throw new RecordCorruptedError(
        `Orchestrated assessment '${assessmentId}' missing after update`,
        assessmentId
      );
    }
    return reloaded;
  }

  /** Independent ASG reload path (projection table). */
  public async findAttackSurfaceGraphByAssessmentId(
    assessmentId: string
  ): Promise<AttackSurfaceGraph | null> {
    const rows = (await this.db
      .select()
      .from(v2_attack_surface_graphs)
      .where(eq(v2_attack_surface_graphs.assessment_id, assessmentId))
      .limit(1)) as V2AttackSurfaceGraphRow[];

    if (rows.length === 0) {
      return null;
    }
    return this.deserializeAttackSurfaceGraph(rows[0]!);
  }

  private async upsertAttackSurfaceGraph(
    graph: AttackSurfaceGraph,
    updatedAt: Date
  ): Promise<void> {
    if (!validateAttackSurfaceGraph(graph)) {
      throw new Error(
        'Invalid AttackSurfaceGraph: failed persistence-boundary validation'
      );
    }
    const cloned = cloneForPersistence(graph);
    const counts = countEpistemicByStatus(cloned);

    await this.db
      .insert(v2_attack_surface_graphs)
      .values({
        graph_id: cloned.graphId,
        assessment_id: cloned.assessmentId,
        scan_id: cloned.scanId,
        target_host: cloned.targetHost,
        contract_version: cloned.contractVersion,
        built_at: new Date(cloned.builtAt),
        node_count: cloned.nodes.length,
        edge_count: cloned.edges.length,
        observed_node_count: counts.observed,
        inferred_node_count: counts.inferred,
        verified_node_count: counts.verified,
        refuted_node_count: counts.refuted,
        actor_id: cloned.lineage.actorId,
        authorization_grant_id: cloned.lineage.authorizationGrantId,
        authorization_decision_id: cloned.lineage.authorizationDecisionId,
        graph_json: cloned,
        updated_at: updatedAt,
      })
      .onConflictDoUpdate({
        target: v2_attack_surface_graphs.graph_id,
        set: {
          assessment_id: cloned.assessmentId,
          scan_id: cloned.scanId,
          target_host: cloned.targetHost,
          contract_version: cloned.contractVersion,
          built_at: new Date(cloned.builtAt),
          node_count: cloned.nodes.length,
          edge_count: cloned.edges.length,
          observed_node_count: counts.observed,
          inferred_node_count: counts.inferred,
          verified_node_count: counts.verified,
          refuted_node_count: counts.refuted,
          actor_id: cloned.lineage.actorId,
          authorization_grant_id: cloned.lineage.authorizationGrantId,
          authorization_decision_id: cloned.lineage.authorizationDecisionId,
          graph_json: cloned,
          updated_at: updatedAt,
        },
      });
  }

  private deserializeAssessment(
    row: V2OrchestratedAssessmentRow
  ): OrchestratedAssessmentRecord {
    const raw = row.record_json;
    let isValid = false;
    try {
      isValid = validateOrchestratedAssessmentRecord(raw);
    } catch {
      isValid = false;
    }
    if (!isValid) {
      throw new RecordCorruptedError(
        'Orchestrated assessment failed defensive domain deserialization validation',
        row.assessment_id
      );
    }

    const entity = raw;
    if (
      row.assessment_id !== entity.assessmentId ||
      row.scan_id !== entity.scanId ||
      row.target_domain !== entity.targetDomain ||
      row.status !== entity.status ||
      row.contract_version !== entity.contractVersion ||
      row.actor_id !== entity.lineage.actorId ||
      row.authorization_grant_id !== entity.lineage.authorizationGrantId ||
      row.authorization_decision_id !== entity.lineage.authorizationDecisionId ||
      row.has_attack_surface_graph !== (entity.attackSurfaceGraph !== undefined) ||
      (row.graph_id ?? null) !== (entity.attackSurfaceGraph?.graphId ?? null)
    ) {
      throw new RecordCorruptedError(
        `Relational cross-column consistency check failed for assessment ${row.assessment_id}`,
        row.assessment_id
      );
    }

    return cloneForPersistence(entity);
  }

  private deserializeAttackSurfaceGraph(
    row: V2AttackSurfaceGraphRow
  ): AttackSurfaceGraph {
    const raw = row.graph_json;
    let isValid = false;
    try {
      isValid = validateAttackSurfaceGraph(raw);
    } catch {
      isValid = false;
    }
    if (!isValid) {
      throw new RecordCorruptedError(
        'Attack surface graph failed defensive domain deserialization validation',
        row.graph_id
      );
    }

    const entity = raw;
    const counts = countEpistemicByStatus(entity);
    if (
      row.graph_id !== entity.graphId ||
      row.assessment_id !== entity.assessmentId ||
      row.scan_id !== entity.scanId ||
      row.target_host !== entity.targetHost ||
      row.contract_version !== entity.contractVersion ||
      row.node_count !== entity.nodes.length ||
      row.edge_count !== entity.edges.length ||
      row.observed_node_count !== counts.observed ||
      row.inferred_node_count !== counts.inferred ||
      row.verified_node_count !== counts.verified ||
      row.refuted_node_count !== counts.refuted ||
      row.actor_id !== entity.lineage.actorId ||
      row.authorization_grant_id !== entity.lineage.authorizationGrantId ||
      row.authorization_decision_id !== entity.lineage.authorizationDecisionId
    ) {
      throw new RecordCorruptedError(
        `Relational cross-column consistency check failed for ASG ${row.graph_id}`,
        row.graph_id
      );
    }

    return cloneForPersistence(entity);
  }
}
