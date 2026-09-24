/**
 * Phase D2 — durable composition helpers for OrchestratedAssessment + ASG.
 *
 * Default V2CompositionRoot remains InMemory (ADR-011 hermetic).
 * Call createDurableV2CompositionFromEnv() when Postgres opt-in + DATABASE_URL are set.
 */

import { Pool } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import {
  V2CompositionRoot,
  type V2CompositionDependencies,
} from '../../api/V2CompositionRoot.js';
import {
  adaptOrchestratedAssessmentDb,
  PostgresOrchestratedAssessmentRepository,
  type OrchestratedAssessmentDb,
} from '../postgres/PostgresOrchestratedAssessmentRepository.js';

export type DurableV2Composition = {
  readonly root: V2CompositionRoot;
  readonly mode: 'memory' | 'postgres';
  readonly close: () => Promise<void>;
};

export type DurableCompositionOptions = {
  readonly databaseUrl?: string;
  readonly forceMemory?: boolean;
  readonly dependencies?: Omit<V2CompositionDependencies, 'orchestratedRepository'>;
};

function resolveDatabaseUrl(options: DurableCompositionOptions): string | undefined {
  return (
    options.databaseUrl ??
    process.env.FIXGUARD_V2_DATABASE_URL ??
    process.env.DATABASE_URL
  );
}

/**
 * Opt-in durable composition.
 *
 * Uses Postgres when:
 * - forceMemory is not set, AND
 * - FIXGUARD_V2_ORCHESTRATED_REPOSITORY=postgres with a database URL, OR
 * - FIXGUARD_V2_ENABLE_POSTGRES_ORCHESTRATED=1 with FIXGUARD_V2_DATABASE_URL / DATABASE_URL
 *
 * Otherwise returns InMemory-backed composition (safe hermetic default).
 */
export async function createDurableV2CompositionFromEnv(
  options: DurableCompositionOptions = {}
): Promise<DurableV2Composition> {
  if (options.forceMemory) {
    return {
      root: V2CompositionRoot.withDependencies(options.dependencies ?? {}),
      mode: 'memory',
      close: async () => undefined,
    };
  }

  const repoType = process.env.FIXGUARD_V2_ORCHESTRATED_REPOSITORY;
  const enabled = process.env.FIXGUARD_V2_ENABLE_POSTGRES_ORCHESTRATED;
  const databaseUrl = resolveDatabaseUrl(options);
  const explicitPostgres = repoType === 'postgres';

  if (explicitPostgres && !databaseUrl) {
    throw new Error(
      'FIXGUARD_V2_ORCHESTRATED_REPOSITORY=postgres requires FIXGUARD_V2_DATABASE_URL or DATABASE_URL'
    );
  }

  const usePostgres =
    (explicitPostgres || enabled === '1') && Boolean(databaseUrl);

  if (!usePostgres || !databaseUrl) {
    return {
      root: V2CompositionRoot.withDependencies(options.dependencies ?? {}),
      mode: 'memory',
      close: async () => undefined,
    };
  }

  const pool = new Pool({ connectionString: databaseUrl });
  const drizzleDb = drizzle(pool);
  const orchestratedRepository = new PostgresOrchestratedAssessmentRepository(
    adaptOrchestratedAssessmentDb(drizzleDb)
  );

  return {
    root: V2CompositionRoot.withDependencies({
      ...(options.dependencies ?? {}),
      orchestratedRepository,
    }),
    mode: 'postgres',
    close: async () => {
      await pool.end();
    },
  };
}

export function createPostgresOrchestratedAssessmentRepository(
  db: OrchestratedAssessmentDb
): PostgresOrchestratedAssessmentRepository {
  return new PostgresOrchestratedAssessmentRepository(db);
}
