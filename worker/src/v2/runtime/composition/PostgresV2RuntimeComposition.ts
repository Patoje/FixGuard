import { Pool } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import { V2AssessmentRuntime } from '../V2AssessmentRuntime';
import { PostgresAssessmentRepository } from '../../storage/postgres/PostgresAssessmentRepository';
import type { MinimalOrchestrator } from '../../core/MinimalOrchestrator';

export type V2RuntimeComposition = {
  runtime: V2AssessmentRuntime;
  close: () => Promise<void>;
};

export async function createPostgresBackedV2Runtime(
  options: { databaseUrl: string },
  orchestratorStub?: MinimalOrchestrator
): Promise<V2RuntimeComposition> {
  const pool = new Pool({ connectionString: options.databaseUrl });
  const db = drizzle(pool);
  const repository = new PostgresAssessmentRepository(db);
  
  // Note: the orchestratorStub is primarily for deterministic testing.
  // In production, omitting it uses the default ToolRegistry and ProcessRunner.
  const runtime = new V2AssessmentRuntime(repository, orchestratorStub);

  return {
    runtime,
    close: async () => {
      await pool.end();
    }
  };
}

export async function createPostgresBackedV2RuntimeFromEnv(
  orchestratorStub?: MinimalOrchestrator
): Promise<V2RuntimeComposition> {
  const repoType = process.env.FIXGUARD_V2_RUNTIME_REPOSITORY;
  const isEnabled = process.env.FIXGUARD_V2_ENABLE_POSTGRES_RUNTIME;
  const databaseUrl = process.env.FIXGUARD_V2_DATABASE_URL;

  if (repoType !== 'postgres' || isEnabled !== '1' || !databaseUrl) {
    throw new Error('Explicit opt-in required for Postgres-backed V2 runtime. Set FIXGUARD_V2_RUNTIME_REPOSITORY=postgres, FIXGUARD_V2_ENABLE_POSTGRES_RUNTIME=1, and FIXGUARD_V2_DATABASE_URL.');
  }

  return createPostgresBackedV2Runtime({ databaseUrl }, orchestratorStub);
}
