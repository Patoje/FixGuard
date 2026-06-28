import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository';
import { runAssessmentRepositoryTransactionConformanceSuite } from '../storage/testing/AssessmentRepositoryTransactionConformanceSuite';

async function runSmoke() {
  const repo = new InMemoryAssessmentRepository();

  await runAssessmentRepositoryTransactionConformanceSuite(
    "InMemoryAssessmentRepository",
    async () => repo,
    {
      seedParentSession: async (sessionId: string) => {
        const state = {
          sessionId,
          targetUri: 'https://example.com',
          lifecycleStatus: 'initialized' as const,
          evidenceCollections: [],
          currentProfile: null,
          pendingRecommendations: [],
          approvedRequestRecords: [],
          executionFailures: [],
          auditEntries: [],
          errors: [],
          timestamps: { created: Date.now(), lastUpdated: Date.now() },
          version: 1
        };
        await repo.saveAssessmentState({ state, expectedVersion: 0 });
      }
    }
  );

  console.log('--- InMemory Transaction Smoke Completed Successfully ---');
}

runSmoke().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
