import { InMemoryAssessmentRepository } from "../storage/InMemoryAssessmentRepository";
import { runAssessmentRepositoryConformanceSuite } from "../storage/testing/AssessmentRepositoryConformanceSuite";

async function run() {
  await runAssessmentRepositoryConformanceSuite(
    "InMemoryAssessmentRepository",
    () => new InMemoryAssessmentRepository()
  );

  console.log("Milestone 17 repository conformance smoke passed");
}

run().catch((err) => {
  console.error('[!] Conformance suite failed:', err);
  process.exit(1);
});
