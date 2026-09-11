import assert from "node:assert";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { sql, eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/neon-serverless";
import { Pool, neonConfig } from "@neondatabase/serverless";
import { migrate } from "drizzle-orm/neon-serverless/migrator";

import {
  v2_assessment_sessions,
  v2_formal_finding_candidates,
  v2_reviewed_evidence_records
} from "../storage/postgres/schema.js";
import {
  PersistenceConflictError,
  SessionNotFoundError,
  RecordCorruptedError
} from "../storage/StorageErrors.js";
import { InMemoryFormalFindingCandidateRepository } from "../finding-candidate-promotion/InMemoryFormalFindingCandidateRepository.js";
import { PostgresFormalFindingCandidateRepository } from "../finding-candidate-promotion/PostgresFormalFindingCandidateRepository.js";
import { InMemoryReviewedEvidenceStoreRepository } from "../evidence-store/InMemoryReviewedEvidenceStoreRepository.js";
import { PostgresReviewedEvidenceStoreRepository } from "../evidence-store/PostgresReviewedEvidenceStoreRepository.js";
import type { ReviewedEvidenceFormalFindingCandidate } from "../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionContracts.js";
import type { ReviewedEvidenceStoreRecord } from "../evidence-store/ReviewedEvidenceStoreContracts.js";
import type { ExecutionLineage } from "../evidence/EvidenceBoundaryContracts.js";

function buildValidLineage(assessmentId: string, scanId: string): ExecutionLineage {
  return {
    assessmentId,
    scanId,
    authorizationGrantId: "grt_m59_smoke_001",
    authorizationDecisionId: "dec_m59_smoke_001",
    actorId: "usr_m59_auditor",
    validationId: "val_m59_smoke_001"
  };
}

function buildValidCandidate(
  candidateId: string,
  scanId: string,
  assessmentId: string,
  draftId: string = `drf_${candidateId}`
): ReviewedEvidenceFormalFindingCandidate {
  const now = new Date().toISOString();
  return {
    contractVersion: "fixguard-reviewed-evidence-formal-finding-candidate/v0",
    kind: "reviewed_evidence_formal_finding_candidate",
    candidateId,
    scanId,
    createdAt: now,
    lineage: buildValidLineage(assessmentId, scanId),
    sourceDraft: {
      draftId,
      sourceSelectionId: "sel_m59_001",
      selectedCount: 1,
      candidateKind: "reviewed_evidence_group",
      triageState: "requires_human_triage",
      confidenceState: "evidence_grouped_not_confirmed"
    },
    humanTriage: {
      decisionId: "dec_triage_m59_001",
      reviewerId: "usr_m59_auditor",
      reviewedAt: now,
      decision: "approve_finding_candidate_promotion",
      humanApprovedPromotion: true
    },
    evidenceRefs: {
      selectedRefs: [
        {
          storeRecordId: "str_m59_ref_001",
          evidenceId: "evd_m59_ref_001",
          scanId,
          indicatorId: "ind_m59_diff_001"
        }
      ],
      selectedCount: 1
    },
    observedEvidenceSummary: {
      evidenceTypeCounts: { http_difference: 1 },
      strengthCounts: { strong: 1 },
      indicatorIds: ["ind_m59_diff_001"],
      collectedAtRange: { earliest: now, latest: now },
      savedAtRange: { earliest: now, latest: now }
    },
    candidateState: {
      lifecycleState: "formal_candidate_created",
      confirmationState: "not_confirmed",
      reportState: "not_reported",
      persistenceState: "not_persisted",
      requiresFurtherHumanReview: true
    },
    storage: {
      persisted: false,
      persistedToDatabase: false,
      externalized: false
    },
    explicitNonClaims: {
      noConfirmedFinding: true,
      noConfirmedVulnerability: true,
      noExploitabilityClaim: true,
      noSeverityRiskOrImpactClaim: true,
      noRemediationAdvice: true,
      noSafeReportItemCreated: true,
      noExternalReportCreated: true,
      noNetworkExecution: true,
      noToolExecution: true,
      noPersistence: true
    },
    classification: {
      createsFormalFindingCandidate: true,
      createsConfirmedFinding: false,
      createsSafeReportItem: false,
      createsExternalReport: false,
      confirmsVulnerabilities: false,
      makesExploitabilityClaims: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      providesRemediationAdvice: false,
      persistsCandidate: false,
      persistsToDatabase: false,
      executesNetwork: false,
      executesTools: false
    }
  };
}

function buildValidEvidenceStoreRecord(
  storeRecordId: string,
  scanId: string,
  assessmentId: string,
  evidenceId: string = `evd_${storeRecordId}`
): ReviewedEvidenceStoreRecord {
  const now = new Date().toISOString();
  return {
    recordVersion: "fixguard-reviewed-evidence-store-record/v0",
    recordKind: "reviewed_evidence_store_record",
    storeRecordId,
    savedAt: now,
    evidenceRecord: {
      contractVersion: "fixguard-evidence-boundary/v0",
      kind: "evidence_record",
      evidenceId,
      scanId,
      indicatorId: "ind_m59_diff_001",
      collectedAt: now,
      collectedBy: "response_comparator",
      evidenceType: "http_difference",
      strength: "strong",
      redaction: {
        isRedacted: true,
        redactionMethod: "hash_only"
      },
      classification: {
        createsRealFindings: false,
        createsPersistedEvidence: false,
        confirmsVulnerabilities: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false
      },
      lineage: buildValidLineage(assessmentId, scanId),
      baseline: {
        method: "GET",
        statusCode: 200,
        contentLength: 1000,
        responseTimeMs: 35
      },
      attackOrValidation: {
        method: "GET",
        statusCode: 403,
        contentLength: 220,
        responseTimeMs: 40
      },
      difference: {
        statusCodeChanged: true,
        contentLengthDeltaPercent: 78,
        responseTimeDeltaMs: 5
      }
    },
    source: {
      sourceBoundary: "M50",
      sourceContractVersion: "fixguard-human-reviewed-evidence-promotion/v0",
      sourcePromotionId: "prm_m59_001",
      sourceScanId: scanId,
      sourceReasonCode: "promoted_to_non_persisted_evidence_record"
    },
    storage: {
      storageKind: "in_memory_db_free",
      persistedToDatabase: false,
      externalized: false
    },
    explicitNonClaims: {
      noConfirmedVulnerability: true,
      noFindingCreated: true,
      noFindingCandidateCreated: true,
      noSafeReportItemCreated: true,
      noExternalReportCreated: true,
      noSeverityRiskOrImpactClaim: true,
      noNetworkExecution: true,
      noToolExecution: true
    },
    classification: {
      storesReviewedEvidenceRecord: true,
      storesInMemoryOnly: true,
      persistsToDatabase: false,
      createsFindingCandidate: false,
      createsSafeReportItem: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false
    }
  };
}

// ---------------------------------------------------------------------------
// In-Memory Simulated Postgres Driver for Continuous Local/CI Testing
// ---------------------------------------------------------------------------
class MockPostgresDb {
  public sessions = new Set<string>();
  public candidates = new Map<string, any>();
  public evidence = new Map<string, any>();

  private extractEqParams(expr: any): { column: string; value: any } | null {
    if (expr && Array.isArray(expr.queryChunks) && expr.queryChunks.length >= 4) {
      const colName = expr.queryChunks[1]?.name;
      const val = expr.queryChunks[3]?.value;
      if (colName && val !== undefined) {
        return { column: colName, value: val };
      }
    }
    return null;
  }

  insert(table: any) {
    return {
      values: async (data: any) => {
        if (table === v2_formal_finding_candidates) {
          if (!this.sessions.has(data.session_id)) {
            const err: any = new Error("insert or update on table 'v2_formal_finding_candidates' violates foreign key constraint");
            err.code = "23503";
            throw err;
          }
          if (this.candidates.has(data.candidate_id)) {
            const err: any = new Error("duplicate key value violates unique constraint 'v2_formal_finding_candidates_pkey'");
            err.code = "23505";
            throw err;
          }
          for (const existing of this.candidates.values()) {
            if (existing.draft_id === data.draft_id) {
              const err: any = new Error("duplicate key value violates unique constraint 'v2_formal_finding_candidates_draft_id_unique'");
              err.code = "23505";
              throw err;
            }
          }
          this.candidates.set(data.candidate_id, JSON.parse(JSON.stringify(data)));
          return;
        }

        if (table === v2_reviewed_evidence_records) {
          if (!this.sessions.has(data.session_id)) {
            const err: any = new Error("insert or update on table 'v2_reviewed_evidence_records' violates foreign key constraint");
            err.code = "23503";
            throw err;
          }
          if (this.evidence.has(data.store_record_id)) {
            const err: any = new Error("duplicate key value violates unique constraint 'v2_reviewed_evidence_records_pkey'");
            err.code = "23505";
            throw err;
          }
          for (const existing of this.evidence.values()) {
            if (existing.evidence_id === data.evidence_id) {
              const err: any = new Error("duplicate key value violates unique constraint 'v2_reviewed_evidence_records_evidence_id_unique'");
              err.code = "23505";
              throw err;
            }
          }
          this.evidence.set(data.store_record_id, JSON.parse(JSON.stringify(data)));
          return;
        }
      }
    };
  }

  select() {
    return {
      from: (table: any) => {
        const getRows = (): any[] => {
          if (table === v2_formal_finding_candidates) {
            return Array.from(this.candidates.values()).map((r) => JSON.parse(JSON.stringify(r)));
          }
          if (table === v2_reviewed_evidence_records) {
            return Array.from(this.evidence.values()).map((r) => JSON.parse(JSON.stringify(r)));
          }
          return [];
        };

        return {
          where: (expr: any) => {
            const params = this.extractEqParams(expr);
            const filterRows = () => {
              const rows = getRows();
              if (!params) return rows;
              return rows.filter((r) => r[params.column] === params.value);
            };

            return {
              limit: async (lim: number) => filterRows().slice(0, lim),
              orderBy: (..._args: any[]) => ({
                limit: async (lim: number) => filterRows().slice(0, lim)
              })
            };
          }
        };
      }
    };
  }
}

async function runInMemoryRepositoriesSuite() {
  console.log("=== FixGuard V2 Milestone 59: In-Memory Repositories Smoke ===");

  // Candidate Repository in-memory
  const candRepo = new InMemoryFormalFindingCandidateRepository();
  const c1 = buildValidCandidate("m59_mem_c1", "scn_m59_mem_1", "asm_m59_mem_1");

  const savedC1 = await candRepo.saveCandidate(c1);
  assert.strictEqual(savedC1.candidateId, "m59_mem_c1");

  const fetchedC1 = await candRepo.getCandidate("m59_mem_c1");
  assert.ok(fetchedC1);
  assert.strictEqual(fetchedC1.candidateId, "m59_mem_c1");

  const fetchedByDraft = await candRepo.getCandidateByDraftId(c1.sourceDraft.draftId);
  assert.ok(fetchedByDraft);
  assert.strictEqual(fetchedByDraft.candidateId, "m59_mem_c1");

  // Duplicate candidateId rejection
  await assert.rejects(
    candRepo.saveCandidate(c1),
    (err: any) => err instanceof PersistenceConflictError,
    "Expected PersistenceConflictError on duplicate candidateId"
  );

  // Evidence Store Repository in-memory
  const evRepo = new InMemoryReviewedEvidenceStoreRepository();
  const e1 = buildValidEvidenceStoreRecord("m59_mem_e1", "scn_m59_mem_1", "asm_m59_mem_1");

  const savedE1 = await evRepo.save(e1);
  assert.strictEqual(savedE1.storeRecordId, "m59_mem_e1");

  const fetchedE1 = await evRepo.getByStoreRecordId("m59_mem_e1");
  assert.ok(fetchedE1);
  assert.strictEqual(fetchedE1.storeRecordId, "m59_mem_e1");

  // Duplicate storeRecordId rejection
  await assert.rejects(
    evRepo.save(e1),
    (err: any) => err instanceof PersistenceConflictError,
    "Expected PersistenceConflictError on duplicate storeRecordId"
  );

  console.log("[+] In-memory repositories passed all checks.");
}

async function runMockPostgresAdapterAndAdversarialAuditSuite() {
  console.log("=== FixGuard V2 Milestone 59: Postgres Adapters & Adversarial Audit (Simulated PG) ===");

  const mockDb = new MockPostgresDb();
  const testSessionId = "m59_mock_session_1";
  const testScanId = "scn_m59_mock_1";
  mockDb.sessions.add(testSessionId);

  const candidateRepo = new PostgresFormalFindingCandidateRepository(mockDb as any);
  const evidenceRepo = new PostgresReviewedEvidenceStoreRepository(mockDb as any);

  // 1. Candidate persistence & common errors
  const cand = buildValidCandidate("m59_cand_01", testScanId, testSessionId);
  await candidateRepo.saveCandidate(cand);
  console.log("  [+] Candidate saved successfully in Postgres adapter.");

  // Assert duplicate throws PersistenceConflictError (NOT raw 23505)
  await assert.rejects(
    candidateRepo.saveCandidate(cand),
    (err: any) => {
      assert.ok(err instanceof PersistenceConflictError, `Expected PersistenceConflictError, got ${err?.constructor?.name}`);
      return true;
    },
    "Duplicate insert must translate 23505 to PersistenceConflictError"
  );
  console.log("  [+] Code 23505 properly translated to PersistenceConflictError.");

  // Assert missing session throws SessionNotFoundError (NOT raw 23503)
  const orphanedCand = buildValidCandidate("m59_cand_orphan", testScanId, "non_existent_session");
  await assert.rejects(
    candidateRepo.saveCandidate(orphanedCand),
    (err: any) => {
      assert.ok(err instanceof SessionNotFoundError, `Expected SessionNotFoundError, got ${err?.constructor?.name}`);
      return true;
    },
    "FK violation must translate 23503 to SessionNotFoundError"
  );
  console.log("  [+] Code 23503 properly translated to SessionNotFoundError.");

  // 2. Ataque Adversarial en Candidate (Compromised DB injecting severity: "CRITICAL")
  console.log("  [*] Running adversarial attack: injecting 'severity': 'CRITICAL' directly into SQL payload...");
  const storedRow = mockDb.candidates.get("m59_cand_01");
  storedRow.candidate_json.severity = "CRITICAL"; // Simulated direct SQL injection

  let candidateAttackBlocked = false;
  try {
    await candidateRepo.getCandidate("m59_cand_01");
  } catch (err: any) {
    if (err instanceof RecordCorruptedError) {
      candidateAttackBlocked = true;
      console.log("  [+] SUCCESS: getCandidate failed-closed with RecordCorruptedError on injected severity claim!");
    }
  }

  if (!candidateAttackBlocked) {
    console.error("  [-] CRITICAL AUDIT FAILURE: Repository returned candidate with forged severity!");
    process.exit(1);
  }

  // 3. Relational Desync Attack on Candidate
  console.log("  [*] Running relational desync attack: altering indexed column 'scan_id'...");
  delete storedRow.candidate_json.severity; // remove forged field
  storedRow.scan_id = "different_scan_desync"; // alter column

  let candidateDesyncBlocked = false;
  try {
    await candidateRepo.getCandidate("m59_cand_01");
  } catch (err: any) {
    if (err instanceof RecordCorruptedError) {
      candidateDesyncBlocked = true;
      console.log("  [+] SUCCESS: Cross-column consistency check detected desync and threw RecordCorruptedError!");
    }
  }

  if (!candidateDesyncBlocked) {
    console.error("  [-] CRITICAL AUDIT FAILURE: Candidate cross-column check failed to detect desync!");
    process.exit(1);
  }

  // 4. Evidence Store persistence & common errors
  const evRecord = buildValidEvidenceStoreRecord("m59_evd_01", testScanId, testSessionId);
  await evidenceRepo.save(evRecord);
  console.log("  [+] Evidence record saved successfully in Postgres adapter.");

  // Duplicate
  await assert.rejects(
    evidenceRepo.save(evRecord),
    (err: any) => err instanceof PersistenceConflictError,
    "Duplicate insert must translate 23505 to PersistenceConflictError"
  );
  console.log("  [+] Duplicate evidence translated to PersistenceConflictError.");

  // FK violation
  const orphanedEv = buildValidEvidenceStoreRecord("m59_evd_orphan", testScanId, "non_existent_session");
  await assert.rejects(
    evidenceRepo.save(orphanedEv),
    (err: any) => err instanceof SessionNotFoundError,
    "FK violation must translate 23503 to SessionNotFoundError"
  );
  console.log("  [+] Missing session translated to SessionNotFoundError.");

  // 5. Ataque Adversarial en Evidence Store (Compromised DB injecting severity: "HIGH")
  console.log("  [*] Running adversarial attack on evidence store: injecting 'severity': 'HIGH'...");
  const storedEvRow = mockDb.evidence.get("m59_evd_01");
  storedEvRow.record_json.severity = "HIGH";

  let evAttackBlocked = false;
  try {
    await evidenceRepo.getByStoreRecordId("m59_evd_01");
  } catch (err: any) {
    if (err instanceof RecordCorruptedError) {
      evAttackBlocked = true;
      console.log("  [+] SUCCESS: getByStoreRecordId failed-closed with RecordCorruptedError on tampered evidence!");
    }
  }

  if (!evAttackBlocked) {
    console.error("  [-] CRITICAL AUDIT FAILURE: Evidence repository returned tampered record!");
    process.exit(1);
  }

  // 6. Relational Desync Attack on Evidence Store
  delete storedEvRow.record_json.severity;
  storedEvRow.scan_id = "different_scan_desync";

  let evDesyncBlocked = false;
  try {
    await evidenceRepo.getByStoreRecordId("m59_evd_01");
  } catch (err: any) {
    if (err instanceof RecordCorruptedError) {
      evDesyncBlocked = true;
      console.log("  [+] SUCCESS: Evidence cross-column check detected desync and threw RecordCorruptedError!");
    }
  }

  if (!evDesyncBlocked) {
    console.error("  [-] CRITICAL AUDIT FAILURE: Evidence cross-column check failed to detect desync!");
    process.exit(1);
  }

  console.log("[+] Postgres adapters and adversarial defense audit passed 100%.");
}

async function runLivePostgresSuite() {
  const testUrl = process.env.FIXGUARD_PG_TEST_URL;
  if (!testUrl) {
    console.log("--- Live PostgreSQL Verification Skipped ---");
    console.log("Reason: FIXGUARD_PG_TEST_URL is not set (ADR-011 db-free conformance).");
    return;
  }

  console.log("=== FixGuard V2 Milestone 59: Live PostgreSQL Execution ===");

  if (typeof WebSocket !== "undefined") {
    neonConfig.webSocketConstructor = WebSocket;
  }

  console.log("[*] Connecting to PostgreSQL at configured test URL...");
  const pool = new Pool({ connectionString: testUrl });
  const db = drizzle(pool);

  try {
    const migrationsFolder = fileURLToPath(new URL("../../../drizzle-v2", import.meta.url));
    console.log(`[*] Applying V2 migrations from ${migrationsFolder}...`);
    await migrate(db, {
      migrationsFolder,
      migrationsSchema: "drizzle_v2",
      migrationsTable: "__drizzle_migrations_v2"
    });
    console.log("[+] Migrations complete.");

    // Clean up any old test rows
    await db.execute(sql`DELETE FROM v2_formal_finding_candidates WHERE candidate_id LIKE 'm59_pg_smoke_%'`);
    await db.execute(sql`DELETE FROM v2_reviewed_evidence_records WHERE store_record_id LIKE 'm59_pg_smoke_%'`);
    await db.execute(sql`DELETE FROM v2_assessment_sessions WHERE session_id LIKE 'm59_pg_smoke_%'`);

    const validSessionId = "m59_pg_smoke_session_001";
    const validScanId = "scn_m59_pg_001";
    console.log(`[*] Setup: Inserting test parent session '${validSessionId}'...`);
    await db.insert(v2_assessment_sessions).values({
      session_id: validSessionId,
      target_uri: "https://example.com",
      lifecycle_status: "analyzing",
      version: 1,
      created_at_ms: Date.now(),
      updated_at_ms: Date.now(),
      finding_count: 0,
      pending_recommendation_count: 0,
      execution_failure_count: 0,
      state_json: {
        assessmentId: validSessionId,
        version: 1,
        targetUri: "https://example.com",
        lifecycleStatus: "analyzing",
        createdAtMs: Date.now(),
        updatedAtMs: Date.now(),
        capabilitiesRequested: [],
        evidenceCollected: [],
        auditLog: [],
        pendingRecommendations: [],
        approvedRequests: [],
        executionFailures: [],
        findings: []
      } as any
    });
    console.log("[+] Parent session inserted successfully.");

    const candidateRepo = new PostgresFormalFindingCandidateRepository(db);
    const candidateId = "m59_pg_smoke_cand_001";
    const candidate = buildValidCandidate(candidateId, validScanId, validSessionId);

    // Save candidate
    await candidateRepo.saveCandidate(candidate);
    const fetchedCandidate = await candidateRepo.getCandidate(candidateId);
    assert.ok(fetchedCandidate);
    assert.strictEqual(fetchedCandidate.candidateId, candidateId);
    console.log("  [+] Candidate persisted and fetched from live PostgreSQL.");

    // Duplicate rejection
    await assert.rejects(
      candidateRepo.saveCandidate(candidate),
      (err: any) => err instanceof PersistenceConflictError,
      "Expected PersistenceConflictError on duplicate in live PG"
    );
    console.log("  [+] Live duplicate rejected with PersistenceConflictError.");

    // Foreign key rejection
    const orphanedCandidate = buildValidCandidate(
      "m59_pg_smoke_orphan_001",
      validScanId,
      "m59_pg_smoke_non_existent_session"
    );
    await assert.rejects(
      candidateRepo.saveCandidate(orphanedCandidate),
      (err: any) => err instanceof SessionNotFoundError,
      "Expected SessionNotFoundError on orphaned FK in live PG"
    );
    console.log("  [+] Live FK violation rejected with SessionNotFoundError.");

    // Live SQL Adversarial Attack
    console.log("  [*] Running live SQL adversarial injection: updating JSONB directly with severity: 'CRITICAL'...");
    await db.execute(sql`
      UPDATE v2_formal_finding_candidates
      SET candidate_json = jsonb_set(candidate_json, '{severity}', '"CRITICAL"', true)
      WHERE candidate_id = ${candidateId}
    `);

    let liveAttackBlocked = false;
    try {
      await candidateRepo.getCandidate(candidateId);
    } catch (err: any) {
      if (err instanceof RecordCorruptedError) {
        liveAttackBlocked = true;
        console.log("  [+] SUCCESS: Live getCandidate threw RecordCorruptedError on SQL-injected severity!");
      }
    }

    if (!liveAttackBlocked) {
      console.error("  [-] CRITICAL AUDIT FAILURE: Live repository returned tampered candidate!");
      process.exit(1);
    }

    // Cleanup
    console.log("[*] Cleaning up test records from live database...");
    await db.execute(sql`DELETE FROM v2_formal_finding_candidates WHERE candidate_id LIKE 'm59_pg_smoke_%'`);
    await db.execute(sql`DELETE FROM v2_reviewed_evidence_records WHERE store_record_id LIKE 'm59_pg_smoke_%'`);
    await db.execute(sql`DELETE FROM v2_assessment_sessions WHERE session_id LIKE 'm59_pg_smoke_%'`);
    console.log("[+] Live PostgreSQL cleanup complete.");

    console.log("--- Live PostgreSQL Smoke Passed 100% ---");
  } finally {
    await pool.end();
  }
}

async function main() {
  await runInMemoryRepositoriesSuite();
  await runMockPostgresAdapterAndAdversarialAuditSuite();
  await runLivePostgresSuite();
  console.log("=== Milestone 59 Smoke Suite Finished Successfully ===");
}

main().catch((err) => {
  console.error("[-] Smoke test failed with unexpected error:", err);
  process.exit(1);
});
