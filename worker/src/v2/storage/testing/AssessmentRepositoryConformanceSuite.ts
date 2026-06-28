import assert from 'node:assert';
import type { 
  AssessmentRepository
} from '../AssessmentRepository';
import { StaleStateError } from '../StorageErrors';
import type { AssessmentState } from '../../runtime/AssessmentState';
import type { EvidenceCollection } from '../../core/Evidence';
import type { AuditEntry } from '../../approval/ApprovalContracts';
import type { ApprovedRequestRecord, ExecutionFailureRecord } from '../../runtime/AssessmentState';
import type { AttackRecommendation } from '../../intelligence/AttackRecommendation';

export type AssessmentRepositoryFactory = () => AssessmentRepository | Promise<AssessmentRepository>;

export interface ConformanceSuiteHooks {
  beforeEachCase?: () => Promise<void>;
  afterEachCase?: () => Promise<void>;
  seedParentSession?: (sessionId: string) => Promise<void>;
}

function createMinimalAssessmentState(sessionId: string, version: number = 0): AssessmentState {
  return {
    sessionId,
    targetUri: 'https://example.com',
    lifecycleStatus: 'initialized',
    evidenceCollections: [],
    currentProfile: null,
    pendingRecommendations: [],
    approvedRequestRecords: [],
    executionFailures: [],
    auditEntries: [],
    errors: [],
    timestamps: {
      created: 1000,
      lastUpdated: 1000
    },
    version
  };
}

function createMinimalEvidence(): EvidenceCollection {
  return {
    findings: [],
    metadata: {}
  };
}

function createMinimalRecommendation(): AttackRecommendation {
  return {
    id: 'r1',
    capability: 'cap',
    targetContext: { uri: 'https://example.com' },
    rationale: 'j',
    confidence: 1,
    severity: 'low',
    sourceFindingIds: []
  };
}

function createMinimalAuditEntry(): AuditEntry {
  return {
    id: 'audit-1',
    recommendationId: 'r1',
    decision: {
      recommendationId: 'r1',
      status: 'approved',
      operatorId: 'operator',
      decidedAt: 1000
    },
    sourceRecommendation: createMinimalRecommendation(),
    recordedAt: 1000
  };
}

function createMinimalApprovedRequest(): ApprovedRequestRecord {
  return {
    id: 'app-1',
    recommendationId: 'rec-1',
    capability: 'test_cap',
    targetUri: 'https://example.com',
    approvedAt: 1000,
    operatorId: 'operator',
    sourceRecommendationId: 'source-1',
    requestSummary: {}
  };
}

function createMinimalExecutionFailure(): ExecutionFailureRecord {
  return {
    id: 'fail-1',
    capability: 'test_cap',
    targetUri: 'https://example.com',
    failedAt: 1000,
    errorMessage: 'failed',
    recoverable: false,
    lifecycleStatusAtFailure: 'initial_execution_running'
  };
}

export async function runAssessmentRepositoryConformanceSuite(
  name: string,
  createRepository: AssessmentRepositoryFactory,
  hooks?: ConformanceSuiteHooks
): Promise<void> {
  console.log(`\n--- Running AssessmentRepositoryConformanceSuite for ${name} ---`);

  const runBefore = async () => { if (hooks?.beforeEachCase) await hooks.beforeEachCase(); };
  const runAfter = async () => { if (hooks?.afterEachCase) await hooks.afterEachCase(); };
  const seed = async (sessionId: string) => { if (hooks?.seedParentSession) await hooks.seedParentSession(sessionId); };

  // 1 & 2. saveAssessmentState creates a new session with expectedVersion: 0, load returns it.
  {
    await runBefore();
    const repo = await createRepository();
    const sessionId = 'session-1';
    const state = createMinimalAssessmentState(sessionId);
    await repo.saveAssessmentState({ state, expectedVersion: 0 });
    const loaded = await repo.loadAssessmentState(sessionId);
    assert.deepStrictEqual(loaded, state);
    console.log('[+] 1 & 2. saveAssessmentState(expectedVersion: 0) and loadAssessmentState works');
    await runAfter();
  }

  // 3. Missing loadAssessmentState(sessionId) returns undefined.
  {
    await runBefore();
    const repo = await createRepository();
    const loaded = await repo.loadAssessmentState('missing-session');
    assert.strictEqual(loaded, undefined);
    console.log('[+] 3. Missing loadAssessmentState returns undefined');
    await runAfter();
  }

  // 4 & 5. External mutation does not mutate stored state.
  {
    await runBefore();
    const repo = await createRepository();
    const sessionId = 'session-clone';
    const state = createMinimalAssessmentState(sessionId);
    await repo.saveAssessmentState({ state, expectedVersion: 0 });
    
    // Mutate original after save
    state.targetUri = 'https://mutated.com';
    const loaded1 = await repo.loadAssessmentState(sessionId);
    assert.strictEqual(loaded1?.targetUri, 'https://example.com');

    // Mutate loaded object
    if (loaded1) {
      loaded1.targetUri = 'https://mutated-again.com';
    }
    const loaded2 = await repo.loadAssessmentState(sessionId);
    assert.strictEqual(loaded2?.targetUri, 'https://example.com');
    console.log('[+] 4 & 5. External mutation does not mutate stored state (cloned)');
    await runAfter();
  }

  // 6. Returned list items are cloned, not live references.
  {
    await runBefore();
    const repo = await createRepository();
    const sessionId = 'session-list-clone';
    await seed(sessionId);
    const ev = createMinimalEvidence();
    await repo.appendEvidence({ sessionId, evidence: ev, capability: 'recon', recordedAt: 1000 });
    await repo.appendAuditEntry({ sessionId, entry: createMinimalAuditEntry(), recordedAt: 1000 });
    await repo.appendApprovedRequest({ sessionId, record: createMinimalApprovedRequest(), recordedAt: 1000 });
    await repo.appendExecutionFailure({ sessionId, record: createMinimalExecutionFailure(), recordedAt: 1000 });
    
    if (!hooks?.seedParentSession) {
      await repo.saveAssessmentState({ state: createMinimalAssessmentState(sessionId), expectedVersion: 0 });
    }
    
    const list1 = await repo.listEvidence(sessionId);
    list1[0].metadata = { mutated: true };
    const list2 = await repo.listEvidence(sessionId);
    assert.strictEqual(list2[0].metadata.mutated, undefined);

    const au1 = await repo.listAuditEntries(sessionId);
    (au1[0] as any).action = 'mutated';
    const au2 = await repo.listAuditEntries(sessionId);
    assert.strictEqual((au2[0] as any).action, undefined); // 'action' doesn't exist on AuditEntry in V2

    const ar1 = await repo.listApprovedRequests(sessionId);
    ar1[0].capability = 'mutated';
    const ar2 = await repo.listApprovedRequests(sessionId);
    assert.strictEqual(ar2[0].capability, 'test_cap');

    const ef1 = await repo.listExecutionFailures(sessionId);
    ef1[0].errorMessage = 'mutated';
    const ef2 = await repo.listExecutionFailures(sessionId);
    assert.strictEqual(ef2[0].errorMessage, 'failed');

    const s1 = await repo.listSessions();
    s1[0].lifecycleStatus = 'completed';
    const s2 = await repo.listSessions();
    assert.strictEqual(s2[0].lifecycleStatus, 'initialized');

    console.log('[+] 6. Returned list items are cloned');
    await runAfter();
  }

  // 7 & 8. expectedVersion mismatch throws StaleStateError + Error shape.
  {
    await runBefore();
    const repo = await createRepository();
    const sessionId = 'session-stale';
    const state = createMinimalAssessmentState(sessionId, 0);
    await repo.saveAssessmentState({ state, expectedVersion: 0 });
    
    // Simulate updating with wrong expectedVersion (repo is at 0, we expect 1)
    state.version = 2;
    let caughtError: any;
    try {
      await repo.saveAssessmentState({ state, expectedVersion: 1 });
    } catch (e) {
      caughtError = e;
    }
    assert(caughtError instanceof StaleStateError, 'Should throw StaleStateError');
    assert.strictEqual(caughtError.sessionId, sessionId);
    assert.strictEqual(caughtError.expectedVersion, 1);
    assert.strictEqual(caughtError.actualVersion, 0); // it was 0 in repo
    console.log('[+] 7 & 8. expectedVersion mismatch throws correctly shaped StaleStateError');
    await runAfter();
  }

  // 9. Matching expectedVersion updates successfully.
  {
    await runBefore();
    const repo = await createRepository();
    const sessionId = 'session-update';
    const state = createMinimalAssessmentState(sessionId, 0);
    await repo.saveAssessmentState({ state, expectedVersion: 0 });
    
    state.version = 1;
    await repo.saveAssessmentState({ state, expectedVersion: 0 });
    
    const loaded = await repo.loadAssessmentState(sessionId);
    assert.strictEqual(loaded?.version, 1);
    console.log('[+] 9. Matching expectedVersion updates successfully');
    await runAfter();
  }

  // 10 & 11 & 12 & 20. listSessions summaries, fields, filters, and counts
  {
    await runBefore();
    const repo = await createRepository();
    const sessionId1 = 'session-s1';
    const state1 = createMinimalAssessmentState(sessionId1);
    state1.targetUri = 'https://t1.com';
    state1.timestamps.created = 100;
    state1.timestamps.lastUpdated = 200;
    
    // simulate findings by adding to evidence collections inside state
    const ev = createMinimalEvidence();
    ev.findings.push({ id: 'f1', type: 't', severity: 'low', title: 'test', description: 'd', target: 't', evidence: 'e', confidence: 1, metadata: {} });
    state1.evidenceCollections.push(ev);
    state1.pendingRecommendations.push(createMinimalRecommendation());
    state1.executionFailures.push(createMinimalExecutionFailure());
    await repo.saveAssessmentState({ state: state1, expectedVersion: 0 });
    
    const sessionId2 = 'session-s2';
    const state2 = createMinimalAssessmentState(sessionId2);
    state2.targetUri = 'https://t2.com';
    state2.timestamps.created = 300;
    state2.timestamps.lastUpdated = 400;
    await repo.saveAssessmentState({ state: state2, expectedVersion: 0 });

    const sessionId3 = 'session-s3';
    const state3 = createMinimalAssessmentState(sessionId3);
    state3.lifecycleStatus = 'completed';
    await repo.saveAssessmentState({ state: state3, expectedVersion: 0 });

    const all = await repo.listSessions();
    assert.strictEqual(all.length, 3);
    
    // Check summary fields for session 1
    const s1 = all.find(s => s.sessionId === sessionId1)!;
    assert.strictEqual(s1.targetUri, 'https://t1.com');
    assert.strictEqual(s1.lifecycleStatus, 'initialized');
    assert.strictEqual(s1.version, 0);
    assert.strictEqual(s1.createdAt, 100);
    assert.strictEqual(s1.updatedAt, 200);
    assert.strictEqual(s1.findingCount, 1);
    assert.strictEqual(s1.pendingRecommendationCount, 1);
    assert.strictEqual(s1.executionFailureCount, 1);

    // Verify summaries don't have snapshot fields
    for (const summary of all) {
      assert(!('evidenceCollections' in summary));
      assert(!('currentProfile' in summary));
      assert(!('pendingRecommendations' in summary));
      assert(!('approvedRequestRecords' in summary));
      assert(!('auditEntries' in summary));
      assert(!('errors' in summary));
    }
    
    // Check filters
    const fStatus = await repo.listSessions({ lifecycleStatus: 'completed' });
    assert.strictEqual(fStatus.length, 1);
    assert.strictEqual(fStatus[0].sessionId, sessionId3);

    const fUri = await repo.listSessions({ targetUri: 'https://t2.com' });
    assert.strictEqual(fUri.length, 1);
    assert.strictEqual(fUri[0].sessionId, sessionId2);
    
    const fCreatedAfter = await repo.listSessions({ createdAfter: 150 });
    assert.strictEqual(fCreatedAfter.length, 2);
    
    const fCreatedBefore = await repo.listSessions({ createdBefore: 200 });
    assert.strictEqual(fCreatedBefore.length, 1);
    assert.strictEqual(fCreatedBefore[0].sessionId, sessionId1);
    
    const fUpdatedAfter = await repo.listSessions({ updatedAfter: 300 });
    assert.strictEqual(fUpdatedAfter.length, 2);
    
    const fUpdatedBefore = await repo.listSessions({ updatedBefore: 300 });
    assert.strictEqual(fUpdatedBefore.length, 1);
    assert.strictEqual(fUpdatedBefore[0].sessionId, sessionId1);
    
    const fLimit = await repo.listSessions({ limit: 1 });
    assert.strictEqual(fLimit.length, 1);
    
    const fOffset = await repo.listSessions({ offset: 1 });
    assert.strictEqual(fOffset.length, 2);

    console.log('[+] 10 & 11 & 12 & 20. listSessions summaries, counts, and filters work correctly');
    await runAfter();
  }

  // 13, 14, 15, 16, 17, 18, 19, 21. Append-only methods, isolation, and deterministic ordering.
  {
    await runBefore();
    const repo = await createRepository();
    const sa = 'session-a';
    const sb = 'session-b';
    await seed(sa);
    await seed(sb);

    // Append record A (higher timestamp, second in time but first inserted)
    const evA1 = createMinimalEvidence();
    evA1.findings.push({ id: 'evA1', type: 't', severity: 'low', title: 'test', description: 'd', target: 't', evidence: 'e', confidence: 1, metadata: {} });
    await repo.appendEvidence({ sessionId: sa, evidence: evA1, capability: 'cap', recordedAt: 2000 });
    
    // Append record B (lower timestamp, first in time but second inserted)
    const evA2 = createMinimalEvidence();
    evA2.findings.push({ id: 'evA2', type: 't', severity: 'low', title: 'test', description: 'd', target: 't', evidence: 'e', confidence: 1, metadata: {} });
    await repo.appendEvidence({ sessionId: sa, evidence: evA2, capability: 'cap', recordedAt: 1000 });
    
    // Isolation check
    await repo.appendEvidence({ sessionId: sb, evidence: createMinimalEvidence(), capability: 'cap', recordedAt: 1000 });

    const auA1 = createMinimalAuditEntry(); auA1.id = 'au1';
    await repo.appendAuditEntry({ sessionId: sa, entry: auA1, recordedAt: 2000 });
    const auA2 = createMinimalAuditEntry(); auA2.id = 'au2';
    await repo.appendAuditEntry({ sessionId: sa, entry: auA2, recordedAt: 1000 });

    const appA1 = createMinimalApprovedRequest(); appA1.id = 'app1';
    await repo.appendApprovedRequest({ sessionId: sa, record: appA1, recordedAt: 2000 });
    const appA2 = createMinimalApprovedRequest(); appA2.id = 'app2';
    await repo.appendApprovedRequest({ sessionId: sa, record: appA2, recordedAt: 1000 });

    const efA1 = createMinimalExecutionFailure(); efA1.id = 'ef1';
    await repo.appendExecutionFailure({ sessionId: sa, record: efA1, recordedAt: 2000 });
    const efA2 = createMinimalExecutionFailure(); efA2.id = 'ef2';
    await repo.appendExecutionFailure({ sessionId: sa, record: efA2, recordedAt: 1000 });

    await repo.appendExecutionFailure({ sessionId: sb, record: createMinimalExecutionFailure(), recordedAt: 1000 });

    // Verify Evidence isolation and insertion ordering
    const evList = await repo.listEvidence(sa);
    assert.strictEqual(evList.length, 2);
    assert.strictEqual(evList[0].findings[0].id, 'evA1'); // Proves insertion order wins over recordedAt
    assert.strictEqual(evList[1].findings[0].id, 'evA2');
    
    const evB = await repo.listEvidence(sb);
    assert.strictEqual(evB.length, 1);

    // Verify Audit ordering
    const auList = await repo.listAuditEntries(sa);
    assert.strictEqual(auList.length, 2);
    assert.strictEqual(auList[0].id, 'au1');
    assert.strictEqual(auList[1].id, 'au2');
    
    const auB = await repo.listAuditEntries(sb);
    assert.strictEqual(auB.length, 0);

    // Verify ApprovedRequest ordering
    const arList = await repo.listApprovedRequests(sa);
    assert.strictEqual(arList.length, 2);
    assert.strictEqual(arList[0].id, 'app1');
    assert.strictEqual(arList[1].id, 'app2');

    // Explicit durability check on the persisted record
    const persistedApp = arList[0] as any;
    assert(!('binary' in persistedApp));
    assert(!('args' in persistedApp));
    assert(!('env' in persistedApp));
    assert(!('command' in persistedApp));
    assert(!('shell' in persistedApp));
    
    const arB = await repo.listApprovedRequests(sb);
    assert.strictEqual(arB.length, 0);

    // Verify ExecutionFailure ordering
    const efList = await repo.listExecutionFailures(sa);
    assert.strictEqual(efList.length, 2);
    assert.strictEqual(efList[0].id, 'ef1');
    assert.strictEqual(efList[1].id, 'ef2');
    
    const efB = await repo.listExecutionFailures(sb);
    assert.strictEqual(efB.length, 1);

    console.log('[+] 13-19, 21. Append-only, session isolation, ordering, and approved-request shape all verified');
    await runAfter();
  }

  console.log('--- Conformance Suite Passed ---\n');
}
