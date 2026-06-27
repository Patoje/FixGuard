import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository';
import { StaleStateError } from '../storage/StorageErrors';
import type { AssessmentState, ApprovedRequestRecord, ExecutionFailureRecord } from '../runtime/AssessmentState';
import type { EvidenceCollection } from '../core/Evidence';
import type { AuditEntry } from '../approval/ApprovalContracts';

console.log('--- V2 Storage InMemoryAdapter Smoke Test ---');

async function runSmoke() {
  const repo = new InMemoryAssessmentRepository();
  const sessionId = 'test-session-1';

  // 1. Initial State creation
  const initialState: AssessmentState = {
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
    timestamps: { created: 100, lastUpdated: 100 },
    version: 1
  };

  console.log('[*] Testing saveAssessmentState (expectedVersion: 0)...');
  await repo.saveAssessmentState({ state: initialState, expectedVersion: 0 });
  console.log('[+] Save successful.');

  console.log('[*] Testing loadAssessmentState...');
  const loadedState = await repo.loadAssessmentState(sessionId);
  if (!loadedState || loadedState.version !== 1) throw new Error('Failed to load state');
  console.log('[+] Load successful.');

  console.log('[*] Testing external mutation protection (save clone)...');
  initialState.targetUri = 'https://hacked.com';
  const loadedState2 = await repo.loadAssessmentState(sessionId);
  if (loadedState2?.targetUri === 'https://hacked.com') throw new Error('Stored state mutated externally');
  console.log('[+] Save clone protection works.');

  console.log('[*] Testing external mutation protection (load clone)...');
  loadedState.targetUri = 'https://hacked.com';
  const loadedState3 = await repo.loadAssessmentState(sessionId);
  if (loadedState3?.targetUri === 'https://hacked.com') throw new Error('Loaded state mutation leaked to store');
  console.log('[+] Load clone protection works.');

  console.log('[*] Testing expectedVersion mismatch...');
  try {
    const nextState = { ...loadedState3!, version: 2 };
    await repo.saveAssessmentState({ state: nextState, expectedVersion: 99 });
    throw new Error('Should have thrown StaleStateError');
  } catch (err) {
    if (!(err instanceof StaleStateError)) throw err;
    console.log('[+] StaleStateError correctly thrown for version mismatch.');
  }

  console.log('[*] Testing expectedVersion match...');
  const nextState = { ...loadedState3!, version: 2 };
  await repo.saveAssessmentState({ state: nextState, expectedVersion: 1 });
  console.log('[+] Save with matched expectedVersion successful.');

  console.log('[*] Testing append behavior (Evidence, Audit, Approved, Failure)...');
  const mockEvidence: EvidenceCollection = { findings: [], metadata: { m: 1 } };
  const mockAudit: AuditEntry = { 
    id: 'a1', 
    recommendationId: 'r1', 
    decision: { recommendationId: 'r1', status: 'approved', operatorId: 'sys', decidedAt: 200 }, 
    sourceRecommendation: { id: 'r1', capability: 'test', targetContext: { uri: 'test' }, rationale: 'test', confidence: 1, severity: 'info', sourceFindingIds: [] }, 
    recordedAt: 200 
  };
  const mockApproved: ApprovedRequestRecord = { 
    id: 'ap1', 
    recommendationId: 'r1', 
    capability: 'test', 
    targetUri: 'https://example.com', 
    approvedAt: 200, 
    operatorId: 'sys', 
    sourceRecommendationId: 'r1',
    requestSummary: {} 
  };
  const mockFailure: ExecutionFailureRecord = { 
    id: 'f1', 
    capability: 'test', 
    targetUri: 'https://example.com', 
    errorMessage: 'err', 
    failedAt: 300, 
    recoverable: true, 
    lifecycleStatusAtFailure: 'initialized' 
  };
  
  await repo.appendEvidence({ sessionId, evidence: mockEvidence, capability: 'subdomain_discovery', recordedAt: 200 });
  await repo.appendAuditEntry({ sessionId, entry: mockAudit, recordedAt: 200 });
  await repo.appendApprovedRequest({ sessionId, record: mockApproved, recordedAt: 200 });
  await repo.appendExecutionFailure({ sessionId, record: mockFailure, recordedAt: 300 });

  const evList = await repo.listEvidence(sessionId);
  const auList = await repo.listAuditEntries(sessionId);
  const apList = await repo.listApprovedRequests(sessionId);
  const faList = await repo.listExecutionFailures(sessionId);

  if (evList.length !== 1 || evList[0].metadata.m !== 1) throw new Error('Evidence list failed');
  if (auList.length !== 1 || auList[0].id !== 'a1') throw new Error('Audit list failed');
  if (apList.length !== 1 || apList[0].id !== 'ap1') throw new Error('Approved list failed');
  if (faList.length !== 1 || faList[0].id !== 'f1') throw new Error('Failure list failed');
  
  console.log('[+] Append and list correctly filter by sessionId.');

  console.log('[*] Testing listSessions summary counts...');
  // update findingCount, pendingRecs, executionFailures inside state for summary check
  const stateForSummary: AssessmentState = {
    ...nextState,
    version: 3,
    evidenceCollections: [
      { findings: [{ id: 'f1', type: 't', severity: 'info', title: 't', description: 'd', target: 't', evidence: 'e', confidence: 1, metadata: {} }], metadata: {} }
    ],
    pendingRecommendations: [{ id: 'r2', capability: 'c', targetContext: { uri: 't' }, rationale: 'r', confidence: 1, severity: 'info', sourceFindingIds: [] }],
    executionFailures: [mockFailure]
  };
  await repo.saveAssessmentState({ state: stateForSummary, expectedVersion: 2 });

  const summaries = await repo.listSessions();
  if (summaries.length !== 1) throw new Error('listSessions failed');
  const summary = summaries[0];
  if (summary.findingCount !== 1) throw new Error(`Summary findingCount is ${summary.findingCount}, expected 1`);
  if (summary.pendingRecommendationCount !== 1) throw new Error('Summary pendingRecommendationCount failed');
  if (summary.executionFailureCount !== 1) throw new Error('Summary executionFailureCount failed');
  
  console.log('[+] listSessions successfully derived summaries from snapshot.');

  // Check no raw CapabilityRequest or anything related to executables
  if ('approvedRequests' in summary || 'CapabilityRequest' in summary) {
    throw new Error('Storage adapter leaked executable state into summary');
  }

  console.log('[*] Testing cross-session isolation...');
  const secondSessionId = 'session-storage-smoke-2';
  const secondTargetUri = 'https://second.example.com';
  
  const secondState: AssessmentState = {
    ...initialState,
    sessionId: secondSessionId,
    targetUri: secondTargetUri,
    version: 1
  };
  await repo.saveAssessmentState({ state: secondState, expectedVersion: 0 });

  const mockEvidence2: EvidenceCollection = { findings: [], metadata: { m: 2 } };
  const mockAudit2: AuditEntry = { ...mockAudit, id: 'a2' };
  const mockApproved2: ApprovedRequestRecord = { ...mockApproved, id: 'ap2' };
  const mockFailure2: ExecutionFailureRecord = { ...mockFailure, id: 'f2' };

  await repo.appendEvidence({ sessionId: secondSessionId, evidence: mockEvidence2, capability: 'http_probe', recordedAt: 400 });
  await repo.appendAuditEntry({ sessionId: secondSessionId, entry: mockAudit2, recordedAt: 400 });
  await repo.appendApprovedRequest({ sessionId: secondSessionId, record: mockApproved2, recordedAt: 400 });
  await repo.appendExecutionFailure({ sessionId: secondSessionId, record: mockFailure2, recordedAt: 400 });

  console.log('[-] Verifying first-session lists do not include second-session records...');
  const evList1 = await repo.listEvidence(sessionId);
  if (evList1.some(e => e.metadata.m === 2)) throw new Error('First session evidence leaked from second session');
  const auList1 = await repo.listAuditEntries(sessionId);
  if (auList1.some(a => a.id === 'a2')) throw new Error('First session audit leaked from second session');
  const apList1 = await repo.listApprovedRequests(sessionId);
  if (apList1.some(a => a.id === 'ap2')) throw new Error('First session approved requests leaked from second session');
  const faList1 = await repo.listExecutionFailures(sessionId);
  if (faList1.some(f => f.id === 'f2')) throw new Error('First session failures leaked from second session');

  console.log('[-] Verifying second-session lists only return its own records...');
  const evList2 = await repo.listEvidence(secondSessionId);
  if (evList2.length !== 1 || evList2[0].metadata.m !== 2) throw new Error('Second session evidence list failed');
  const auList2 = await repo.listAuditEntries(secondSessionId);
  if (auList2.length !== 1 || auList2[0].id !== 'a2') throw new Error('Second session audit list failed');
  const apList2 = await repo.listApprovedRequests(secondSessionId);
  if (apList2.length !== 1 || apList2[0].id !== 'ap2') throw new Error('Second session approved requests list failed');
  const faList2 = await repo.listExecutionFailures(secondSessionId);
  if (faList2.length !== 1 || faList2[0].id !== 'f2') throw new Error('Second session failures list failed');

  console.log('[-] Verifying listSessions filter behavior...');
  const sessionsSummary1 = await repo.listSessions({ targetUri: 'https://example.com' });
  if (sessionsSummary1.length !== 1 || sessionsSummary1[0].sessionId !== sessionId) {
    throw new Error('listSessions filter by first targetUri failed');
  }

  const sessionsSummary2 = await repo.listSessions({ targetUri: secondTargetUri });
  if (sessionsSummary2.length !== 1 || sessionsSummary2[0].sessionId !== secondSessionId) {
    throw new Error('listSessions filter by second targetUri failed');
  }
  
  console.log('[+] Session isolation and filters verified successfully.');
  
  console.log('--- Smoke Test Completed Successfully ---');
}

runSmoke().catch(err => {
  console.error('[!] Smoke test failed:', err);
  process.exit(1);
});
