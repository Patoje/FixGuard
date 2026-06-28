import { MinimalOrchestrator } from '../core/MinimalOrchestrator';
import { LocalProcessRunner } from '../core/ProcessRunner';
import { createV2ToolRegistry } from '../composition/createV2ToolRegistry';
import type { ToolRegistry } from '../core/ToolRegistry';
import { LocalEvidenceAccumulator } from '../intelligence/EvidenceAccumulator';
import { LocalCorrelationEngine } from '../intelligence/CorrelationEngine';
import { LocalTargetProfileBuilder } from '../intelligence/TargetProfileBuilder';
import { LocalRecommendationEngine } from '../intelligence/RecommendationEngine';
import { SubdomainProfilerRule } from '../intelligence/rules/SubdomainProfilerRule';
import { HttpProbeProfilerRule } from '../intelligence/rules/HttpProbeProfilerRule';
import { SubdomainHttpProbeRule } from '../intelligence/rules/SubdomainHttpProbeRule';
import { LocalRecommendationInbox } from '../approval/RecommendationInbox';
import { LocalApprovalGateway } from '../approval/ApprovalGateway';
import { LocalAuditLog } from '../approval/AuditLog';
import { LocalIntentTranslator, CapabilityValidationError } from '../approval/IntentTranslator';
import type { IntentTranslator } from '../approval/IntentTranslator';
import type { CapabilityRegistry } from '../capabilities/CapabilityRegistry';
import { createDefaultCapabilityRegistry } from '../capabilities/DefaultCapabilityRegistry';

import type { CapabilityRequest } from '../core/ExecutionContracts';
import type { AttackRecommendation } from '../intelligence/AttackRecommendation';
import type { AssessmentState, ApprovedRequestRecord, ExecutionFailureRecord, LifecycleState } from './AssessmentState';
import { V2AssessmentSession } from './V2AssessmentSession';
import { RuntimeLifecycleError } from './RuntimeLifecycleError';
import type { AssessmentRepository } from '../storage/AssessmentRepository';
import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository';
import { isTransactionalAssessmentRepository } from '../storage/TransactionalAssessmentRepository';
import type { AuditEntry } from '../approval/ApprovalContracts';
import type { EvidenceCollection } from '../core/Evidence';

const FORBIDDEN_OVERRIDE_KEYS = new Set([
  'binary', 'args', 'env', 'command', 'shell', 'stdin'
]);

function assertNoExecutableKeys(obj: any): void {
  if (obj === null || obj === undefined) {
    return;
  }
  
  if (Array.isArray(obj)) {
    for (const item of obj) {
      assertNoExecutableKeys(item);
    }
    return;
  }
  
  if (typeof obj === 'object') {
    for (const [key, value] of Object.entries(obj)) {
      if (FORBIDDEN_OVERRIDE_KEYS.has(key)) {
        throw new Error(`Approval validation failed: Executable override key '${key}' is forbidden`);
      }
      assertNoExecutableKeys(value);
    }
  }
}

export interface V2AssessmentRuntimeOptions {
  intentTranslator?: IntentTranslator;
  capabilityRegistry?: CapabilityRegistry;
}

export class V2AssessmentRuntime {
  private sessions = new Map<string, V2AssessmentSession>();

  // Shared internal services.
  private readonly orchestrator: MinimalOrchestrator;
  
  private inbox = new LocalRecommendationInbox();
  private auditLog = new LocalAuditLog();
  private intentTranslator: IntentTranslator;
  private approvalGateway: LocalApprovalGateway;

  constructor(
    private readonly repository: AssessmentRepository = new InMemoryAssessmentRepository(),
    orchestratorOrRegistry?: MinimalOrchestrator | ToolRegistry,
    options?: V2AssessmentRuntimeOptions
  ) {
    if (orchestratorOrRegistry instanceof MinimalOrchestrator) {
      this.orchestrator = orchestratorOrRegistry;
    } else if (orchestratorOrRegistry !== undefined) {
      // Treat as a ToolRegistry — compose the orchestrator from it
      this.orchestrator = new MinimalOrchestrator(orchestratorOrRegistry, new LocalProcessRunner());
    } else {
      // Default: production registry + local process runner
      const registry = createV2ToolRegistry();
      this.orchestrator = new MinimalOrchestrator(registry, new LocalProcessRunner());
    }

    const registry = options?.capabilityRegistry ?? createDefaultCapabilityRegistry();
    this.intentTranslator = options?.intentTranslator ?? new LocalIntentTranslator(registry);
    this.approvalGateway = new LocalApprovalGateway(this.inbox, this.auditLog, this.intentTranslator);
  }

  private async runWithRepositoryTransactionIfAvailable<T>(
    work: (repository: AssessmentRepository) => Promise<T>
  ): Promise<T> {
    if (isTransactionalAssessmentRepository(this.repository)) {
      return this.repository.withTransaction(work);
    }
    return work(this.repository);
  }

  private async persistState(repository: AssessmentRepository, session: V2AssessmentSession, isNew: boolean = false): Promise<void> {
    const state = session.getState();
    const expectedVersion = isNew ? 0 : state.version - 1;
    await repository.saveAssessmentState({ state, expectedVersion });
  }

  public async createSession(targetUri: string): Promise<V2AssessmentSession> {
    const session = new V2AssessmentSession(targetUri);
    await this.persistState(this.repository, session, true);
    this.sessions.set(session.getState().sessionId, session);
    return session;
  }

  public getSession(sessionId: string): V2AssessmentSession | undefined {
    return this.sessions.get(sessionId);
  }

  public async loadSession(sessionId: string): Promise<V2AssessmentSession | undefined> {
    const active = this.getSession(sessionId);
    if (active) {
      return active;
    }

    const state = await this.repository.loadAssessmentState(sessionId);
    if (!state) {
      return undefined;
    }

    const session = V2AssessmentSession.fromState(state);
    this.sessions.set(session.getState().sessionId, session);
    return session;
  }

  public async startInitialRecon(sessionId: string): Promise<AssessmentState> {
    const session = this.getSessionOrThrow(sessionId);
    const state = session.getState();
    this.assertCanStartInitialRecon(state);

    const targetUri = state.targetUri;

    let draft = V2AssessmentSession.fromState(session.getState());
    draft.update(() => ({ lifecycleStatus: 'initial_execution_running' }));
    await this.persistState(this.repository, draft);
    this.sessions.set(sessionId, draft);

    const req: CapabilityRequest = {
      capability: 'subdomain_discovery',
      target: { uri: targetUri },
      config: {}
    };

    let evidence!: EvidenceCollection;
    let executionErr: any;
    try {
      evidence = await this.orchestrator.run(req);
    } catch (err: any) {
      executionErr = err;
    }

    if (executionErr) {
      draft = V2AssessmentSession.fromState(this.sessions.get(sessionId)!.getState());
      const failure: ExecutionFailureRecord = {
        id: `fail_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
        capability: req.capability,
        targetUri,
        failedAt: Date.now(),
        errorMessage: executionErr.message || String(executionErr),
        recoverable: true,
        lifecycleStatusAtFailure: draft.getState().lifecycleStatus
      };
      
      draft.update(state => ({
        executionFailures: [...state.executionFailures, failure],
        errors: [...state.errors, `Initial recon failed: ${executionErr.message}`],
        lifecycleStatus: 'profile_updated'
      }));

      await this.runWithRepositoryTransactionIfAvailable(async (txRepo) => {
        await this.persistState(txRepo, draft);
        await txRepo.appendExecutionFailure({
          sessionId,
          record: failure,
          recordedAt: failure.failedAt
        });
      });
      this.sessions.set(sessionId, draft);
      return draft.getState();
    }

    draft = V2AssessmentSession.fromState(this.sessions.get(sessionId)!.getState());
    draft.update(state => ({
      evidenceCollections: [...state.evidenceCollections, evidence],
      lifecycleStatus: 'profile_updated'
    }));

    await this.runWithRepositoryTransactionIfAvailable(async (txRepo) => {
      await this.persistState(txRepo, draft);
      await txRepo.appendEvidence({
        sessionId,
        evidence,
        capability: req.capability,
        recordedAt: Date.now()
      });
    });
    this.sessions.set(sessionId, draft);
    return draft.getState();
  }

  public async runIntelligence(sessionId: string): Promise<AssessmentState> {
    const session = this.getSessionOrThrow(sessionId);
    const state = session.getState();
    this.assertCanRunIntelligence(state);

    let draft = V2AssessmentSession.fromState(session.getState());
    draft.update(() => ({ lifecycleStatus: 'intelligence_running' }));
    await this.persistState(this.repository, draft);
    this.sessions.set(sessionId, draft);

    const accumulator = new LocalEvidenceAccumulator();
    for (const ec of state.evidenceCollections) {
      accumulator.add(ec);
    }

    const correlationEngine = new LocalCorrelationEngine();
    const correlated = correlationEngine.correlate(accumulator.getAllFindings());

    const profileBuilder = new LocalTargetProfileBuilder([
      new SubdomainProfilerRule(),
      new HttpProbeProfilerRule()
    ]);
    const profile = profileBuilder.build(correlated, state.targetUri);

    const recommendationEngine = new LocalRecommendationEngine([
      new SubdomainHttpProbeRule()
    ]);
    const recommendations = recommendationEngine.recommend(profile);

    const existingIntents = new Set<string>();

    for (const r of state.pendingRecommendations) {
      existingIntents.add(this.getIntentKey(r.capability, r.targetContext.uri));
    }
    
    for (const r of state.approvedRequestRecords) {
      existingIntents.add(this.getIntentKey(r.capability, r.targetUri));
    }

    const newRecs = recommendations.filter((r: AttackRecommendation) => {
      const intent = this.getIntentKey(r.capability, r.targetContext.uri);
      return !existingIntents.has(intent);
    });

    for (const rec of newRecs) {
      this.inbox.add(rec);
    }

    // Refresh draft from active session in case it wasn't modified? 
    // It's the same draft object so we can just update it again, 
    // but wait! If we mutated draft earlier, it's the active session now, so we can just make a new draft from active session
    draft = V2AssessmentSession.fromState(this.sessions.get(sessionId)!.getState());
    draft.update(s => ({
      currentProfile: profile,
      pendingRecommendations: [...s.pendingRecommendations, ...newRecs],
      lifecycleStatus: (s.pendingRecommendations.length + newRecs.length) > 0 ? 'awaiting_approval' : 'completed'
    }));
    await this.persistState(this.repository, draft);
    this.sessions.set(sessionId, draft);

    return draft.getState();
  }

  public async approveRecommendation(
    sessionId: string, 
    recommendationId: string, 
    operatorId: string, 
    overrides?: Record<string, unknown>
  ): Promise<AssessmentState> {
    assertNoExecutableKeys(overrides);

    const session = this.getSessionOrThrow(sessionId);
    const state = session.getState();
    this.assertCanApproveRecommendation(state);
    
    // Verify recommendation belongs to this session
    const pendingRec = state.pendingRecommendations.find(r => r.id === recommendationId);
    if (!pendingRec) {
      throw new Error(`Recommendation ${recommendationId} not found in pending state for session ${sessionId}`);
    }
    
    let approvalResult;
    try {
      approvalResult = overrides 
        ? this.approvalGateway.approveRecommendation(pendingRec, operatorId, overrides)
        : this.approvalGateway.approveRecommendation(pendingRec, operatorId);
    } catch (err: any) {
      if (err instanceof CapabilityValidationError) {
        throw err;
      }
      let draft = V2AssessmentSession.fromState(session.getState());
      draft.update(state => ({
        lifecycleStatus: 'failed',
        errors: [...state.errors, `Approval translation failure: ${err.message}`]
      }));
      await this.persistState(this.repository, draft);
      this.sessions.set(sessionId, draft);
      return draft.getState();
    }

    if (!approvalResult.request) {
      let draft = V2AssessmentSession.fromState(session.getState());
      draft.update(state => ({
        lifecycleStatus: 'failed',
        errors: [...state.errors, `Approval failed to yield a CapabilityRequest`]
      }));
      await this.persistState(this.repository, draft);
      this.sessions.set(sessionId, draft);
      return draft.getState();
    }

    const request = approvalResult.request;
    const sourceRecId = request.config?.sourceRecommendationId as string || recommendationId;

    let draft = V2AssessmentSession.fromState(session.getState());
    const record: ApprovedRequestRecord = {
      id: `ar_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
      recommendationId,
      capability: request.capability,
      targetUri: request.target.uri,
      approvedAt: Date.now(),
      operatorId,
      sourceRecommendationId: sourceRecId,
      requestSummary: { ...request.config }
    };

    let auditEntry!: AuditEntry;
    draft.update(state => {
      const sourceRec = state.pendingRecommendations.find(r => r.id === recommendationId)!;
      auditEntry = {
        id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
        recommendationId,
        decision: approvalResult.decision,
        sourceRecommendation: sourceRec,
        recordedAt: Date.now()
      };
      return {
        lifecycleStatus: 'approved_execution_running',
        pendingRecommendations: state.pendingRecommendations.filter(r => r.id !== recommendationId),
        approvedRequestRecords: [...state.approvedRequestRecords, record],
        auditEntries: [...state.auditEntries, auditEntry]
      };
    });

    await this.runWithRepositoryTransactionIfAvailable(async (txRepo) => {
      await this.persistState(txRepo, draft);
      await txRepo.appendApprovedRequest({
        sessionId,
        record,
        recordedAt: record.approvedAt
      });
      await txRepo.appendAuditEntry({
        sessionId,
        entry: auditEntry,
        recordedAt: auditEntry.recordedAt
      });
    });
    this.sessions.set(sessionId, draft);

    let evidence!: EvidenceCollection;
    let executionErr: any;
    try {
      evidence = await this.orchestrator.run(request);
    } catch (err: any) {
      executionErr = err;
    }

    if (executionErr) {
      draft = V2AssessmentSession.fromState(this.sessions.get(sessionId)!.getState());
      const failure: ExecutionFailureRecord = {
        id: `fail_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
        capability: request.capability,
        targetUri: request.target.uri,
        failedAt: Date.now(),
        errorMessage: executionErr.message || String(executionErr),
        recoverable: true,
        sourceRecommendationId: recommendationId,
        lifecycleStatusAtFailure: draft.getState().lifecycleStatus
      };
      
      draft.update(state => ({
        executionFailures: [...state.executionFailures, failure],
        errors: [...state.errors, `Approved execution failed: ${executionErr.message}`],
        lifecycleStatus: state.pendingRecommendations.length > 0 ? 'awaiting_approval' : 'completed'
      }));

      await this.runWithRepositoryTransactionIfAvailable(async (txRepo) => {
        await this.persistState(txRepo, draft);
        await txRepo.appendExecutionFailure({
          sessionId,
          record: failure,
          recordedAt: failure.failedAt
        });
      });
      this.sessions.set(sessionId, draft);
      return draft.getState();
    }

    draft = V2AssessmentSession.fromState(this.sessions.get(sessionId)!.getState());
    draft.update(state => ({
      evidenceCollections: [...state.evidenceCollections, evidence],
      lifecycleStatus: 'profile_updated'
    }));

    await this.runWithRepositoryTransactionIfAvailable(async (txRepo) => {
      await this.persistState(txRepo, draft);
      await txRepo.appendEvidence({
        sessionId,
        evidence,
        capability: request.capability,
        recordedAt: Date.now(),
        sourceApprovedRequestRecordId: record.id
      });
    });
    this.sessions.set(sessionId, draft);
    return draft.getState();
  }

  public async rejectRecommendation(sessionId: string, recommendationId: string, operatorId: string, reason: string): Promise<AssessmentState> {
    const session = this.getSessionOrThrow(sessionId);
    const state = session.getState();
    this.assertCanRejectRecommendation(state);
    
    // Verify recommendation belongs to this session
    const pendingRec = state.pendingRecommendations.find(r => r.id === recommendationId);
    if (!pendingRec) {
      throw new Error(`Recommendation ${recommendationId} not found in pending state for session ${sessionId}`);
    }

    const approvalResult = this.approvalGateway.rejectRecommendation(pendingRec, operatorId, reason);

    const draft = V2AssessmentSession.fromState(session.getState());
    let auditEntry!: AuditEntry;
    draft.update(state => {
      const pending = state.pendingRecommendations.filter(r => r.id !== recommendationId);
      const sourceRec = state.pendingRecommendations.find(r => r.id === recommendationId)!;
      auditEntry = {
        id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
        recommendationId,
        decision: approvalResult.decision,
        sourceRecommendation: sourceRec,
        recordedAt: Date.now()
      };
      return {
        pendingRecommendations: pending,
        lifecycleStatus: pending.length > 0 ? 'awaiting_approval' : 'completed',
        auditEntries: [...state.auditEntries, auditEntry]
      };
    });

    await this.runWithRepositoryTransactionIfAvailable(async (txRepo) => {
      await this.persistState(txRepo, draft);
      await txRepo.appendAuditEntry({
        sessionId,
        entry: auditEntry,
        recordedAt: auditEntry.recordedAt
      });
    });

    this.sessions.set(sessionId, draft);
    return draft.getState();
  }

  public async completeSession(sessionId: string): Promise<AssessmentState> {
    const session = this.getSessionOrThrow(sessionId);
    const state = session.getState();
    this.assertCanComplete(state);

    const draft = V2AssessmentSession.fromState(session.getState());
    draft.update(() => ({ lifecycleStatus: 'completed' }));
    await this.persistState(this.repository, draft);
    this.sessions.set(sessionId, draft);
    return draft.getState();
  }

  private getSessionOrThrow(sessionId: string): V2AssessmentSession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    return session;
  }

  /**
   * Generates a stable intent key for deduplicating recommendations.
   * Future richer dedupe may need config/source-finding/auth-context, but capability+targetUri is sufficient for now.
   */
  private getIntentKey(capability: string, targetUri: string): string {
    return `${capability}:${targetUri}`;
  }

  // --- Lifecycle Guards ---

  private assertCanStartInitialRecon(state: AssessmentState): void {
    this.assertNotTerminal(state, 'startInitialRecon');
    if (this.isRunningStatus(state.lifecycleStatus) || state.lifecycleStatus !== 'initialized') {
      throw new RuntimeLifecycleError(state.sessionId, 'startInitialRecon', state.lifecycleStatus);
    }
  }

  private assertCanRunIntelligence(state: AssessmentState): void {
    this.assertNotTerminal(state, 'runIntelligence');
    const allowed: LifecycleState[] = ['initialized', 'profile_updated', 'awaiting_approval'];
    if (this.isRunningStatus(state.lifecycleStatus) || !allowed.includes(state.lifecycleStatus)) {
      throw new RuntimeLifecycleError(state.sessionId, 'runIntelligence', state.lifecycleStatus);
    }
  }

  private assertCanApproveRecommendation(state: AssessmentState): void {
    this.assertNotTerminal(state, 'approveRecommendation');
    if (this.isRunningStatus(state.lifecycleStatus) || state.lifecycleStatus !== 'awaiting_approval') {
      throw new RuntimeLifecycleError(state.sessionId, 'approveRecommendation', state.lifecycleStatus);
    }
  }

  private assertCanRejectRecommendation(state: AssessmentState): void {
    this.assertNotTerminal(state, 'rejectRecommendation');
    if (this.isRunningStatus(state.lifecycleStatus) || state.lifecycleStatus !== 'awaiting_approval') {
      throw new RuntimeLifecycleError(state.sessionId, 'rejectRecommendation', state.lifecycleStatus);
    }
  }

  private assertCanComplete(state: AssessmentState): void {
    this.assertNotTerminal(state, 'completeSession');
    const allowed: LifecycleState[] = ['initialized', 'profile_updated', 'awaiting_approval'];
    if (this.isRunningStatus(state.lifecycleStatus) || !allowed.includes(state.lifecycleStatus)) {
      throw new RuntimeLifecycleError(state.sessionId, 'completeSession', state.lifecycleStatus);
    }
  }

  private assertNotTerminal(state: AssessmentState, action: string): void {
    if (state.lifecycleStatus === 'completed' || state.lifecycleStatus === 'failed') {
      throw new RuntimeLifecycleError(state.sessionId, action, state.lifecycleStatus);
    }
  }

  private isRunningStatus(status: LifecycleState): boolean {
    return status === 'initial_execution_running' ||
           status === 'intelligence_running' ||
           status === 'approved_execution_running';
  }
}
