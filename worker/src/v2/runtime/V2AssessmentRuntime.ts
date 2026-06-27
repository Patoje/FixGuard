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
import { LocalIntentTranslator } from '../approval/IntentTranslator';

import type { CapabilityRequest } from '../core/ExecutionContracts';
import type { AttackRecommendation } from '../intelligence/AttackRecommendation';
import type { AssessmentState, ApprovedRequestRecord, ExecutionFailureRecord } from './AssessmentState';
import { V2AssessmentSession } from './V2AssessmentSession';
import type { AssessmentRepository } from '../storage/AssessmentRepository';
import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository';
import type { AuditEntry } from '../approval/ApprovalContracts';

export class V2AssessmentRuntime {
  private sessions = new Map<string, V2AssessmentSession>();

  // Shared internal services.
  private readonly orchestrator: MinimalOrchestrator;
  
  private inbox = new LocalRecommendationInbox();
  private auditLog = new LocalAuditLog();
  private intentTranslator = new LocalIntentTranslator();
  private approvalGateway = new LocalApprovalGateway(this.inbox, this.auditLog, this.intentTranslator);

  constructor(
    private readonly repository: AssessmentRepository = new InMemoryAssessmentRepository(),
    orchestratorOrRegistry?: MinimalOrchestrator | ToolRegistry
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
  }

  private async persistState(session: V2AssessmentSession, isNew: boolean = false): Promise<void> {
    const state = session.getState();
    const expectedVersion = isNew ? 0 : state.version - 1;
    await this.repository.saveAssessmentState({ state, expectedVersion });
  }

  public async createSession(targetUri: string): Promise<V2AssessmentSession> {
    const session = new V2AssessmentSession(targetUri);
    this.sessions.set(session.getState().sessionId, session);
    await this.persistState(session, true);
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
    const targetUri = session.getState().targetUri;

    session.update(() => ({ lifecycleStatus: 'initial_execution_running' }));
    await this.persistState(session);

    const req: CapabilityRequest = {
      capability: 'subdomain_discovery',
      target: { uri: targetUri },
      config: {}
    };

    try {
      const evidence = await this.orchestrator.run(req);
      session.update(state => ({
        evidenceCollections: [...state.evidenceCollections, evidence],
        lifecycleStatus: 'profile_updated'
      }));
      await this.persistState(session);
      await this.repository.appendEvidence({
        sessionId,
        evidence,
        capability: req.capability,
        recordedAt: Date.now()
      });
    } catch (err: any) {
      const failure: ExecutionFailureRecord = {
        id: `fail_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
        capability: req.capability,
        targetUri,
        failedAt: Date.now(),
        errorMessage: err.message || String(err),
        recoverable: true,
        lifecycleStatusAtFailure: session.getState().lifecycleStatus
      };
      
      session.update(state => ({
        executionFailures: [...state.executionFailures, failure],
        errors: [...state.errors, `Initial recon failed: ${err.message}`],
        lifecycleStatus: 'profile_updated'
      }));
      await this.persistState(session);
      await this.repository.appendExecutionFailure({
        sessionId,
        record: failure,
        recordedAt: failure.failedAt
      });
    }

    return session.getState();
  }

  public async runIntelligence(sessionId: string): Promise<AssessmentState> {
    const session = this.getSessionOrThrow(sessionId);
    const state = session.getState();

    session.update(() => ({ lifecycleStatus: 'intelligence_running' }));
    await this.persistState(session);

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

    session.update(s => ({
      currentProfile: profile,
      pendingRecommendations: [...s.pendingRecommendations, ...newRecs],
      lifecycleStatus: (s.pendingRecommendations.length + newRecs.length) > 0 ? 'awaiting_approval' : 'completed'
    }));
    await this.persistState(session);

    return session.getState();
  }

  public async approveRecommendation(
    sessionId: string, 
    recommendationId: string, 
    operatorId: string, 
    overrides?: Record<string, unknown>
  ): Promise<AssessmentState> {
    const session = this.getSessionOrThrow(sessionId);
    
    // Verify recommendation belongs to this session
    const pendingRec = session.getState().pendingRecommendations.find(r => r.id === recommendationId);
    if (!pendingRec) {
      throw new Error(`Recommendation ${recommendationId} not found in pending state for session ${sessionId}`);
    }
    
    let approvalResult;
    try {
      approvalResult = overrides 
        ? this.approvalGateway.approveWithOverrides(recommendationId, operatorId, overrides)
        : this.approvalGateway.approve(recommendationId, operatorId);
    } catch (err: any) {
      session.update(state => ({
        lifecycleStatus: 'failed',
        errors: [...state.errors, `Approval translation failure: ${err.message}`]
      }));
      await this.persistState(session);
      return session.getState();
    }

    if (!approvalResult.request) {
      session.update(state => ({
        lifecycleStatus: 'failed',
        errors: [...state.errors, `Approval failed to yield a CapabilityRequest`]
      }));
      await this.persistState(session);
      return session.getState();
    }

    const request = approvalResult.request;
    const sourceRecId = request.config?.sourceRecommendationId as string || recommendationId;

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
    session.update(state => {
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
    await this.persistState(session);
    await this.repository.appendApprovedRequest({
      sessionId,
      record,
      recordedAt: record.approvedAt
    });
    await this.repository.appendAuditEntry({
      sessionId,
      entry: auditEntry,
      recordedAt: auditEntry.recordedAt
    });

    try {
      const evidence = await this.orchestrator.run(request);
      session.update(state => ({
        evidenceCollections: [...state.evidenceCollections, evidence],
        lifecycleStatus: 'profile_updated'
      }));
      await this.persistState(session);
      await this.repository.appendEvidence({
        sessionId,
        evidence,
        capability: request.capability,
        recordedAt: Date.now(),
        sourceApprovedRequestRecordId: record.id
      });
    } catch (err: any) {
      const failure: ExecutionFailureRecord = {
        id: `fail_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
        capability: request.capability,
        targetUri: request.target.uri,
        failedAt: Date.now(),
        errorMessage: err.message || String(err),
        recoverable: true,
        sourceRecommendationId: recommendationId,
        lifecycleStatusAtFailure: session.getState().lifecycleStatus
      };
      
      session.update(state => ({
        executionFailures: [...state.executionFailures, failure],
        errors: [...state.errors, `Approved execution failed: ${err.message}`],
        lifecycleStatus: state.pendingRecommendations.length > 0 ? 'awaiting_approval' : 'completed'
      }));
      await this.persistState(session);
      await this.repository.appendExecutionFailure({
        sessionId,
        record: failure,
        recordedAt: failure.failedAt
      });
    }

    return session.getState();
  }

  public async rejectRecommendation(sessionId: string, recommendationId: string, operatorId: string, reason: string): Promise<AssessmentState> {
    const session = this.getSessionOrThrow(sessionId);
    
    // Verify recommendation belongs to this session
    const pendingRec = session.getState().pendingRecommendations.find(r => r.id === recommendationId);
    if (!pendingRec) {
      throw new Error(`Recommendation ${recommendationId} not found in pending state for session ${sessionId}`);
    }

    const approvalResult = this.approvalGateway.reject(recommendationId, operatorId, reason);

    let auditEntry!: AuditEntry;
    session.update(state => {
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
    await this.persistState(session);
    await this.repository.appendAuditEntry({
      sessionId,
      entry: auditEntry,
      recordedAt: auditEntry.recordedAt
    });

    return session.getState();
  }

  public async completeSession(sessionId: string): Promise<AssessmentState> {
    const session = this.getSessionOrThrow(sessionId);
    const status = session.getState().lifecycleStatus;
    
    if (status === 'initial_execution_running' || status === 'intelligence_running' || status === 'approved_execution_running') {
      throw new Error(`Cannot complete session while operations are running (current status: ${status})`);
    }

    session.update(() => ({ lifecycleStatus: 'completed' }));
    await this.persistState(session);
    return session.getState();
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
}
