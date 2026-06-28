import type { AttackRecommendation } from '../intelligence/AttackRecommendation';
import type { ApprovalDecision, AuditEntry } from './ApprovalContracts';
import type { CapabilityRequest } from '../core/ExecutionContracts';
import type { RecommendationInbox } from './RecommendationInbox';
import type { AuditLog } from './AuditLog';
import type { IntentTranslator } from './IntentTranslator';

export interface ApprovalResult {
  decision: ApprovalDecision;
  request?: CapabilityRequest;
}

export interface ApprovalGateway {
  listPending(): AttackRecommendation[];
  approve(id: string, operatorId: string, configOverrides?: Record<string, unknown>): ApprovalResult;
  approveWithOverrides(id: string, operatorId: string, overrides: Record<string, unknown>): ApprovalResult;
  reject(id: string, operatorId: string, reason: string): ApprovalResult;
  
  approveRecommendation(recommendation: AttackRecommendation, operatorId: string, configOverrides?: Record<string, unknown>): ApprovalResult;
  rejectRecommendation(recommendation: AttackRecommendation, operatorId: string, reason: string): ApprovalResult;
}

export class LocalApprovalGateway implements ApprovalGateway {
  constructor(
    private inbox: RecommendationInbox,
    private auditLog: AuditLog,
    private translator: IntentTranslator
  ) {}

  listPending(): AttackRecommendation[] {
    return this.inbox.listPending();
  }

  approve(id: string, operatorId: string, configOverrides?: Record<string, unknown>): ApprovalResult {
    const recommendation = this.getRecommendationOrThrow(id);
    return this.approveRecommendation(recommendation, operatorId, configOverrides);
  }

  approveWithOverrides(id: string, operatorId: string, overrides: Record<string, unknown>): ApprovalResult {
    return this.approve(id, operatorId, overrides);
  }

  reject(id: string, operatorId: string, reason: string): ApprovalResult {
    const recommendation = this.getRecommendationOrThrow(id);
    return this.rejectRecommendation(recommendation, operatorId, reason);
  }

  approveRecommendation(recommendation: AttackRecommendation, operatorId: string, configOverrides?: Record<string, unknown>): ApprovalResult {
    const decision: ApprovalDecision = {
      recommendationId: recommendation.id,
      status: configOverrides ? 'approved_with_overrides' : 'approved',
      operatorId,
      decidedAt: Date.now()
    };
    
    if (configOverrides) {
      decision.configOverrides = configOverrides;
    }

    const request = this.translator.translate(recommendation, decision);
    
    this.recordAndRemove(recommendation, decision);
    
    return { decision, request };
  }

  rejectRecommendation(recommendation: AttackRecommendation, operatorId: string, reason: string): ApprovalResult {
    const decision: ApprovalDecision = {
      recommendationId: recommendation.id,
      status: 'rejected',
      operatorId,
      decidedAt: Date.now(),
      rejectionReason: reason
    };

    this.recordAndRemove(recommendation, decision);
    
    return { decision };
  }

  private getRecommendationOrThrow(id: string): AttackRecommendation {
    const rec = this.inbox.get(id);
    if (!rec) {
      throw new Error(`Recommendation not found: ${id}`);
    }
    return rec;
  }

  private recordAndRemove(recommendation: AttackRecommendation, decision: ApprovalDecision): void {
    const entry: AuditEntry = {
      id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
      recommendationId: recommendation.id,
      decision,
      sourceRecommendation: recommendation,
      recordedAt: Date.now()
    };
    
    this.auditLog.record(entry);
    this.inbox.remove(recommendation.id);
  }
}
