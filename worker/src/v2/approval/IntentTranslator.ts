import type { AttackRecommendation } from '../intelligence/AttackRecommendation';
import type { ApprovalDecision } from './ApprovalContracts';
import type { CapabilityRequest } from '../core/ExecutionContracts';

export interface IntentTranslator {
  translate(
    recommendation: AttackRecommendation,
    decision: ApprovalDecision
  ): CapabilityRequest;
}

export class LocalIntentTranslator implements IntentTranslator {
  translate(
    recommendation: AttackRecommendation,
    decision: ApprovalDecision
  ): CapabilityRequest {
    if (decision.status === 'rejected' || decision.status === 'pending') {
      throw new Error(`Cannot translate intent for recommendation with status: ${decision.status}`);
    }

    const baseConfig = decision.configOverrides || {};
    
    return {
      capability: recommendation.capability,
      target: {
        uri: recommendation.targetContext.uri
      },
      config: {
        ...baseConfig,
        sourceRecommendationId: recommendation.id
      }
    };
  }
}
