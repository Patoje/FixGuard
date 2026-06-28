import type { AttackRecommendation } from '../intelligence/AttackRecommendation';
import type { ApprovalDecision } from './ApprovalContracts';
import type { CapabilityRequest } from '../core/ExecutionContracts';
import type { CapabilityRegistry } from '../capabilities/CapabilityRegistry';

export class CapabilityValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CapabilityValidationError';
  }
}

export interface IntentTranslator {
  translate(
    recommendation: AttackRecommendation,
    decision: ApprovalDecision
  ): CapabilityRequest;
}

export class LocalIntentTranslator implements IntentTranslator {
  constructor(private registry?: CapabilityRegistry) {}

  translate(
    recommendation: AttackRecommendation,
    decision: ApprovalDecision
  ): CapabilityRequest {
    if (decision.status === 'rejected' || decision.status === 'pending') {
      throw new Error(`Cannot translate intent for recommendation with status: ${decision.status}`);
    }

    if (this.registry) {
      const def = this.registry.getDefinition(recommendation.capability);
      if (!def) {
        throw new CapabilityValidationError(`Unknown capability: ${recommendation.capability}`);
      }
    }

    const baseConfig = decision.configOverrides || {};
    
    const finalConfig = {
      ...baseConfig,
      sourceRecommendationId: recommendation.id
    };

    if (this.registry) {
      try {
        this.registry.validateInput(recommendation.capability, finalConfig);
      } catch (err: any) {
        throw new CapabilityValidationError(`Capability validation failed: ${err.message}`);
      }
    }
    
    return {
      capability: recommendation.capability,
      target: {
        uri: recommendation.targetContext.uri
      },
      config: finalConfig
    };
  }
}
