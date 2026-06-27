import type { TargetProfile } from './TargetProfile';
import type { AttackRecommendation } from './AttackRecommendation';

export interface RecommendationRule {
  readonly id: string;
  readonly description: string;
  applies(profile: TargetProfile): boolean;
  recommend(profile: TargetProfile): AttackRecommendation;
}
