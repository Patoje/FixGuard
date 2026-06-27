import type { TargetProfile } from './TargetProfile';
import type { AttackRecommendation } from './AttackRecommendation';
import type { RecommendationRule } from './RecommendationRule';

export interface RecommendationEngine {
  recommend(profile: TargetProfile): AttackRecommendation[];
}

export class LocalRecommendationEngine implements RecommendationEngine {
  constructor(private rules: RecommendationRule[]) {}

  recommend(profile: TargetProfile): AttackRecommendation[] {
    const recommendations: AttackRecommendation[] = [];

    for (const rule of this.rules) {
      if (rule.applies(profile)) {
        recommendations.push(rule.recommend(profile));
      }
    }

    return recommendations;
  }
}
