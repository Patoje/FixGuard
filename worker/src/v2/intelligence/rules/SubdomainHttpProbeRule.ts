import type { TargetProfile } from '../TargetProfile';
import type { AttackRecommendation } from '../AttackRecommendation';
import type { RecommendationRule } from '../RecommendationRule';

export class SubdomainHttpProbeRule implements RecommendationRule {
  readonly id = 'RR-HTTP-PROBE-001';
  readonly description = 'Recommends HTTP probing on discovered subdomains';

  applies(profile: TargetProfile): boolean {
    return profile.discoveredSubdomains.length > 0;
  }

  recommend(profile: TargetProfile): AttackRecommendation {
    return {
      id: `rec_http_probe_${Date.now()}`,
      capability: 'http_probe',
      targetContext: { uri: profile.targetUri },
      rationale: `Discovered ${profile.discoveredSubdomains.length} subdomains. Recommend probing for live HTTP services.`,
      confidence: 1.0, // High confidence recommendation
      severity: 'info',
      sourceFindingIds: profile.sourceFindingIds
    };
  }
}
