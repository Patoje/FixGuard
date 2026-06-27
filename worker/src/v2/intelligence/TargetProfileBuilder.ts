import type { CorrelatedFinding } from './CorrelatedFinding';
import type { TargetProfile } from './TargetProfile';
import type { ProfilerRule } from './ProfilerRule';

export interface TargetProfileBuilder {
  build(correlated: CorrelatedFinding[], targetUri: string): TargetProfile;
}

export class LocalTargetProfileBuilder implements TargetProfileBuilder {
  constructor(private rules: ProfilerRule[]) {}

  build(correlated: CorrelatedFinding[], targetUri: string): TargetProfile {
    let profile: TargetProfile = {
      targetUri,
      technologies: [],
      discoveredSubdomains: [],
      exposedCapabilities: [],
      sourceFindingIds: [],
      metadata: {
        version: 1,
        lastUpdated: Date.now()
      }
    };

    for (const rule of this.rules) {
      if (rule.applies(correlated)) {
        profile = rule.enrich(profile, correlated);
        
        // Bump version automatically after a successful rule enrichment
        profile = {
          ...profile,
          metadata: {
            ...profile.metadata,
            version: (profile.metadata.version as number) + 1,
            lastUpdated: Date.now()
          }
        };
      }
    }

    return profile;
  }
}
