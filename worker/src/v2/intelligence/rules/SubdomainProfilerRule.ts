import type { CorrelatedFinding } from '../CorrelatedFinding';
import type { TargetProfile } from '../TargetProfile';
import type { ProfilerRule } from '../ProfilerRule';

export class SubdomainProfilerRule implements ProfilerRule {
  readonly id = 'PR-SUBDOMAIN-001';
  readonly description = 'Extracts discovered subdomains into the profile';

  applies(findings: CorrelatedFinding[]): boolean {
    return findings.some(f => f.type === 'subdomain_discovery');
  }

  enrich(profile: TargetProfile, findings: CorrelatedFinding[]): TargetProfile {
    const subdomainFindings = findings.filter(f => f.type === 'subdomain_discovery');
    const newSubdomains = subdomainFindings.map(f => f.target);
    const sourceIds = subdomainFindings.flatMap(f => f.sourceFindingIds);
    
    const uniqueSubdomains = Array.from(new Set([...profile.discoveredSubdomains, ...newSubdomains]));
    const uniqueSourceIds = Array.from(new Set([...profile.sourceFindingIds, ...sourceIds]));

    return {
      ...profile,
      discoveredSubdomains: uniqueSubdomains,
      sourceFindingIds: uniqueSourceIds
    };
  }
}
