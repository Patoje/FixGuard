import type { CorrelatedFinding } from './CorrelatedFinding';
import type { TargetProfile } from './TargetProfile';

export interface ProfilerRule {
  readonly id: string;
  readonly description: string;
  applies(findings: CorrelatedFinding[]): boolean;
  enrich(profile: TargetProfile, findings: CorrelatedFinding[]): TargetProfile;
}
