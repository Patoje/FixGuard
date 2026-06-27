import type { Finding } from '../core/Evidence';
import type { CorrelatedFinding } from './CorrelatedFinding';

export interface CorrelationEngine {
  correlate(findings: Finding[]): CorrelatedFinding[];
}

export class LocalCorrelationEngine implements CorrelationEngine {
  constructor(
    private keyGenerator: (finding: Finding) => string = (f) => `${f.type}:${f.target}`
  ) {}

  correlate(findings: Finding[]): CorrelatedFinding[] {
    const groups = new Map<string, Finding[]>();

    for (const finding of findings) {
      const key = this.keyGenerator(finding);
      const group = groups.get(key) || [];
      group.push(finding);
      groups.set(key, group);
    }

    const correlated: CorrelatedFinding[] = [];

    for (const group of groups.values()) {
      if (group.length === 0) continue;

      let combinedConfidence = 1;
      let highestConfidenceFinding = group[0] as Finding;
      const sourceFindingIds: string[] = [];

      for (const f of group) {
        sourceFindingIds.push(f.id);
        combinedConfidence *= (1 - f.confidence);
        if (f.confidence > highestConfidenceFinding.confidence) {
          highestConfidenceFinding = f;
        }
      }

      combinedConfidence = 1 - combinedConfidence;

      correlated.push({
        type: highestConfidenceFinding.type,
        target: highestConfidenceFinding.target,
        combinedConfidence,
        occurrences: group.length,
        representativeFinding: highestConfidenceFinding,
        sourceFindingIds
      });
    }

    return correlated;
  }
}
