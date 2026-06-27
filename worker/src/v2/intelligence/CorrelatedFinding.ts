import type { Finding } from '../core/Evidence';

export interface CorrelatedFinding {
  type: string;
  target: string;
  combinedConfidence: number;
  occurrences: number;
  representativeFinding: Finding;
  sourceFindingIds: string[];
}
