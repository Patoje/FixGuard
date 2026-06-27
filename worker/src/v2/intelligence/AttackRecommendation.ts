export interface AttackRecommendation {
  id: string;
  capability: string;
  targetContext: { uri: string };
  rationale: string;
  confidence: number;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  sourceFindingIds: string[];
}
