export interface Finding {
  id: string;
  type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  target: string;
  evidence: string;
  confidence: number;
  metadata: Record<string, unknown>;
}

export interface EvidenceCollection {
  findings: Finding[];
  metadata: Record<string, unknown>;
}
