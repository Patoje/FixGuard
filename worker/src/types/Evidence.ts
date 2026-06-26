/**
 * Evidence - Accumulated proof from multiple tools for confidence calculation
 * Supports cross-tool validation and correlation
 */

export interface Evidence {
  evidenceId: string;
  findingId: string;
  sourceTool: string;
  type: EvidenceType;
  data: any; // structured evidence data
  quality: number; // 0-1 confidence in evidence quality
  timestamp: Date;
  metadata: Record<string, any>;
}

export type EvidenceType = 
  | 'direct_confirmation'
  | 'indirect_indication'
  | 'corroborating_data'
  | 'contradicting_evidence'
  | 'contextual_support'
  | 'exploit_verification'
  | 'false_positive_indicator';

export interface EvidenceCollection {
  findings: Finding[];
  evidenceItems: Evidence[];
  correlations: CorrelationResult[];
  confidenceFactors: ConfidenceFactor[];
  metadata: Record<string, any>;
}

export interface CorrelationResult {
  correlationId: string;
  primaryFindingId: string;
  supportingFindings: string[]; // IDs of supporting findings
  correlationType: CorrelationType;
  strength: number; // 0-1 correlation strength
  explanation: string;
  timestamp: Date;
  metadata: Record<string, any>;
}

export type CorrelationType =
  | 'same_vulnerability_different_tools'
  | 'different_vectors_same_issue'
  | 'exploit_verification'
  | 'contextual_confirmation'
  | 'temporal_correlation'
  | 'network_context';

export interface ConfidenceFactor {
  factorId: string;
  type: ConfidenceFactorType;
  value: number; // 0-1 contribution to confidence
  weight: number; // relative importance
  source: string; // what generated this factor
  explanation: string;
  timestamp: Date;
  metadata: Record<string, any>;
}

export type ConfidenceFactorType =
  | 'evidence_quality'
  | 'tool_reliability'
  | 'reproducibility'
  | 'exploitability'
  | 'context_consistency'
  | 'cross_tool_confirmation'
  | 'temporal_stability'
  | 'environmental_factors';

// Supporting types
export interface Finding {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  evidence: string;
  target: string;
  timestamp: Date;
  metadata: Record<string, any>;
}

// Evidence collection utilities
export class EvidenceCollector {
  private evidenceItems: Evidence[] = [];
  private correlations: CorrelationResult[] = [];
  private findings: Finding[] = [];
  
  addEvidence(evidence: Evidence): void {
    this.evidenceItems.push(evidence);
  }
  
  addFinding(finding: Finding): void {
    this.findings.push(finding);
  }
  
  addCorrelation(correlation: CorrelationResult): void {
    this.correlations.push(correlation);
  }
  
  getEvidenceByFinding(findingId: string): Evidence[] {
    return this.evidenceItems.filter(e => e.findingId === findingId);
  }
  
  getCorrelationsByFinding(findingId: string): CorrelationResult[] {
    return this.correlations.filter(c => 
      c.primaryFindingId === findingId || 
      c.supportingFindings.includes(findingId)
    );
  }
  
  buildCollection(): EvidenceCollection {
    return {
      findings: [...this.findings],
      evidenceItems: [...this.evidenceItems],
      correlations: [...this.correlations],
      confidenceFactors: this.calculateConfidenceFactors(),
      metadata: {}
    };
  }
  
  private calculateConfidenceFactors(): ConfidenceFactor[] {
    const factors: ConfidenceFactor[] = [];
    
    // Calculate evidence quality factors
    for (const finding of this.findings) {
      const evidenceForFinding = this.getEvidenceByFinding(finding.id);
      
      // Factor: Number of evidence items for this finding
      factors.push({
        factorId: `evidence_count_${finding.id}`,
        type: 'evidence_quality',
        value: Math.min(evidenceForFinding.length / 5, 1), // Cap at 1
        weight: 0.3,
        source: 'evidence_collector',
        explanation: `${evidenceForFinding.length} pieces of evidence found`,
        timestamp: new Date(),
        metadata: { findingId: finding.id }
      });
      
      // Factor: Average evidence quality
      const avgQuality = evidenceForFinding.reduce((sum, e) => sum + e.quality, 0) / 
                        Math.max(evidenceForFinding.length, 1);
      
      factors.push({
        factorId: `avg_quality_${finding.id}`,
        type: 'evidence_quality',
        value: avgQuality,
        weight: 0.4,
        source: 'evidence_collector',
        explanation: `Average evidence quality: ${avgQuality.toFixed(2)}`,
        timestamp: new Date(),
        metadata: { findingId: finding.id }
      });
    }
    
    // Calculate correlation factors
    for (const correlation of this.correlations) {
      factors.push({
        factorId: `correlation_strength_${correlation.correlationId}`,
        type: 'cross_tool_confirmation',
        value: correlation.strength,
        weight: 0.5,
        source: 'correlation_engine',
        explanation: `Correlation strength: ${correlation.strength.toFixed(2)}`,
        timestamp: new Date(),
        metadata: { 
          correlationId: correlation.correlationId,
          primaryFindingId: correlation.primaryFindingId
        }
      });
    }
    
    return factors;
  }
}

// Confidence calculation utilities
export interface ConfidenceCalculationParams {
  baseConfidence: number;
  factors: ConfidenceFactor[];
  correlationWeight: number;
  toolReliabilityWeight: number;
  reproducibilityWeight: number;
  metadata: Record<string, any>;
}

export function calculateConfidence(params: ConfidenceCalculationParams): number {
  // Start with base confidence
  let confidence = params.baseConfidence;
  
  // Apply weighted factors
  for (const factor of params.factors) {
    confidence += factor.value * factor.weight;
  }
  
  // Ensure confidence stays within bounds
  return Math.max(0, Math.min(1, confidence));
}

export interface ConfidenceResult {
  correlationId: string;
  confidenceScore: number; // 0.0-1.0
  factors: ConfidenceFactor[];
  justification: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  timestamp: Date;
}

export function determineRiskLevel(confidenceScore: number): 'low' | 'medium' | 'high' | 'critical' {
  if (confidenceScore >= 0.8) return 'critical';
  if (confidenceScore >= 0.6) return 'high';
  if (confidenceScore >= 0.4) return 'medium';
  return 'low';
}