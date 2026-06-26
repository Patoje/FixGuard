/**
 * ScannerResult - Structure for holding results from security scanners
 */

export interface Finding {
  id: string;
  type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  evidence: string;
  confidence: number; // 0.0 - 1.0
  cvssScore?: number;
  cveIds?: string[];
  references: string[];
  affectedAssets: string[];
  timestamp: Date;
  metadata: Record<string, any>;
}

export interface ScannerResult {
  scanId: string;
  scannerName: string;
  target: string;
  startTime: Date;
  endTime: Date;
  durationMs: number;
  status: 'success' | 'failed' | 'partial' | 'timeout';
  findings: Finding[];
  rawOutput: string;
  metadata: Record<string, any>;
}

/**
 * Base class for scanner result parsers
 */
export abstract class ResultParser<T = any> {
  abstract parse(rawOutput: string): ScannerResult;
  abstract getFindings(rawOutput: string): Finding[];
  
  /**
   * Creates a standard finding object
   */
  protected createFinding(partial: Partial<Finding>): Finding {
    return {
      id: partial.id || `finding_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type: partial.type || 'generic',
      severity: partial.severity || 'info',
      title: partial.title || 'Untitled Finding',
      description: partial.description || '',
      evidence: partial.evidence || '',
      confidence: partial.confidence || 0,
      references: partial.references || [],
      affectedAssets: partial.affectedAssets || [],
      timestamp: partial.timestamp || new Date(),
      metadata: partial.metadata || {}
    };
  }
}