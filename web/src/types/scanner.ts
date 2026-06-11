export type ScanState = 'idle' | 'scanning' | 'completed' | 'failed';

export interface Vulnerability {
  id: string | number;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  autoFixCode?: string | null;
}

export interface ScanResult {
  scanId: number;
  targetUrl: string;
  status: ScanState;
  vulnerabilities: Vulnerability[];
}
