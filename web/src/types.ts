export type ScanMode = 'passive' | 'active' | 'aggressive' | 'sast' | 'targeted';

export type ScanStatus = 'pending' | 'in_progress' | 'completed' | 'failed' | 'paused_for_approval';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface Scan {
  id: number;
  targetUrl: string;
  mode: ScanMode;
  status: ScanStatus;
  startedAt: Date | null;
  completedAt: Date | null;
}

export interface Vulnerability {
  id: number;
  scanId: number;
  type: string;
  severity: Severity;
  description: string;
  autoFixCode: string | null;
}

export interface TerminalLog {
  id: string;
  timestamp: string;
  message: string;
  type: 'info' | 'warning' | 'error' | 'success';
}

export interface TechStackItem {
  name: string;
  category: string;
  confidence: number;
  evidence: string[];
  role: string;
}

export interface AttackSurfaceItem {
  path: string;
  method: string;
  riskLevel: 'CRÍTICO' | 'ALTO' | 'MEDIO' | 'BAJO';
  type: string;
}

export interface VectorItem {
  id: string;
  name: string;
  cliCommand: string;
}

export interface FrameworkVector {
  framework: string;
  vectors: VectorItem[];
}

export interface ArchitectureNode {
  name: string;
  children?: ArchitectureNode[];
}

export interface ReconProfile {
  id: number;
  scanId: number;
  techStack: TechStackItem[];
  attackSurface: AttackSurfaceItem[];
  frameworkIntelligence: FrameworkVector[];
  architectureTree: ArchitectureNode;
}
