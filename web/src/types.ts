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
  parentId?: number | null;
  metadata?: {
    discovered_urls?: string[];
    vulnerable_parameters?: string[];
  };
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
  params?: string[];
  headers?: string[];
  authType?: string;
  framework?: string;
  relationships?: string[];
  aiExplanation?: string;
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
  businessDictionary?: {
    roles: string[];
    entities: string[];
    permissions: string[];
    configFlags: string[];
  };
  authIntelligence?: {
    mechanisms: string[];
    sessionStorage: boolean;
    localStorage: boolean;
    cookieNames: string[];
  };
  cloudIntelligence?: {
    provider: string;
    services: string[];
    buckets: string[];
    misconfigurations: string[];
  };
}
