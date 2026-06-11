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
  version?: string;
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
  communicationIntelligence?: {
    graphql: {
      enabled: boolean;
      endpoint: string;
      queries: string[];
      mutations: string[];
      types: string[];
    };
    websockets: {
      detected: boolean;
      urls: string[];
      namespaces: string[];
    };
  };
  subdomainIntelligence?: {
    discoveredCount: number;
    interestingSubdomains: Array<{
      subdomain: string;
      type: 'STAGING' | 'DEV' | 'API' | 'ADMIN' | 'INTERNAL' | 'OTHER';
    }>;
    allSubdomains: string[];
  };
  artifactIntelligence?: {
    discoveredRoutes: string[];
    hiddenRoutes: string[];
    manifestType?: string;
  };
  parameterIntelligence?: {
    totalParameters: number;
    topParameters: Array<{ name: string; frequency: number }>;
    allParameters: string[];
  };
  auditReport?: {
    summary: string;
    contexts: Array<{
      name: string;
      description: string;
      confidence: 'HIGH' | 'MEDIUM' | 'LOW';
      evidences: string[];
      inferredTechnologies: string[];
    }>;
  };
}
