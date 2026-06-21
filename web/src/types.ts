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
  businessImpactScore?: number;
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

export interface WorkflowStep {
  name: string;
  endpoint: string;
  method: string;
  description: string;
}

export interface WorkflowJourney {
  name: string;
  category: string;
  steps: WorkflowStep[];
  confidence: number;
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
    exposedSecrets?: Array<{
      type: string;
      value: string;
      url?: string;
      source?: string;
      isLikelyFalsePositive?: boolean;
      falsePositiveReason?: string;
    }>;
  };
  parameterIntelligence?: {
    totalParameters: number;
    topParameters: Array<{ name: string; frequency: number }>;
    allParameters: string[];
  };
  serverActionsIntelligence?: {
    extractedActionsCount: number;
    actions: Array<{
      id: string;
      context?: string;
    }>;
  };
  aiIntelligence?: {
    detected: boolean;
    providers: string[];
    frameworks: string[];
    features: string[];
  };
  entityGraph?: {
    nodes: Array<{id: string, label: string, type: string}>;
    edges: Array<{id: string, source: string, target: string, label: string}>;
  };
  workflowIntelligence?: WorkflowJourney[];
  runtimeIntelligence?: {
    totalClicks: number;
    totalFormsFilled: number;
    totalScrolls: number;
    requestsIntercepted: number;
    endpointsDiscovered: number;
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
  smartVectors?: Array<{
    id?: string;
    targetUrl: string;
    endpoint?: string;
    method: string;
    attackType: string;
    description: string;
    severity: string;
    cliCommand?: string;
  }>;
  normalizedData?: {
    scanId: number;
    target: string;
    stack: {
      frontend: string | null;
      runtime: string | null;
      waf: string | null;
      cdn: string | null;
      confidence: number;
      database_hints?: string[];
      pipeline?: 'modern_spa' | 'legacy';
    };
    endpoints: {
      url: string;
      source: string;
      lastSeen: string;
    }[];
    subdomains: {
      domain: string;
      source: string;
      takeover_candidate: boolean;
    }[];
    credentials: {
      email: string;
      type: string;
      breach_count: number;
      has_plaintext: boolean;
      high_risk?: boolean;
      breach_names?: string[];
    }[];
    vulnerabilities_hints: {
      type: string;
      detail: string;
      cve?: string;
    }[];
  };
}
