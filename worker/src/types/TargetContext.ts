/**
 * TargetContext - Persistent, evolving understanding of the target
 * Maintains target state across scan phases
 */

export interface TargetContext {
  readonly targetId: string;
  readonly targetUrl: string;
  readonly technologies: TechnologyProfile[];
  readonly endpoints: Endpoint[];
  readonly discoveredSubdomains: Subdomain[];
  readonly previousFindings: readonly Finding[];
  readonly executionHistory: readonly ExecutionRecord[];
  readonly attackSurface: AttackSurfaceModel;
  readonly constraints: ExecutionConstraints;
  readonly metadata: Record<string, any>;
}

export interface TargetKnowledge {
  getCapabilities(): string[];
  getVulnerabilityLikelihood(): VulnerabilityLikelihood;
  getExecutionConstraints(): ExecutionConstraints;
  getRelevantAssessments(): string[];
}

// Supporting types
export interface TechnologyProfile {
  name: string;
  version?: string;
  confidence: number;
  detectionMethod: string;
  metadata: Record<string, any>;
}

export interface Endpoint {
  url: string;
  method: string;
  parameters: Parameter[];
  headers: Record<string, string>;
  metadata: Record<string, any>;
}

export interface Parameter {
  name: string;
  type: 'path' | 'query' | 'body' | 'header';
  required: boolean;
  dataType: string;
  metadata: Record<string, any>;
}

export interface Subdomain {
  name: string;
  ip?: string;
  ports?: number[];
  metadata: Record<string, any>;
}

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

export interface ExecutionRecord {
  toolId: string;
  startTime: Date;
  endTime: Date;
  status: 'success' | 'failed' | 'partial';
  findingsCount: number;
  metadata: Record<string, any>;
}

export interface AttackSurfaceModel {
  endpoints: string[];
  technologies: string[];
  authentication: string[];
  attackVectors: AttackVector[];
  metadata: Record<string, any>;
}

export interface AttackVector {
  type: string;
  description: string;
  accessibility: 'public' | 'authenticated' | 'internal';
  riskLevel: 'low' | 'medium' | 'high';
  metadata: Record<string, any>;
}

export interface ExecutionConstraints {
  maxConcurrent: number;
  timeout: number;
  rateLimit: RateLimitConfig;
  bandwidthLimit?: string;
  metadata: Record<string, any>;
}

export interface RateLimitConfig {
  requestsPerSecond: number;
  burstSize: number;
  penaltySeconds: number;
  metadata: Record<string, any>;
}

export interface VulnerabilityLikelihood {
  sqlInjection: number; // 0.0 - 1.0
  xss: number;
  sqli: number;
  commandInjection: number;
  pathTraversal: number;
  other: number;
  metadata: Record<string, any>;
}