export interface TechnologySignal {
  name: string;
  version?: string;
  confidence: number;
}

export interface TargetProfile {
  targetUri: string;
  technologies: TechnologySignal[];
  discoveredSubdomains: string[];
  exposedCapabilities: string[];
  sourceFindingIds: string[];
  metadata: {
    version: number;
    lastUpdated: number;
    [key: string]: unknown;
  };
}
