export interface TechStackItem {
  name: string;
  category: 'Frontend Framework' | 'Backend Framework' | 'Database' | 'Authentication' | 'Hosting / Infrastructure' | 'External Services' | 'CMS';
  confidence: number;
  evidence: string[];
  role: string;
  version?: string;
}
