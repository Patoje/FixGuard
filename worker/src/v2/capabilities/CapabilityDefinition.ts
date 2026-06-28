export type CapabilityCategory = 'recon' | 'http' | 'dns' | 'tls' | 'web' | 'api' | 'passive';
export type RiskLevel = 'info' | 'low' | 'medium' | 'high';

export interface CapabilityDefinition {
  id: string;
  name: string;
  description: string;
  category: CapabilityCategory;
  riskLevel: RiskLevel;
  requiresApproval: boolean;
  inputSchema: any; // Simplified for M27
  outputKind: string;
  evidenceKind: string;
  allowedTargetKinds: string[];
}
