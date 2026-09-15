/**
 * FixGuard V2 — Capability Status Contracts (Milestone P0-3)
 * Contract Version: fixguard-capability-status/v0
 *
 * Defines domain contracts, types, allowlists, and response envelopes for host
 * binary availability verification.
 */

export const CAPABILITY_STATUS_CONTRACT_VERSION =
  'fixguard-capability-status/v0' as const;

export const RECON_TOOL_ALLOWLIST = [
  'subfinder',
  'naabu',
  'httpx',
  'dnsx',
  'tlsx',
  'ffuf',
  'gau',
  'arjun',
  'trufflehog',
] as const;

export type ReconToolName = (typeof RECON_TOOL_ALLOWLIST)[number];

const RECON_TOOL_SET = new Set<string>(RECON_TOOL_ALLOWLIST);

/**
 * Validates whether a tool name belongs strictly to the recognized recon tool allowlist.
 */
export function isAllowedReconTool(tool: string): tool is ReconToolName {
  return typeof tool === 'string' && RECON_TOOL_SET.has(tool);
}

export type ToolAvailabilityStatus = 'available' | 'missing' | 'wrong_version';

export interface SingleToolStatus {
  readonly tool: ReconToolName;
  readonly status: ToolAvailabilityStatus;
  readonly path?: string;
  readonly version?: string;
  readonly error?: string;
  readonly probedAt: string;
}

export type ToolCapabilityMatrix = {
  readonly [K in ReconToolName]: SingleToolStatus;
};

export interface CapabilityStatusSummary {
  readonly total: number;
  readonly availableCount: number;
  readonly missingCount: number;
  readonly wrongVersionCount: number;
  readonly allAvailable: boolean;
}

export interface CapabilityStatusResponse {
  readonly contractVersion: typeof CAPABILITY_STATUS_CONTRACT_VERSION;
  readonly tools: ToolCapabilityMatrix;
  readonly summary: CapabilityStatusSummary;
  readonly generatedAt: string;
}

export const STAGE_REQUIRED_TOOLS: Record<string, readonly ReconToolName[]> = {
  stage_1_domain_zone: ['subfinder', 'dnsx'],
  stage_2_port_service: ['naabu'],
  stage_3_web_tls: ['httpx', 'tlsx'],
  stage_4_crawling_parameters: ['gau', 'ffuf', 'arjun'],
  stage_5_secret_inspection: ['trufflehog'],
};
