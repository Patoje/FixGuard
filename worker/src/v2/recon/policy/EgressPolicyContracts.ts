export interface AuthorizedScope {
  allowedOrigins: string[];
  allowSameHostPaths: boolean;
  allowSubdomains: boolean; // Currently false by default or strictly controlled
}

export interface NormalizedTargetUrl {
  originalUrl: string;
  normalizedUrl: string;
  scheme: string;
  hostname: string;
  port: string;
  pathname: string;
  search: string;
  isIpv4: boolean;
  isIpv6: boolean;
}

export type EgressPolicyBlockReason = 
  | 'unsupported_scheme'
  | 'malformed_url'
  | 'credentials_in_url'
  | 'empty_host'
  | 'internal_target_blocked'
  | 'out_of_scope'
  | 'url_too_long';

export interface DiscoveredScopeCandidate {
  candidateUrl: string;
  discoveredFromOrigin: string;
  capabilityId: string;
}

export type EgressPolicyDecision =
  | { 
      decision: 'allow'; 
      normalizedTarget: NormalizedTargetUrl; 
      reasons: string[]; 
      sensitiveQueryKeys?: string[];
      safeDisplayUrl: string;
    }
  | { 
      decision: 'block'; 
      normalizedTarget?: NormalizedTargetUrl; 
      blockReason: EgressPolicyBlockReason; 
      safeDisplayUrl?: string;
    }
  | { 
      decision: 'candidate'; 
      candidate: DiscoveredScopeCandidate; 
      reason: string; 
      safeDisplayUrl: string;
    };
