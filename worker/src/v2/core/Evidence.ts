export interface BrokenAccessControlMetadata {
  readonly kind: 'broken_access_control_metadata';
  readonly category: 'BROKEN_ACCESS_CONTROL';
  readonly candidateId: string;
  readonly evidenceRecordId: string;
  readonly lineage: Record<string, unknown>;
  readonly endpointUrl?: string;
  readonly resourceParamName?: string;
  readonly baselineResourceId?: string;
  readonly unauthorizedActorId?: string;
}

export interface SecurityMisconfigurationMetadata {
  readonly kind: 'security_misconfiguration_metadata';
  readonly category: 'CORS_MISCONFIGURATION' | 'SECURITY_MISCONFIGURATION';
  readonly candidateId: string;
  readonly evidenceRecordId: string;
  readonly lineage: Record<string, unknown>;
  readonly endpointUrl?: string;
  readonly reflectedOrigin?: string;
  readonly allowCredentials?: boolean;
}

export interface InputValidationFlawMetadata {
  readonly kind: 'input_validation_flaw_metadata';
  readonly category: 'INPUT_VALIDATION_FLAW' | 'PARAMETER_REFLECTION';
  readonly candidateId: string;
  readonly evidenceRecordId: string;
  readonly lineage: Record<string, unknown>;
  readonly endpointUrl?: string;
  readonly parameterName?: string;
  readonly reflectedCanary?: string;
}

export interface MissingSecurityHeadersMetadata {
  readonly kind: 'missing_security_headers_metadata';
  readonly category?: 'SECURITY_MISCONFIGURATION';
  readonly missingHeaders: readonly string[];
  readonly presentHeaders: readonly string[];
  readonly observedAt: string;
  readonly endpointUrl?: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: Record<string, unknown>;
  readonly [key: string]: unknown;
}

export interface OpenRedirectMetadata {
  readonly kind: 'open_redirect_metadata';
  readonly parameterName: string;
  readonly injectedCanary: string;
  readonly finalDestination: string;
  readonly redirectChain: readonly string[];
  readonly observedAt: string;
  readonly category?: 'INPUT_VALIDATION_FLAW' | 'SECURITY_MISCONFIGURATION';
  readonly endpointUrl?: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: Record<string, unknown>;
  readonly [key: string]: unknown;
}

export interface InformationDisclosureMetadata {
  readonly kind: 'information_disclosure_metadata';
  readonly disclosureKind: 'stack_trace' | 'framework_version' | 'server_banner' | 'internal_path';
  readonly disclosedFragment: string; // sanitized excerpt
  readonly trigger: string; // the request/anomaly that produced the response
  readonly observedAt: string;
  readonly category?: 'SECURITY_MISCONFIGURATION';
  readonly endpointUrl?: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: Record<string, unknown>;
  readonly [key: string]: unknown;
}

export interface SubdomainTakeoverMetadata {
  readonly kind: 'subdomain_takeover_metadata';
  readonly subdomain: string;
  readonly cnameTarget: string;
  readonly hostingProvider: 'github_pages' | 'heroku' | 'aws_s3' | 'azure' | 'fastly' | 'netlify' | 'shopify' | 'unknown';
  readonly fingerprintMatch: string;
  readonly observedAt: string;
  readonly category?: 'DNS_HIJACKING_RISK' | 'SECURITY_MISCONFIGURATION';
  readonly endpointUrl?: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: Record<string, unknown>;
  readonly [key: string]: unknown;
}

export interface DiscoveryFindingMetadata {
  readonly kind: 'discovery_finding_metadata';
  readonly category?: string;
  readonly [key: string]: unknown;
}

export type FindingMetadata =
  | BrokenAccessControlMetadata
  | SecurityMisconfigurationMetadata
  | InputValidationFlawMetadata
  | MissingSecurityHeadersMetadata
  | OpenRedirectMetadata
  | InformationDisclosureMetadata
  | SubdomainTakeoverMetadata
  | DiscoveryFindingMetadata;



export interface Finding {
  id: string;
  type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  target: string;
  evidence: string;
  confidence: number;
  metadata: FindingMetadata;
}

export interface EvidenceCollection {
  findings: Finding[];
  metadata: Record<string, unknown>;
}

