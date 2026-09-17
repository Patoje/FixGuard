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
}

export interface WeakTlsMetadata {
  readonly kind: 'weak_tls_metadata';
  readonly targetHost: string;
  readonly port: number;
  readonly weakProtocols: readonly string[];
  readonly weakCiphers: readonly string[];
  readonly certificateIssues: readonly ('expired' | 'self_signed' | 'invalid_san')[];
  readonly supportedTlsVersions: readonly string[];
  readonly observedAt: string;
  readonly category?: 'SECURITY_MISCONFIGURATION';
  readonly endpointUrl?: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: Record<string, unknown>;
}

export interface DiscoveryFindingMetadata {
  readonly kind: 'discovery_finding_metadata';
  readonly category?: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: Record<string, unknown>;
  readonly endpointUrl?: string;
  readonly targetHost?: string;
  readonly host?: string;
  readonly subdomain?: string;
  readonly url?: string;
  readonly port?: number | string;
  readonly statusCode?: number;
  readonly title?: string;
  readonly webserver?: string;
  readonly technologies?: readonly string[];
  readonly scheme?: string;
  readonly finalUrl?: string;
  readonly source?: string;
  readonly ip?: string;
  readonly observedAt?: string;
  readonly details?: string;
}

export interface AuthBypassMetadata {
  readonly kind: 'auth_bypass_metadata';
  readonly category: 'BROKEN_AUTHENTICATION';
  readonly endpointUrl: string;
  readonly httpMethod: string;
  readonly authenticatedStatusCode: number;
  readonly anonymousStatusCode: number;
  readonly bypassMechanism: 'header_stripping' | 'cookie_omission' | 'verb_tampering';
  readonly bodySimilarityRatio: number;
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface SourcemapExposureMetadata {
  readonly kind: 'sourcemap_exposure_metadata';
  readonly category: 'INFORMATION_DISCLOSURE';
  readonly exposedMapUrl: string;
  readonly sourceJsUrl: string;
  readonly detectionSignal: 'sourcemapping_url_comment' | 'sourcemap_header' | 'deterministic_path_probe';
  readonly mapFileSizeBytes?: number;
  readonly sampleSourcesCount?: number;
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface WordPressSurfaceMetadata {
  readonly kind: 'wordpress_surface_metadata';
  readonly category: 'SECURITY_MISCONFIGURATION' | 'INFORMATION_DISCLOSURE';
  readonly probeKind: 'xmlrpc_capabilities' | 'rest_user_enumeration';
  readonly endpointUrl: string;
  readonly xmlRpcMethodsExposed?: readonly string[];
  readonly multicallSupported?: boolean;
  readonly exposedUsersCount?: number;
  readonly sampleUserSlugs?: readonly string[];
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface SqlErrorOracleMetadata {
  readonly kind: 'sql_error_oracle_metadata';
  readonly category: 'INFORMATION_DISCLOSURE';
  readonly databaseEngine: 'mysql' | 'mssql' | 'postgresql' | 'oracle' | 'sqlite' | 'unknown';
  readonly parameterName: string;
  readonly injectedProbe: string;
  readonly errorFragment: string;
  readonly endpointUrl: string;
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface GraphQLSurfaceMetadata {
  readonly kind: 'graphql_surface_metadata';
  readonly category: 'SECURITY_MISCONFIGURATION' | 'INFORMATION_DISCLOSURE';
  readonly endpointUrl: string;
  readonly introspectionEnabled: boolean;
  readonly batchingEnabled: boolean;
  readonly fieldSuggestionsEnabled: boolean;
  readonly discoveredRootTypes?: readonly string[];
  readonly suggestionLeak?: string;
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface JwtAlgorithmConfusionMetadata {
  readonly kind: 'jwt_algorithm_confusion_metadata';
  readonly category: 'BROKEN_AUTHENTICATION';
  readonly endpointUrl: string;
  readonly httpMethod: string;
  readonly originalAlgorithm: string;
  readonly manipulatedAlgorithm: 'none' | 'None' | 'NONE';
  readonly probeMechanism: 'signature_stripping' | 'alg_none_header';
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface SessionFixationMetadata {
  readonly kind: 'session_fixation_metadata';
  readonly category: 'BROKEN_AUTHENTICATION';
  readonly endpointUrl: string;
  readonly httpMethod: string;
  readonly sessionCookieName: string;
  readonly fixedSessionId: string; // sanitized excerpt/prefix, max 32 chars
  readonly serverRegeneratedSession: boolean;
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface CredentialedCorsMetadata {
  readonly kind: 'credentialed_cors_metadata';
  readonly category: 'SECURITY_MISCONFIGURATION';
  readonly endpointUrl: string;
  readonly httpMethod: string;
  readonly suppliedOrigin: string;
  readonly reflectedOrigin: string;
  readonly allowCredentialsHeader: boolean;
  readonly acaoHeader: string;
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface CmsPluginVulnerabilityMetadata {
  readonly kind: 'cms_plugin_vulnerability_metadata';
  readonly category: 'SECURITY_MISCONFIGURATION';
  readonly cmsType: 'wordpress' | 'joomla' | 'drupal';
  readonly pluginSlug: string;
  readonly detectedVersion: string;
  readonly minimumSafeVersion: string;
  readonly isOutdated: boolean;
  readonly evidenceSourceUrl: string;
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface CompoundChainMetadata {
  readonly kind: 'compound_chain_metadata';
  readonly category: 'BROKEN_ACCESS_CONTROL';
  readonly chainKind: 'cors_idor_compound';
  readonly primaryFindingId: string;   // Credentialed CORS Finding ID
  readonly secondaryFindingId: string; // IDOR Finding ID
  readonly sharedOrigin: string;
  readonly targetEndpointUrl: string;
  readonly compoundImpactScore: number; // 0.85 - 1.0 (Critical)
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export type FindingMetadata =
  | BrokenAccessControlMetadata
  | SecurityMisconfigurationMetadata
  | InputValidationFlawMetadata
  | MissingSecurityHeadersMetadata
  | OpenRedirectMetadata
  | InformationDisclosureMetadata
  | SubdomainTakeoverMetadata
  | WeakTlsMetadata
  | AuthBypassMetadata
  | SourcemapExposureMetadata
  | WordPressSurfaceMetadata
  | SqlErrorOracleMetadata
  | GraphQLSurfaceMetadata
  | JwtAlgorithmConfusionMetadata
  | SessionFixationMetadata
  | CredentialedCorsMetadata
  | CmsPluginVulnerabilityMetadata
  | CompoundChainMetadata
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

