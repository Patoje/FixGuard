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

export interface ApiVersioningSprawlMetadata {
  readonly kind: 'api_versioning_sprawl_metadata';
  readonly category: 'BROKEN_AUTHENTICATION' | 'SECURITY_MISCONFIGURATION';
  readonly currentEndpointUrl: string;
  readonly legacyEndpointUrl: string;
  readonly currentStatusCode: number;
  readonly legacyStatusCode: number;
  readonly detectedVersions: readonly string[]; // e.g. ['v1', 'v2']
  readonly unauthenticatedExposure: boolean;
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface HttpMethodManipulationMetadata {
  readonly kind: 'http_method_manipulation_metadata';
  readonly category: 'BROKEN_ACCESS_CONTROL' | 'SECURITY_MISCONFIGURATION';
  readonly endpointUrl: string;
  readonly targetOperation: string;
  readonly baselineMethod: string;
  readonly bypassMethodOrHeader: string;
  readonly baselineStatusCode: number;
  readonly manipulatedStatusCode: number;
  readonly bypassType: 'method_override_header' | 'query_param_override' | 'trace_enabled';
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface DependencyConfusionMetadata {
  readonly kind: 'dependency_confusion_metadata';
  readonly category: 'SUPPLY_CHAIN_RISK';
  readonly packageName: string;
  readonly detectedVersion?: string;
  readonly sourceManifestUrl: string;
  readonly publicRegistryUrl: string;
  readonly registryStatusCode: number;
  readonly isUnclaimedPublicly: boolean;
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface ManifestExposureMetadata {
  readonly kind: 'manifest_exposure_metadata';
  readonly category: 'INFORMATION_DISCLOSURE';
  readonly exposedFilePath: string; // e.g. '/.env', '/.git/config', '/package.json'
  readonly endpointUrl: string;
  readonly fileKind: 'env_file' | 'git_config' | 'package_manifest' | 'dependency_lockfile';
  readonly exposureSeverity: 'critical' | 'high' | 'medium';
  readonly sanitizedSnippet: string; // max 128 chars, all credentials redacted
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface ParameterIntegrityMetadata {
  readonly kind: 'parameter_integrity_metadata';
  readonly category: 'INFORMATION_DISCLOSURE' | 'BROKEN_ACCESS_CONTROL';
  readonly endpointUrl: string;
  readonly parameterName: string;
  readonly injectedProbePattern: string;
  readonly boundaryEnforced: boolean;
  readonly sanitizedExcerpt?: string; // max 128 chars
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface ObjectMappingAnomalyMetadata {
  readonly kind: 'object_mapping_anomaly_metadata';
  readonly category: 'BROKEN_ACCESS_CONTROL';
  readonly endpointUrl: string;
  readonly httpMethod: string;
  readonly injectedProperties: readonly string[]; // e.g. ['isAdmin', 'role']
  readonly bindingAccepted: boolean;
  readonly sanitizedEchoResponse?: string; // max 128 chars
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface StateTransitionAnomalyMetadata {
  readonly kind: 'state_transition_anomaly_metadata';
  readonly category: 'BUSINESS_LOGIC_BYPASS';
  readonly endpointUrl: string;
  readonly expectedPrerequisiteSteps: readonly string[];
  readonly bypassedSuccessfully: boolean;
  readonly responseExcerpt?: string; // max 128 chars
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface AttackSurfaceDeltaMetadata {
  readonly kind: 'attack_surface_delta_metadata';
  readonly category: 'SECURITY_MISCONFIGURATION';
  readonly baselineAssessmentId?: string;
  readonly newEndpointsCount: number;
  readonly removedEndpointsCount: number;
  readonly newlyExposedPaths: readonly string[]; // max 15 paths
  readonly technologyDriftDetected: boolean;
  readonly deltaSeverity: 'high' | 'medium' | 'low';
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface CrossFindingChainMetadata {
  readonly kind: 'cross_finding_chain_metadata';
  readonly category: 'BROKEN_ACCESS_CONTROL' | 'SECURITY_MISCONFIGURATION';
  readonly chainTitle: string;
  readonly constituentFindingIds: readonly string[]; // linking 2+ findings
  readonly primaryVector: string;
  readonly secondaryVector: string;
  readonly compoundImpactScore: number; // 0.90 - 1.0
  readonly observedAt: string;
  readonly candidateId?: string;
  readonly evidenceRecordId?: string;
  readonly lineage?: string | Record<string, unknown>;
}

export interface StaticSecretExposureMetadata {
  readonly kind: 'static_secret_exposure_metadata';
  readonly category: 'INFORMATION_DISCLOSURE';
  readonly filePath: string;
  readonly lineNumber: number;
  readonly secretKind: 'aws_key' | 'private_key' | 'generic_api_key' | 'database_uri' | 'jwt_secret';
  readonly exposureSeverity: 'critical' | 'high';
  readonly sanitizedSnippet: string; // max 128 chars, secret redacted
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
  | ApiVersioningSprawlMetadata
  | HttpMethodManipulationMetadata
  | DependencyConfusionMetadata
  | ManifestExposureMetadata
  | ParameterIntegrityMetadata
  | ObjectMappingAnomalyMetadata
  | StateTransitionAnomalyMetadata
  | AttackSurfaceDeltaMetadata
  | CrossFindingChainMetadata
  | StaticSecretExposureMetadata
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

