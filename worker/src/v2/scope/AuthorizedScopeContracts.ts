/**
 * M46 — Authorized Scope + Permission Policy Boundary (DB-free)
 *
 * Contract version: fixguard-authorized-scope-policy/v0
 *
 * This module defines pure TypeScript contracts for representing and evaluating
 * layered authorization/scope policy decisions.
 *
 * M46 does NOT:
 *   - execute tools
 *   - touch network
 *   - validate domains
 *   - persist scope grants
 *   - create findings, evidence, severity, risk or impact claims
 *   - replace M30 egress policy
 *
 * Future active execution must pass both M46 authorized-scope/permission decision
 * AND M30/M33 egress policy decision.
 */

// ---------------------------------------------------------------------------
// Contract Version
// ---------------------------------------------------------------------------

export type AuthorizedScopePolicyContractVersion = 'fixguard-authorized-scope-policy/v0';

export const AUTHORIZED_SCOPE_POLICY_CONTRACT_VERSION: AuthorizedScopePolicyContractVersion =
  'fixguard-authorized-scope-policy/v0';

// ---------------------------------------------------------------------------
// Classification Flags
// ---------------------------------------------------------------------------

export interface AuthorizedScopePolicyClassificationFlags {
  createsRealFindings: false;
  createsPersistedEvidence: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  executesNetwork: false;
  executesTools: false;
  persistsData: false;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

export interface ValidationResult {
  isValid: boolean;
  errorCode?: string;
  message?: string;
}

// ---------------------------------------------------------------------------
// HTTP Methods
// ---------------------------------------------------------------------------

export const ALLOWED_HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const;
export type HttpMethod = (typeof ALLOWED_HTTP_METHODS)[number];

// ---------------------------------------------------------------------------
// ActionKind
// ---------------------------------------------------------------------------

export const ALLOWED_ACTION_KINDS = [
  'passive_recon',
  'technology_fingerprint',
  'endpoint_discovery',
  'active_crawl',
  'authenticated_probe',
  'light_validation',
  'active_validation',
  'aggressive_validation',
  'oob_validation',
  'destructive_operation'
] as const;
export type ActionKind = (typeof ALLOWED_ACTION_KINDS)[number];

// ---------------------------------------------------------------------------
// Intensity
// ---------------------------------------------------------------------------

export const ALLOWED_INTENSITIES = [
  'passive',
  'low',
  'medium',
  'high',
  'aggressive',
  'destructive'
] as const;
export type Intensity = (typeof ALLOWED_INTENSITIES)[number];

// ---------------------------------------------------------------------------
// RequiredPermission
// ---------------------------------------------------------------------------

export const ALLOWED_REQUIRED_PERMISSIONS = [
  'passiveRecon',
  'technologyFingerprinting',
  'endpointDiscovery',
  'activeCrawling',
  'authenticatedTesting',
  'lightValidation',
  'activeValidation',
  'aggressiveValidation',
  'oobTesting',
  'destructiveOperations'
] as const;
export type RequiredPermission = (typeof ALLOWED_REQUIRED_PERMISSIONS)[number];

// ---------------------------------------------------------------------------
// PathScopePattern
// ---------------------------------------------------------------------------

export const ALLOWED_MATCH_TYPES = ['exact', 'prefix'] as const;
export type MatchType = (typeof ALLOWED_MATCH_TYPES)[number];

export interface PathScopePattern {
  match: MatchType;
  pathTemplate: string;
}

// ---------------------------------------------------------------------------
// Subject
// ---------------------------------------------------------------------------

export const ALLOWED_TARGET_KINDS = ['origin', 'host', 'domain'] as const;
export type TargetKind = (typeof ALLOWED_TARGET_KINDS)[number];

export interface ScopeSubject {
  targetKind: TargetKind;
  normalizedOrigin?: string;
  host?: string;
  domain?: string;
}

// ---------------------------------------------------------------------------
// Authorization Basis
// ---------------------------------------------------------------------------

export const ALLOWED_BASIS_KINDS = [
  'user_attestation',
  'contract_reference',
  'internal_asset_record',
  'external_verification_record'
] as const;
export type BasisKind = (typeof ALLOWED_BASIS_KINDS)[number];

export const ALLOWED_RECORDED_BY = ['human_user', 'system_import'] as const;
export type RecordedBy = (typeof ALLOWED_RECORDED_BY)[number];

export interface AuthorizationBasis {
  basisKind: BasisKind;
  referenceId?: string;
  recordedBy: RecordedBy;
  authorizationText: string;
}

// ---------------------------------------------------------------------------
// Permission Set
// ---------------------------------------------------------------------------

export interface PermissionSet {
  passiveRecon: boolean;
  technologyFingerprinting: boolean;
  endpointDiscovery: boolean;
  activeCrawling: boolean;
  authenticatedTesting: boolean;
  lightValidation: boolean;
  activeValidation: boolean;
  aggressiveValidation: boolean;
  oobTesting: boolean;
  /** Always false — destructive operations are never permitted via M46. */
  destructiveOperations: false;
}

// ---------------------------------------------------------------------------
// Scope Boundaries
// ---------------------------------------------------------------------------

export interface ScopeBoundaries {
  allowedOrigins?: string[];
  allowedHosts?: string[];
  allowedDomains?: string[];
  allowedPathPatterns?: PathScopePattern[];
  deniedPathPatterns?: PathScopePattern[];
  allowedMethods?: HttpMethod[];
  deniedMethods?: HttpMethod[];
}

// ---------------------------------------------------------------------------
// Scope Constraints
// ---------------------------------------------------------------------------

export interface ScopeConstraints {
  maxRequestsPerMinute?: number;
  maxDepth?: number;
  maxRuntimeSeconds?: number;
  allowLoginRequiredAreas: boolean;
  allowStateChangingRequests: boolean;
  allowCredentialUse: boolean;
  allowOobCallbacks: boolean;
  /** Always false — third-party targets are never permitted. */
  allowThirdPartyTargets: false;
  notes?: string;
}

// ---------------------------------------------------------------------------
// AuthorizedScopeGrant
// ---------------------------------------------------------------------------

export interface AuthorizedScopeGrant {
  contractVersion: AuthorizedScopePolicyContractVersion;
  kind: 'authorized_scope_grant';
  grantId: string;
  scanId: string;
  issuedAt: string;
  expiresAt: string;
  subject: ScopeSubject;
  authorizationBasis: AuthorizationBasis;
  permissionSet: PermissionSet;
  boundaries: ScopeBoundaries;
  constraints: ScopeConstraints;
  classification: AuthorizedScopePolicyClassificationFlags;
}

// ---------------------------------------------------------------------------
// ScopeActionRequest
// ---------------------------------------------------------------------------

export interface ScopeActionRequest {
  contractVersion: AuthorizedScopePolicyContractVersion;
  kind: 'scope_action_request';
  requestId: string;
  scanId: string;
  requestedAt: string;
  actionKind: ActionKind;
  target: ScopeSubject;
  method?: HttpMethod;
  pathTemplate?: string;
  /**
   * UNTRUSTED: Caller hint only. The service always derives the required
   * permission from actionKind/intensity and rejects any mismatch.
   */
  requiredPermission?: RequiredPermission;
  intensity: Intensity;
  usesCredentials: boolean;
  mayChangeServerState: boolean;
  usesOob: boolean;
  classification: AuthorizedScopePolicyClassificationFlags;
}

// ---------------------------------------------------------------------------
// Policy Decision
// ---------------------------------------------------------------------------

export const ALLOWED_DECISION_VALUES = ['allowed', 'denied'] as const;
export type DecisionValue = (typeof ALLOWED_DECISION_VALUES)[number];

export const ALLOWED_REASON_CODES = [
  'allowed_by_scope_policy',
  'denied_invalid_grant',
  'denied_invalid_request',
  'grant_not_yet_valid',
  'denied_expired_grant',
  'denied_scan_mismatch',
  'denied_target_out_of_scope',
  'denied_path_out_of_scope',
  'denied_path_explicitly_denied',
  'denied_method_not_allowed',
  'denied_method_explicitly_denied',
  'denied_missing_permission',
  'denied_requires_authenticated_testing',
  'denied_requires_oob_permission',
  'denied_state_change_not_allowed',
  'denied_third_party_target',
  'denied_destructive_operation',
  'denied_unsafe_content',
  'unexpected_scope_policy_failure'
] as const;
export type ReasonCode = (typeof ALLOWED_REASON_CODES)[number];

export const ALLOWED_BOUNDARY_KINDS = [
  'subject',
  'allowed_origin',
  'allowed_host',
  'allowed_domain',
  'allowed_path',
  'allowed_method'
] as const;
export type BoundaryKind = (typeof ALLOWED_BOUNDARY_KINDS)[number];

export interface MatchedBoundary {
  boundaryKind: BoundaryKind;
  matchType?: MatchType;
}

export interface ScopePolicyDecision {
  contractVersion: AuthorizedScopePolicyContractVersion;
  kind: 'scope_policy_decision';
  decisionId: string;
  requestId: string;
  grantId: string;
  scanId: string;
  evaluatedAt: string;
  decision: DecisionValue;
  reasonCode: ReasonCode;
  reason: string;
  matchedPermission: RequiredPermission | null;
  matchedBoundary?: MatchedBoundary;
  classification: AuthorizedScopePolicyClassificationFlags;
}
