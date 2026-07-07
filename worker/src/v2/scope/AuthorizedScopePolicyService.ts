/**
 * M46 — Authorized Scope Policy Service (DB-free)
 *
 * Pure functions with no network, no tools, no DB, no side effects.
 *
 * Decision precedence (deterministic):
 *  1. invalid grant
 *  2. invalid request
 *  3. destructive operation / destructive intensity
 *  4. expired grant
 *  5. scan mismatch
 *  6. target out of scope / third-party explicit
 *  7. denied path
 *  8. allowed path mismatch
 *  9. denied method
 * 10. allowed method mismatch
 * 11. credentials/auth requirements
 * 12. OOB requirements
 * 13. state-changing restrictions
 * 14. missing derived permission
 * 15. allowed
 */

import type {
  AuthorizedScopeGrant,
  ScopeActionRequest,
  ScopePolicyDecision,
  ValidationResult,
  AuthorizedScopePolicyClassificationFlags,
  RequiredPermission,
  PathScopePattern,
  ScopeSubject,
  ActionKind,
  Intensity,
  MatchedBoundary
} from './AuthorizedScopeContracts.js';

import {
  AUTHORIZED_SCOPE_POLICY_CONTRACT_VERSION,
  ALLOWED_HTTP_METHODS,
  ALLOWED_ACTION_KINDS,
  ALLOWED_INTENSITIES,
  ALLOWED_REQUIRED_PERMISSIONS,
  ALLOWED_MATCH_TYPES,
  ALLOWED_TARGET_KINDS,
  ALLOWED_BASIS_KINDS,
  ALLOWED_RECORDED_BY,
  ALLOWED_BOUNDARY_KINDS
} from './AuthorizedScopeContracts.js';

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

export function getSafeClassification(): AuthorizedScopePolicyClassificationFlags {
  return {
    createsRealFindings: false,
    createsPersistedEvidence: false,
    confirmsVulnerabilities: false,
    makesRiskClaims: false,
    makesSeverityClaims: false,
    makesImpactClaims: false,
    executesNetwork: false,
    executesTools: false,
    persistsData: false
  };
}

// ---------------------------------------------------------------------------
// Generic validators
// ---------------------------------------------------------------------------

const CLASSIFICATION_KEYS = [
  'createsRealFindings', 'createsPersistedEvidence', 'confirmsVulnerabilities',
  'makesRiskClaims', 'makesSeverityClaims', 'makesImpactClaims',
  'executesNetwork', 'executesTools', 'persistsData'
] as const;

function validateAllowedKeys(value: any, allowed: readonly string[]): ValidationResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Value must be a plain object' };
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      return { isValid: false, errorCode: 'unsafe_content_rejected', message: `Unknown/forbidden field rejected: ${key}` };
    }
  }
  return { isValid: true };
}

function forbiddenContentScan(str: string): boolean {
  if (!str) return false;
  const lower = str.toLowerCase();
  const forbidden = [
    'authorization', 'authorization:', 'bearer', 'bearer ',
    'cookie', 'cookie:', 'set-cookie', 'password', 'secret', 'token',
    'api_key', 'apikey', 'access_token', 'refresh_token',
    'raw_request', 'raw request', 'raw_response', 'raw response',
    'raw_body', 'raw body', 'raw_headers', 'raw headers',
    'raw payload', 'raw command', 'raw output', 'raw tool output',
    'stack trace', 'error:',
    'confirmed vulnerability', 'critical severity'
  ];
  return forbidden.some(f => lower.includes(f));
}

function validateSafeId(id: any): ValidationResult {
  if (!id || typeof id !== 'string' || id.length === 0) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'ID is missing or empty' };
  if (id.length > 128) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'ID exceeds max length 128' };
  if (!/^[a-zA-Z0-9_\-.:]+$/.test(id)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'ID contains invalid characters' };
  if (forbiddenContentScan(id)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'ID contains forbidden content' };
  return { isValid: true };
}

function validateIsoTimestamp(ts: any): ValidationResult {
  if (!ts || typeof ts !== 'string') return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Timestamp missing' };
  if (isNaN(Date.parse(ts))) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid ISO timestamp' };
  return { isValid: true };
}

function validateSafeText(text: any, maxLength: number): ValidationResult {
  if (text === undefined || typeof text !== 'string') return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Text missing or invalid type' };
  if (text.length > maxLength) return { isValid: false, errorCode: 'unsafe_content_rejected', message: `Text exceeds max length ${maxLength}` };
  if (forbiddenContentScan(text)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Text contains forbidden content' };
  return { isValid: true };
}

function validateClassification(cls: any): ValidationResult {
  const keysVal = validateAllowedKeys(cls, CLASSIFICATION_KEYS);
  if (!keysVal.isValid) return keysVal;
  for (const key of CLASSIFICATION_KEYS) {
    if ((cls as any)[key] !== false) return { isValid: false, errorCode: 'unsafe_content_rejected', message: `Classification flag ${key} must be false` };
  }
  return { isValid: true };
}

// ---------------------------------------------------------------------------
// Normalized origin validator (scheme + host + optional port, no path/query/fragment/creds)
// ---------------------------------------------------------------------------

function validateNormalizedOrigin(origin: any): ValidationResult {
  if (!origin || typeof origin !== 'string') return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin missing' };
  if (origin.length > 253) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin too long' };
  let url: URL;
  try { url = new URL(origin); } catch { return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin is not a valid URL' }; }
  if (!['http:', 'https:'].includes(url.protocol)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin must be http or https' };
  if (url.username || url.password) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin must not contain credentials' };
  if (url.pathname !== '/') return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin must not contain path' };
  if (url.search || url.hash) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin must not contain query or fragment' };
  if (forbiddenContentScan(origin)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin contains forbidden content' };
  return { isValid: true };
}

// ---------------------------------------------------------------------------
// SafeHostOrDomain validator
// ---------------------------------------------------------------------------

function validateSafeHostOrDomain(value: any, field: string): ValidationResult {
  if (!value || typeof value !== 'string') return { isValid: false, errorCode: 'unsafe_content_rejected', message: `${field} missing` };
  if (value.length > 253) return { isValid: false, errorCode: 'unsafe_content_rejected', message: `${field} too long` };
  if (!/^[a-zA-Z0-9.\-]+$/.test(value)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: `${field} contains invalid characters` };
  if (forbiddenContentScan(value)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: `${field} contains forbidden content` };
  return { isValid: true };
}

// ---------------------------------------------------------------------------
// PathTemplate validator
// ---------------------------------------------------------------------------

function validatePathTemplate(pt: any): ValidationResult {
  if (!pt || typeof pt !== 'string') return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'pathTemplate missing' };
  if (pt.length > 300) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'pathTemplate too long' };
  if (!pt.startsWith('/')) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'pathTemplate must start with /' };
  if (pt.includes('?') || pt.includes('#')) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'pathTemplate must not contain query or fragment' };
  if (pt.includes('*')) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'pathTemplate must not contain glob/wildcard' };
  if (forbiddenContentScan(pt)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'pathTemplate contains forbidden content' };
  return { isValid: true };
}

// ---------------------------------------------------------------------------
// Subject validator
// ---------------------------------------------------------------------------

function validateScopeSubject(subject: any): ValidationResult {
  if (!subject) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Subject missing' };
  const keysVal = validateAllowedKeys(subject, ['targetKind', 'normalizedOrigin', 'host', 'domain']);
  if (!keysVal.isValid) return keysVal;

  if (!ALLOWED_TARGET_KINDS.includes(subject.targetKind)) {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid targetKind' };
  }
  if (subject.targetKind === 'origin') {
    const v = validateNormalizedOrigin(subject.normalizedOrigin);
    if (!v.isValid) return v;
  }
  if (subject.targetKind === 'host' || subject.host !== undefined) {
    const v = validateSafeHostOrDomain(subject.host, 'host');
    if (!v.isValid) return v;
  }
  if (subject.targetKind === 'domain' || subject.domain !== undefined) {
    const v = validateSafeHostOrDomain(subject.domain, 'domain');
    if (!v.isValid) return v;
  }
  return { isValid: true };
}

// ---------------------------------------------------------------------------
// PathScopePattern validator
// ---------------------------------------------------------------------------

function validatePathScopePattern(pattern: any): ValidationResult {
  if (!pattern) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'PathScopePattern missing' };
  const keysVal = validateAllowedKeys(pattern, ['match', 'pathTemplate']);
  if (!keysVal.isValid) return keysVal;
  if (!ALLOWED_MATCH_TYPES.includes(pattern.match)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid match type' };
  return validatePathTemplate(pattern.pathTemplate);
}

// ---------------------------------------------------------------------------
// PermissionSet validator
// ---------------------------------------------------------------------------

const PERMISSION_SET_KEYS = [
  'passiveRecon', 'technologyFingerprinting', 'endpointDiscovery', 'activeCrawling',
  'authenticatedTesting', 'lightValidation', 'activeValidation', 'aggressiveValidation',
  'oobTesting', 'destructiveOperations'
] as const;

function validatePermissionSet(ps: any): ValidationResult {
  if (!ps) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'permissionSet missing' };
  const keysVal = validateAllowedKeys(ps, PERMISSION_SET_KEYS);
  if (!keysVal.isValid) return keysVal;

  for (const key of PERMISSION_SET_KEYS) {
    if (typeof ps[key] !== 'boolean') {
      return { isValid: false, errorCode: 'unsafe_content_rejected', message: `permissionSet.${key} must be a real boolean` };
    }
  }
  if (ps.destructiveOperations !== false) {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'permissionSet.destructiveOperations must always be false' };
  }
  return { isValid: true };
}

// ---------------------------------------------------------------------------
// ScopeBoundaries validator
// ---------------------------------------------------------------------------

const SCOPE_BOUNDARIES_KEYS = [
  'allowedOrigins', 'allowedHosts', 'allowedDomains',
  'allowedPathPatterns', 'deniedPathPatterns',
  'allowedMethods', 'deniedMethods'
] as const;

function validateScopeBoundaries(boundaries: any): ValidationResult {
  if (!boundaries) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'boundaries missing' };
  const keysVal = validateAllowedKeys(boundaries, SCOPE_BOUNDARIES_KEYS);
  if (!keysVal.isValid) return keysVal;

  if (boundaries.allowedOrigins !== undefined) {
    if (!Array.isArray(boundaries.allowedOrigins)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'allowedOrigins must be an array' };
    if (boundaries.allowedOrigins.length > 50) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'allowedOrigins exceeds cap of 50' };
    for (const o of boundaries.allowedOrigins) {
      const v = validateNormalizedOrigin(o);
      if (!v.isValid) return v;
    }
  }
  if (boundaries.allowedHosts !== undefined) {
    if (!Array.isArray(boundaries.allowedHosts)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'allowedHosts must be an array' };
    if (boundaries.allowedHosts.length > 50) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'allowedHosts exceeds cap of 50' };
    for (const h of boundaries.allowedHosts) {
      const v = validateSafeHostOrDomain(h, 'host entry');
      if (!v.isValid) return v;
    }
  }
  if (boundaries.allowedDomains !== undefined) {
    if (!Array.isArray(boundaries.allowedDomains)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'allowedDomains must be an array' };
    if (boundaries.allowedDomains.length > 50) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'allowedDomains exceeds cap of 50' };
    for (const d of boundaries.allowedDomains) {
      const v = validateSafeHostOrDomain(d, 'domain entry');
      if (!v.isValid) return v;
    }
  }
  if (boundaries.allowedPathPatterns !== undefined) {
    if (!Array.isArray(boundaries.allowedPathPatterns)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'allowedPathPatterns must be an array' };
    if (boundaries.allowedPathPatterns.length > 100) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'allowedPathPatterns exceeds cap of 100' };
    for (const p of boundaries.allowedPathPatterns) {
      const v = validatePathScopePattern(p);
      if (!v.isValid) return v;
    }
  }
  if (boundaries.deniedPathPatterns !== undefined) {
    if (!Array.isArray(boundaries.deniedPathPatterns)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'deniedPathPatterns must be an array' };
    if (boundaries.deniedPathPatterns.length > 100) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'deniedPathPatterns exceeds cap of 100' };
    for (const p of boundaries.deniedPathPatterns) {
      const v = validatePathScopePattern(p);
      if (!v.isValid) return v;
    }
  }
  if (boundaries.allowedMethods !== undefined) {
    if (!Array.isArray(boundaries.allowedMethods)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'allowedMethods must be an array' };
    if (boundaries.allowedMethods.length > 7) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'allowedMethods exceeds cap of 7' };
    for (const m of boundaries.allowedMethods) {
      if (!ALLOWED_HTTP_METHODS.includes(m)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: `Invalid HTTP method: ${m}` };
    }
  }
  if (boundaries.deniedMethods !== undefined) {
    if (!Array.isArray(boundaries.deniedMethods)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'deniedMethods must be an array' };
    if (boundaries.deniedMethods.length > 7) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'deniedMethods exceeds cap of 7' };
    for (const m of boundaries.deniedMethods) {
      if (!ALLOWED_HTTP_METHODS.includes(m)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: `Invalid HTTP method: ${m}` };
    }
  }
  return { isValid: true };
}

// ---------------------------------------------------------------------------
// ScopeConstraints validator
// ---------------------------------------------------------------------------

const SCOPE_CONSTRAINTS_KEYS = [
  'maxRequestsPerMinute', 'maxDepth', 'maxRuntimeSeconds',
  'allowLoginRequiredAreas', 'allowStateChangingRequests', 'allowCredentialUse',
  'allowOobCallbacks', 'allowThirdPartyTargets', 'notes'
] as const;

function validateScopeConstraints(constraints: any, permissionSet: any): ValidationResult {
  if (!constraints) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'constraints missing' };
  const keysVal = validateAllowedKeys(constraints, SCOPE_CONSTRAINTS_KEYS);
  if (!keysVal.isValid) return keysVal;

  if (constraints.allowThirdPartyTargets !== false) {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'constraints.allowThirdPartyTargets must always be false' };
  }
  for (const key of ['allowLoginRequiredAreas', 'allowStateChangingRequests', 'allowCredentialUse', 'allowOobCallbacks'] as const) {
    if (typeof constraints[key] !== 'boolean') {
      return { isValid: false, errorCode: 'unsafe_content_rejected', message: `constraints.${key} must be a real boolean` };
    }
  }

  // allowCredentialUse: only valid if authenticatedTesting === true
  if (constraints.allowCredentialUse === true && permissionSet?.authenticatedTesting !== true) {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'constraints.allowCredentialUse requires permissionSet.authenticatedTesting === true' };
  }
  // allowOobCallbacks: only valid if oobTesting === true
  if (constraints.allowOobCallbacks === true && permissionSet?.oobTesting !== true) {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'constraints.allowOobCallbacks requires permissionSet.oobTesting === true' };
  }

  if (constraints.maxRequestsPerMinute !== undefined) {
    if (!Number.isFinite(constraints.maxRequestsPerMinute) || constraints.maxRequestsPerMinute < 1 || constraints.maxRequestsPerMinute > 600) {
      return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'maxRequestsPerMinute must be between 1 and 600' };
    }
  }
  if (constraints.maxDepth !== undefined) {
    if (!Number.isFinite(constraints.maxDepth) || constraints.maxDepth < 0 || constraints.maxDepth > 20) {
      return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'maxDepth must be between 0 and 20' };
    }
  }
  if (constraints.maxRuntimeSeconds !== undefined) {
    if (!Number.isFinite(constraints.maxRuntimeSeconds) || constraints.maxRuntimeSeconds < 1 || constraints.maxRuntimeSeconds > 86400) {
      return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'maxRuntimeSeconds must be between 1 and 86400' };
    }
  }
  if (constraints.notes !== undefined) {
    const v = validateSafeText(constraints.notes, 1000);
    if (!v.isValid) return v;
  }
  return { isValid: true };
}

// ---------------------------------------------------------------------------
// AuthorizedScopeGrant validator
// ---------------------------------------------------------------------------

export function validateAuthorizedScopeGrant(grant: any): ValidationResult {
  if (!grant || grant.kind !== 'authorized_scope_grant') {
    return { isValid: false, errorCode: 'denied_invalid_grant', message: 'Invalid kind' };
  }
  if (grant.contractVersion !== AUTHORIZED_SCOPE_POLICY_CONTRACT_VERSION) {
    return { isValid: false, errorCode: 'denied_invalid_grant', message: 'Invalid contractVersion' };
  }

  const keysVal = validateAllowedKeys(grant, [
    'contractVersion', 'kind', 'grantId', 'scanId', 'issuedAt', 'expiresAt',
    'subject', 'authorizationBasis', 'permissionSet', 'boundaries', 'constraints', 'classification'
  ]);
  if (!keysVal.isValid) return { ...keysVal, errorCode: 'denied_invalid_grant' };

  const idChecks = [validateSafeId(grant.grantId), validateSafeId(grant.scanId)];
  for (const c of idChecks) { if (!c.isValid) return { isValid: false, errorCode: 'denied_invalid_grant', message: c.message }; }

  const tsChecks = [validateIsoTimestamp(grant.issuedAt), validateIsoTimestamp(grant.expiresAt)];
  for (const c of tsChecks) { if (!c.isValid) return { isValid: false, errorCode: 'denied_invalid_grant', message: c.message }; }

  const clsVal = validateClassification(grant.classification);
  if (!clsVal.isValid) return { isValid: false, errorCode: 'denied_invalid_grant', message: clsVal.message };

  const subVal = validateScopeSubject(grant.subject);
  if (!subVal.isValid) return { isValid: false, errorCode: 'denied_invalid_grant', message: subVal.message };

  // authorizationBasis
  const ab = grant.authorizationBasis;
  if (!ab) return { isValid: false, errorCode: 'denied_invalid_grant', message: 'authorizationBasis missing' };
  const abKeys = validateAllowedKeys(ab, ['basisKind', 'referenceId', 'recordedBy', 'authorizationText']);
  if (!abKeys.isValid) return { ...abKeys, errorCode: 'denied_invalid_grant' };
  if (!ALLOWED_BASIS_KINDS.includes(ab.basisKind)) return { isValid: false, errorCode: 'denied_invalid_grant', message: 'Invalid basisKind' };
  if (!ALLOWED_RECORDED_BY.includes(ab.recordedBy)) return { isValid: false, errorCode: 'denied_invalid_grant', message: 'Invalid recordedBy' };
  const abTextVal = validateSafeText(ab.authorizationText, 1000);
  if (!abTextVal.isValid) return { isValid: false, errorCode: 'denied_invalid_grant', message: abTextVal.message };
  if (ab.referenceId !== undefined) {
    const refVal = validateSafeId(ab.referenceId);
    if (!refVal.isValid) return { isValid: false, errorCode: 'denied_invalid_grant', message: refVal.message };
  }

  const psVal = validatePermissionSet(grant.permissionSet);
  if (!psVal.isValid) return { isValid: false, errorCode: 'denied_invalid_grant', message: psVal.message };

  const bdVal = validateScopeBoundaries(grant.boundaries);
  if (!bdVal.isValid) return { isValid: false, errorCode: 'denied_invalid_grant', message: bdVal.message };

  const ctVal = validateScopeConstraints(grant.constraints, grant.permissionSet);
  if (!ctVal.isValid) return { isValid: false, errorCode: 'denied_invalid_grant', message: ctVal.message };

  return { isValid: true };
}

// ---------------------------------------------------------------------------
// ScopeActionRequest validator
// ---------------------------------------------------------------------------

export function validateScopeActionRequest(request: any): ValidationResult {
  if (!request || request.kind !== 'scope_action_request') {
    return { isValid: false, errorCode: 'denied_invalid_request', message: 'Invalid kind' };
  }
  if (request.contractVersion !== AUTHORIZED_SCOPE_POLICY_CONTRACT_VERSION) {
    return { isValid: false, errorCode: 'denied_invalid_request', message: 'Invalid contractVersion' };
  }

  const keysVal = validateAllowedKeys(request, [
    'contractVersion', 'kind', 'requestId', 'scanId', 'requestedAt',
    'actionKind', 'target', 'method', 'pathTemplate',
    'requiredPermission', 'intensity', 'usesCredentials',
    'mayChangeServerState', 'usesOob', 'classification'
  ]);
  if (!keysVal.isValid) return { ...keysVal, errorCode: 'denied_invalid_request' };

  const idChecks = [validateSafeId(request.requestId), validateSafeId(request.scanId)];
  for (const c of idChecks) { if (!c.isValid) return { isValid: false, errorCode: 'denied_invalid_request', message: c.message }; }

  const tsVal = validateIsoTimestamp(request.requestedAt);
  if (!tsVal.isValid) return { isValid: false, errorCode: 'denied_invalid_request', message: tsVal.message };

  if (!ALLOWED_ACTION_KINDS.includes(request.actionKind)) {
    return { isValid: false, errorCode: 'denied_invalid_request', message: 'Invalid actionKind' };
  }
  if (!ALLOWED_INTENSITIES.includes(request.intensity)) {
    return { isValid: false, errorCode: 'denied_invalid_request', message: 'Invalid intensity' };
  }

  const clsVal = validateClassification(request.classification);
  if (!clsVal.isValid) return { isValid: false, errorCode: 'denied_invalid_request', message: clsVal.message };

  const tgtVal = validateScopeSubject(request.target);
  if (!tgtVal.isValid) return { isValid: false, errorCode: 'denied_invalid_request', message: tgtVal.message };

  if (request.method !== undefined && !ALLOWED_HTTP_METHODS.includes(request.method)) {
    return { isValid: false, errorCode: 'denied_invalid_request', message: 'Invalid method' };
  }
  if (request.pathTemplate !== undefined) {
    const ptVal = validatePathTemplate(request.pathTemplate);
    if (!ptVal.isValid) return { isValid: false, errorCode: 'denied_invalid_request', message: ptVal.message };
  }
  if (request.requiredPermission !== undefined && !ALLOWED_REQUIRED_PERMISSIONS.includes(request.requiredPermission)) {
    return { isValid: false, errorCode: 'denied_invalid_request', message: 'Invalid requiredPermission' };
  }
  for (const boolKey of ['usesCredentials', 'mayChangeServerState', 'usesOob'] as const) {
    if (typeof request[boolKey] !== 'boolean') {
      return { isValid: false, errorCode: 'denied_invalid_request', message: `${boolKey} must be a real boolean` };
    }
  }
  return { isValid: true };
}

// ---------------------------------------------------------------------------
// Permission Derivation
// ---------------------------------------------------------------------------

export function deriveRequiredPermissionForAction(
  actionKind: ActionKind,
  intensity: Intensity,
  usesCredentials: boolean,
  usesOob: boolean,
  mayChangeServerState: boolean
): RequiredPermission {
  // Destructive always destructive
  if (actionKind === 'destructive_operation' || intensity === 'destructive') return 'destructiveOperations';

  // actionKind is the authority
  const kindMap: Record<ActionKind, RequiredPermission> = {
    passive_recon: 'passiveRecon',
    technology_fingerprint: 'technologyFingerprinting',
    endpoint_discovery: 'endpointDiscovery',
    active_crawl: 'activeCrawling',
    authenticated_probe: 'authenticatedTesting',
    light_validation: 'lightValidation',
    active_validation: 'activeValidation',
    aggressive_validation: 'aggressiveValidation',
    oob_validation: 'oobTesting',
    destructive_operation: 'destructiveOperations'
  };

  let derived = kindMap[actionKind];

  // Intensity may upgrade but never downgrade
  const validationActionKinds: ActionKind[] = [
    'light_validation', 'active_validation', 'aggressive_validation'
  ];

  if (validationActionKinds.includes(actionKind)) {
    if (intensity === 'aggressive') {
      // Ensure aggressiveValidation minimum
      if (derived === 'lightValidation' || derived === 'activeValidation') {
        derived = 'aggressiveValidation';
      }
    } else if (intensity === 'medium' || intensity === 'high') {
      // Ensure activeValidation minimum for validation-like actions
      if (derived === 'lightValidation') {
        derived = 'activeValidation';
      }
    }
  }

  return derived;
}

// ---------------------------------------------------------------------------
// Path matching
// ---------------------------------------------------------------------------

/**
 * Match request pathTemplate against a PathScopePattern.
 *
 * exact: pathTemplates must be identical.
 * prefix: request path must equal pattern OR start with pattern + "/" —
 *         ensuring /api does NOT match /apiary.
 */
function matchPath(requestPath: string, pattern: PathScopePattern): boolean {
  const p = pattern.pathTemplate;
  if (pattern.match === 'exact') return requestPath === p;
  // prefix
  if (requestPath === p) return true;
  const sep = p.endsWith('/') ? p : `${p}/`;
  return requestPath.startsWith(sep);
}

// ---------------------------------------------------------------------------
// Subject target matching
// ---------------------------------------------------------------------------

function matchesGrantSubjectOrBoundaries(
  grantSubject: ScopeSubject,
  boundaries: any,
  requestTarget: ScopeSubject
): { matched: boolean; matchedBoundary?: MatchedBoundary } {
  // Check allowedOrigins first if present
  if (boundaries.allowedOrigins && Array.isArray(boundaries.allowedOrigins) && boundaries.allowedOrigins.length > 0) {
    const ro = requestTarget.normalizedOrigin;
    if (ro && boundaries.allowedOrigins.includes(ro)) {
      return { matched: true, matchedBoundary: { boundaryKind: 'allowed_origin', matchType: 'exact' } };
    }
    return { matched: false };
  }
  if (boundaries.allowedHosts && Array.isArray(boundaries.allowedHosts) && boundaries.allowedHosts.length > 0) {
    const rh = requestTarget.host;
    if (rh && boundaries.allowedHosts.includes(rh)) {
      return { matched: true, matchedBoundary: { boundaryKind: 'allowed_host', matchType: 'exact' } };
    }
    return { matched: false };
  }
  if (boundaries.allowedDomains && Array.isArray(boundaries.allowedDomains) && boundaries.allowedDomains.length > 0) {
    const rd = requestTarget.domain;
    if (rd && boundaries.allowedDomains.includes(rd)) {
      return { matched: true, matchedBoundary: { boundaryKind: 'allowed_domain', matchType: 'exact' } };
    }
    return { matched: false };
  }

  // Fall back to grant subject match
  if (grantSubject.targetKind === 'origin' && requestTarget.normalizedOrigin) {
    if (requestTarget.normalizedOrigin === grantSubject.normalizedOrigin) {
      return { matched: true, matchedBoundary: { boundaryKind: 'subject', matchType: 'exact' } };
    }
  }
  if (grantSubject.targetKind === 'host' && requestTarget.host) {
    if (requestTarget.host === grantSubject.host) {
      return { matched: true, matchedBoundary: { boundaryKind: 'subject', matchType: 'exact' } };
    }
  }
  if (grantSubject.targetKind === 'domain' && requestTarget.domain) {
    if (requestTarget.domain === grantSubject.domain) {
      return { matched: true, matchedBoundary: { boundaryKind: 'subject', matchType: 'exact' } };
    }
  }
  return { matched: false };
}

// ---------------------------------------------------------------------------
// Safe sentinel extraction for IDs that may be untrusted
// ---------------------------------------------------------------------------

const SENTINEL_DECISION_ID = 'invalid_decision_id';
const SENTINEL_EVALUATED_AT = '1970-01-01T00:00:00.000Z';
const SENTINEL_GRANT_ID = 'invalid_grant_id';
const SENTINEL_REQUEST_ID = 'invalid_request_id';
const SENTINEL_SCAN_ID = 'invalid_scan_id';

/**
 * Extract a safe ID from an untrusted source, returning a sentinel if invalid.
 * Never returns forbidden/unsafe values — protects decisions from echoing injected content.
 */
function safeIdOrSentinel(raw: any, sentinel: string): string {
  if (!raw || typeof raw !== 'string') return sentinel;
  const v = validateSafeId(raw);
  return v.isValid ? raw : sentinel;
}

// ---------------------------------------------------------------------------
// Centralized ScopePolicyDecision builder — ALL decisions go through here.
// Ensures decisionId, evaluatedAt, and other IDs are safe before embedding.
// ---------------------------------------------------------------------------

function buildScopePolicyDecision({
  reasonCode,
  decision,
  reason,
  safeDecisionId,
  safeEvaluatedAt,
  safeGrantId,
  safeRequestId,
  safeScanId,
  matchedPermission,
  matchedBoundary
}: {
  reasonCode: ScopePolicyDecision['reasonCode'];
  decision: 'allowed' | 'denied';
  reason: string;
  safeDecisionId: string;
  safeEvaluatedAt: string;
  safeGrantId: string;
  safeRequestId: string;
  safeScanId: string;
  matchedPermission: RequiredPermission | null;
  matchedBoundary?: MatchedBoundary;
}): ScopePolicyDecision {
  return {
    contractVersion: AUTHORIZED_SCOPE_POLICY_CONTRACT_VERSION,
    kind: 'scope_policy_decision',
    decisionId: safeDecisionId,
    requestId: safeRequestId,
    grantId: safeGrantId,
    scanId: safeScanId,
    evaluatedAt: safeEvaluatedAt,
    decision,
    reasonCode,
    reason,
    matchedPermission,
    matchedBoundary,
    classification: getSafeClassification()
  };
}

// ---------------------------------------------------------------------------
// evaluateScopePolicy
// ---------------------------------------------------------------------------

export function evaluateScopePolicy({
  grant,
  request,
  decisionId,
  evaluatedAt
}: {
  grant: any;
  request: any;
  decisionId: string;
  evaluatedAt: string;
}): ScopePolicyDecision {
  // Validate and sanitize decisionId and evaluatedAt FIRST — never echo unsafe values.
  const safeDecisionId = safeIdOrSentinel(decisionId, SENTINEL_DECISION_ID);
  const safeEvaluatedAt = validateIsoTimestamp(evaluatedAt).isValid ? evaluatedAt : SENTINEL_EVALUATED_AT;

  // If core decision metadata is invalid, deny immediately without touching grant/request.
  if (safeDecisionId === SENTINEL_DECISION_ID || safeEvaluatedAt === SENTINEL_EVALUATED_AT) {
    return buildScopePolicyDecision({
      reasonCode: 'denied_invalid_request',
      decision: 'denied',
      reason: 'Decision metadata (decisionId or evaluatedAt) is invalid.',
      safeDecisionId: SENTINEL_DECISION_ID,
      safeEvaluatedAt: SENTINEL_EVALUATED_AT,
      safeGrantId: SENTINEL_GRANT_ID,
      safeRequestId: SENTINEL_REQUEST_ID,
      safeScanId: SENTINEL_SCAN_ID,
      matchedPermission: null
    });
  }

  // Extract IDs safely from grant/request — use sentinels if unsafe or missing.
  const safeGrantId = safeIdOrSentinel(grant?.grantId, SENTINEL_GRANT_ID);
  const safeRequestId = safeIdOrSentinel(request?.requestId, SENTINEL_REQUEST_ID);
  const safeScanId = safeIdOrSentinel(grant?.scanId, SENTINEL_SCAN_ID);

  // Shorthand builder for denied decisions using safe IDs.
  const deny = (
    reasonCode: ScopePolicyDecision['reasonCode'],
    reason: string
  ): ScopePolicyDecision =>
    buildScopePolicyDecision({
      reasonCode, decision: 'denied', reason,
      safeDecisionId, safeEvaluatedAt,
      safeGrantId, safeRequestId, safeScanId,
      matchedPermission: null
    });

  // 1. Validate grant
  const grantVal = validateAuthorizedScopeGrant(grant);
  if (!grantVal.isValid) return deny('denied_invalid_grant', 'Grant validation failed.');

  // 2. Validate request
  const requestVal = validateScopeActionRequest(request);
  if (!requestVal.isValid) return deny('denied_invalid_request', 'Request validation failed.');

  // 3. Destructive operation / intensity
  if (request.actionKind === 'destructive_operation' || request.intensity === 'destructive') {
    return deny('denied_destructive_operation', 'Destructive operations are never permitted.');
  }

  // 4. Expired grant
  if (Date.now() > Date.parse(grant.expiresAt)) {
    return deny('denied_expired_grant', 'Grant has expired.');
  }

  // 5. Scan mismatch
  if (grant.scanId !== request.scanId) {
    return deny('denied_scan_mismatch', 'Request scanId does not match grant scanId.');
  }

  // 6. Target out of scope
  const targetMatch = matchesGrantSubjectOrBoundaries(grant.subject, grant.boundaries, request.target);
  if (!targetMatch.matched) {
    return deny('denied_target_out_of_scope', 'Request target is not within the authorized scope.');
  }

  // 7. Denied path patterns (denied paths win)
  if (request.pathTemplate && grant.boundaries.deniedPathPatterns && Array.isArray(grant.boundaries.deniedPathPatterns)) {
    for (const pattern of grant.boundaries.deniedPathPatterns) {
      if (matchPath(request.pathTemplate, pattern)) {
        return deny('denied_path_explicitly_denied', 'Request path is explicitly denied.');
      }
    }
  }

  // 8. Allowed path patterns (must match if present)
  if (request.pathTemplate && grant.boundaries.allowedPathPatterns && Array.isArray(grant.boundaries.allowedPathPatterns) && grant.boundaries.allowedPathPatterns.length > 0) {
    const matchedPath = grant.boundaries.allowedPathPatterns.find((p: PathScopePattern) => matchPath(request.pathTemplate, p));
    if (!matchedPath) {
      return deny('denied_path_out_of_scope', 'Request path is not within allowed path patterns.');
    }
  }

  // 9. Denied methods
  if (request.method && grant.boundaries.deniedMethods && Array.isArray(grant.boundaries.deniedMethods)) {
    if (grant.boundaries.deniedMethods.includes(request.method)) {
      return deny('denied_method_explicitly_denied', 'Request method is explicitly denied.');
    }
  }

  // 10. Allowed methods
  if (request.method && grant.boundaries.allowedMethods && Array.isArray(grant.boundaries.allowedMethods) && grant.boundaries.allowedMethods.length > 0) {
    if (!grant.boundaries.allowedMethods.includes(request.method)) {
      return deny('denied_method_not_allowed', 'Request method is not in allowedMethods.');
    }
  }

  // 11. Auth/credentials
  if (request.usesCredentials === true && grant.permissionSet.authenticatedTesting !== true) {
    return deny('denied_requires_authenticated_testing', 'Request uses credentials but authenticatedTesting is not permitted.');
  }

  // 12. OOB
  if (request.usesOob === true && (grant.permissionSet.oobTesting !== true || grant.constraints.allowOobCallbacks !== true)) {
    return deny('denied_requires_oob_permission', 'Request uses OOB but oobTesting/allowOobCallbacks is not permitted.');
  }

  // 13. State-changing restrictions
  const stateChangingMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
  const methodIsStateChanging = request.method && stateChangingMethods.includes(request.method);
  if ((methodIsStateChanging || request.mayChangeServerState === true) && grant.constraints.allowStateChangingRequests !== true) {
    return deny('denied_state_change_not_allowed', 'Request may change server state but allowStateChangingRequests is not permitted.');
  }

  // 14. Derive required permission and check.
  // IMPORTANT: never trust request.requiredPermission from the caller.
  const derivedPermission = deriveRequiredPermissionForAction(
    request.actionKind,
    request.intensity,
    request.usesCredentials,
    request.usesOob,
    request.mayChangeServerState
  );

  // If caller sent requiredPermission, validate it matches derived (security invariant)
  if (request.requiredPermission !== undefined && request.requiredPermission !== derivedPermission) {
    return deny('denied_invalid_request', 'Caller requiredPermission does not match derived permission for actionKind/intensity.');
  }

  // Check derived permission against grant
  if (!(grant.permissionSet as any)[derivedPermission]) {
    return deny('denied_missing_permission', 'Derived required permission is not granted.');
  }

  // 15. Allowed
  return buildScopePolicyDecision({
    reasonCode: 'allowed_by_scope_policy',
    decision: 'allowed',
    reason: 'Action is authorized within the declared scope and permissions.',
    safeDecisionId, safeEvaluatedAt,
    safeGrantId, safeRequestId, safeScanId,
    matchedPermission: derivedPermission,
    matchedBoundary: targetMatch.matchedBoundary
  });
}
