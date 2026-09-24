/**
 * Server-side scope grant re-binding.
 *
 * Client-supplied AuthorizedScopeGrant objects are never authoritative.
 * They must be intersected / validated against the assessment's sealed grant.
 * Escalation (new hosts, elevated permissions/constraints) fails closed.
 */

import { isScopeAllowed } from '../attack-execution/AttackExecutionContracts.js';
import type { AuthorizedScopeGrant, PermissionSet } from './AuthorizedScopeContracts.js';

export type ScopeGrantRebindFailure = {
  readonly ok: false;
  readonly reasonCode: 'scope_violation';
  readonly safeMessage: string;
};

export type ScopeGrantRebindSuccess = {
  readonly ok: true;
  /** Authoritative sealed grant — never the client object. */
  readonly scopeGrant: AuthorizedScopeGrant;
};

export type ScopeGrantRebindResult = ScopeGrantRebindSuccess | ScopeGrantRebindFailure;

const PERMISSION_KEYS: readonly (keyof PermissionSet)[] = [
  'passiveRecon',
  'technologyFingerprinting',
  'endpointDiscovery',
  'activeCrawling',
  'authenticatedTesting',
  'lightValidation',
  'activeValidation',
  'aggressiveValidation',
  'oobTesting',
  'destructiveOperations',
] as const;

const CONSTRAINT_KEYS = [
  'allowLoginRequiredAreas',
  'allowStateChangingRequests',
  'allowCredentialUse',
  'allowOobCallbacks',
  'allowThirdPartyTargets',
] as const;

/**
 * Validate client grant against sealed assessment grant and return the sealed grant.
 * Rejects host/domain expansion and permission/constraint escalation.
 */
export function rebindClientScopeGrantAgainstSealed(
  clientGrant: AuthorizedScopeGrant,
  sealedGrant: AuthorizedScopeGrant
): ScopeGrantRebindResult {
  if (clientGrant.grantId !== sealedGrant.grantId) {
    return {
      ok: false,
      reasonCode: 'scope_violation',
      safeMessage: 'Client scopeGrant.grantId does not match sealed assessment grant',
    };
  }
  if (clientGrant.scanId !== sealedGrant.scanId) {
    return {
      ok: false,
      reasonCode: 'scope_violation',
      safeMessage: 'Client scopeGrant.scanId does not match sealed assessment grant',
    };
  }

  const clientHosts = clientGrant.boundaries.allowedHosts ?? [];
  for (const host of clientHosts) {
    if (typeof host !== 'string' || !isScopeAllowed(host, sealedGrant)) {
      return {
        ok: false,
        reasonCode: 'scope_violation',
        safeMessage: 'Client scopeGrant expands allowedHosts beyond sealed assessment grant',
      };
    }
  }

  const sealedDomains = new Set(
    (sealedGrant.boundaries.allowedDomains ?? []).map((d) => d.toLowerCase())
  );
  for (const domain of clientGrant.boundaries.allowedDomains ?? []) {
    if (typeof domain !== 'string') {
      return {
        ok: false,
        reasonCode: 'scope_violation',
        safeMessage: 'Client scopeGrant contains an invalid allowedDomains entry',
      };
    }
    const normalized = domain.toLowerCase();
    if (!sealedDomains.has(normalized) && !isScopeAllowed(normalized, sealedGrant)) {
      return {
        ok: false,
        reasonCode: 'scope_violation',
        safeMessage: 'Client scopeGrant expands allowedDomains beyond sealed assessment grant',
      };
    }
  }

  const sealedOrigins = new Set(
    (sealedGrant.boundaries.allowedOrigins ?? []).map((o) => o.toLowerCase())
  );
  for (const origin of clientGrant.boundaries.allowedOrigins ?? []) {
    if (typeof origin !== 'string') {
      return {
        ok: false,
        reasonCode: 'scope_violation',
        safeMessage: 'Client scopeGrant contains an invalid allowedOrigins entry',
      };
    }
    if (!sealedOrigins.has(origin.toLowerCase())) {
      try {
        const host = new URL(origin).hostname;
        if (!isScopeAllowed(host, sealedGrant)) {
          return {
            ok: false,
            reasonCode: 'scope_violation',
            safeMessage: 'Client scopeGrant expands allowedOrigins beyond sealed assessment grant',
          };
        }
      } catch {
        return {
          ok: false,
          reasonCode: 'scope_violation',
          safeMessage: 'Client scopeGrant contains an invalid allowedOrigins entry',
        };
      }
    }
  }

  for (const key of PERMISSION_KEYS) {
    if (clientGrant.permissionSet[key] === true && sealedGrant.permissionSet[key] !== true) {
      return {
        ok: false,
        reasonCode: 'scope_violation',
        safeMessage: `Client scopeGrant escalates permissionSet.${key}`,
      };
    }
  }

  for (const key of CONSTRAINT_KEYS) {
    if (clientGrant.constraints[key] === true && sealedGrant.constraints[key] !== true) {
      return {
        ok: false,
        reasonCode: 'scope_violation',
        safeMessage: `Client scopeGrant escalates constraints.${key}`,
      };
    }
  }

  return { ok: true, scopeGrant: sealedGrant };
}
