/**
 * Milestone A11 — Credential Reuse Capability
 *
 * Defensive verification of credential reuse against an authorized destination.
 * Consumes CredentialVaultService.authorizeAndUse() and enforces:
 * 1. AuthorizedScopeGrant permits destination host
 * 2. isRuntimeAuthorizedForBlastRadius(token, 'credential_use', ...)
 * 3. SSRF + DNS-rebinding fail-closed BEFORE any network dispatch
 *
 * Injectable transport enables hermetic smoke (zero real network).
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import { isScopeAllowed } from '../AttackExecutionContracts.js';
import { isRuntimeAuthorizedForBlastRadius } from '../../attack-authorization/AttackAuthorizationService.js';
import type { AttackAuthorizationToken } from '../../attack-authorization/AttackAuthorizationContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { CredentialReference } from '../../post-exploitation/PostExploitationContracts.js';
import {
  CredentialVaultAccessError,
  CredentialVaultService,
} from '../../post-exploitation/CredentialVaultService.js';
import { isInternalOrSsrfTarget } from '../../recon/policy/PassiveEgressPolicy.js';
import {
  validateDnsRebinding,
  type PreSpawnDnsResolver,
} from '../../recon/adapters/AdapterPreflightPipeline.js';
import type {
  HttpProbeRequest,
  HttpProbeResponse,
  IdorHttpProbeTransport,
} from '../../detection/DetectionContracts.js';

function succeeded(
  reasonCode: string,
  safeMessage: string,
  evidenceId?: string
): AttackCapabilityExecutionResult {
  return {
    outcome: 'succeeded',
    reasonCode,
    safeMessage,
    ...(evidenceId ? { evidenceId } : {}),
  };
}

function refuted(reasonCode: string, safeMessage: string): AttackCapabilityExecutionResult {
  return { outcome: 'refuted', reasonCode, safeMessage };
}

function failed(reasonCode: string, safeMessage: string): AttackCapabilityExecutionResult {
  return { outcome: 'failed', reasonCode, safeMessage };
}

export type CredentialReuseOutcome =
  | 'access_confirmed'
  | 'access_denied'
  | 'denied'
  | 'preflight_denied';

export interface CredentialReuseAttemptResult {
  readonly outcome: CredentialReuseOutcome;
  readonly reasonCode: string;
  readonly safeMessage: string;
  readonly evidenceId?: string;
  readonly networkDispatched: boolean;
  readonly statusCode?: number;
}

export interface CredentialReuseAttemptInput {
  readonly vault: CredentialVaultService;
  readonly credentialRef: CredentialReference;
  readonly targetHost: string;
  readonly targetUrl: string;
  readonly token: AttackAuthorizationToken;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface CredentialReuseCapabilityOptions {
  readonly vault: CredentialVaultService;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  /**
   * Optional bound credential for AttackCapabilityPort.execute().
   * LateralMovementService prefers attemptCredentialReuse() with an explicit ref.
   */
  readonly credentialRef?: CredentialReference;
}

function buildAuthHeaders(
  credentialKind: CredentialReference['credentialKind'],
  secret: string
): Readonly<Record<string, string>> {
  switch (credentialKind) {
    case 'bearer_token':
    case 'oauth_refresh_token':
      return { Authorization: `Bearer ${secret}` };
    case 'api_key':
      return { 'X-Api-Key': secret };
    case 'basic_auth':
      return { Authorization: `Basic ${secret}` };
    case 'session_cookie':
      return { Cookie: secret };
    default: {
      const _exhaustive: never = credentialKind;
      return _exhaustive;
    }
  }
}

/**
 * Core credential-reuse attempt with mandatory gates before any network I/O.
 */
export async function attemptCredentialReuse(
  input: CredentialReuseAttemptInput
): Promise<CredentialReuseAttemptResult> {
  const targetHost = input.targetHost.trim().toLowerCase();
  if (targetHost.length === 0) {
    return {
      outcome: 'denied',
      reasonCode: 'target_host_invalid',
      safeMessage: 'targetHost must be a non-empty string',
      networkDispatched: false,
    };
  }

  // Gate 1: AuthorizedScopeGrant for destination
  if (!input.scopeGrant || typeof input.scopeGrant !== 'object') {
    return {
      outcome: 'denied',
      reasonCode: 'scope_grant_missing',
      safeMessage: 'AuthorizedScopeGrant is required for credential reuse',
      networkDispatched: false,
    };
  }
  if (!isScopeAllowed(targetHost, input.scopeGrant)) {
    return {
      outcome: 'denied',
      reasonCode: 'target_host_out_of_scope',
      safeMessage: 'Destination host is outside AuthorizedScopeGrant (zero network)',
      networkDispatched: false,
    };
  }

  // Gate 2: credential_use runtime brand
  const token = input.token;
  if (!token || typeof token !== 'object') {
    return {
      outcome: 'denied',
      reasonCode: 'credential_use_not_authorized',
      safeMessage: 'AttackAuthorizationToken is required for credential_use',
      networkDispatched: false,
    };
  }
  const brandOk = isRuntimeAuthorizedForBlastRadius(
    token,
    'credential_use',
    token.planId,
    token.assessmentId
  );
  if (!brandOk) {
    return {
      outcome: 'denied',
      reasonCode: 'credential_use_not_authorized',
      safeMessage: 'credential_use brand missing or blast-radius mismatch (fail-closed)',
      networkDispatched: false,
    };
  }

  // Gate 3: SSRF host blocklist
  if (isInternalOrSsrfTarget(targetHost)) {
    return {
      outcome: 'preflight_denied',
      reasonCode: 'gate_ssrf_egress',
      safeMessage: 'Destination host is internal or SSRF-blocked (zero network)',
      networkDispatched: false,
    };
  }

  // Gate 4: DNS rebinding
  const dnsResolver = input.dnsResolver;
  if (!dnsResolver) {
    return {
      outcome: 'preflight_denied',
      reasonCode: 'gate_dns_rebinding',
      safeMessage: 'DNS resolver required for credential reuse preflight (fail-closed)',
      networkDispatched: false,
    };
  }
  const dnsCheck = await validateDnsRebinding(targetHost, dnsResolver);
  if (!dnsCheck.ok) {
    return {
      outcome: 'preflight_denied',
      reasonCode: 'gate_dns_rebinding',
      safeMessage: 'DNS rebinding / private IP resolution blocked (zero network)',
      networkDispatched: false,
    };
  }

  // Vault authorizeAndUse (scope + brand again; single-use accessor)
  let secret: string;
  try {
    const accessor = input.vault.authorizeAndUse(
      input.credentialRef,
      targetHost,
      token,
      input.scopeGrant
    );
    secret = accessor.use();
  } catch (err) {
    if (err instanceof CredentialVaultAccessError) {
      return {
        outcome: 'denied',
        reasonCode: err.reasonCode,
        safeMessage: err.message,
        networkDispatched: false,
      };
    }
    return {
      outcome: 'denied',
      reasonCode: 'credential_vault_error',
      safeMessage: 'Credential vault access failed (fail-closed)',
      networkDispatched: false,
    };
  }

  const transport = input.transport;
  if (!transport) {
    return {
      outcome: 'denied',
      reasonCode: 'transport_missing',
      safeMessage: 'HTTP transport required for credential reuse (fail-closed)',
      networkDispatched: false,
    };
  }

  const headers = buildAuthHeaders(input.credentialRef.credentialKind, secret);
  const request: HttpProbeRequest = {
    url: input.targetUrl,
    method: 'GET',
    headers,
    timeoutMs: 5_000,
  };

  let response: HttpProbeResponse;
  try {
    response = await transport(request);
  } catch {
    return {
      outcome: 'access_denied',
      reasonCode: 'transport_error',
      safeMessage: 'Credential reuse transport failed after authorized dispatch',
      networkDispatched: true,
    };
  }

  const evidenceId = `ev_cred_reuse_${Date.now().toString(36)}`;
  if (response.statusCode >= 200 && response.statusCode < 400) {
    return {
      outcome: 'access_confirmed',
      reasonCode: 'credential_reuse_access_confirmed',
      safeMessage: `Credential reuse observed HTTP ${response.statusCode} on authorized destination`,
      evidenceId,
      networkDispatched: true,
      statusCode: response.statusCode,
    };
  }

  if (response.statusCode === 401 || response.statusCode === 403) {
    return {
      outcome: 'access_denied',
      reasonCode: 'credential_reuse_access_denied',
      safeMessage: `Credential reuse denied by destination (HTTP ${response.statusCode})`,
      evidenceId,
      networkDispatched: true,
      statusCode: response.statusCode,
    };
  }

  return {
    outcome: 'access_denied',
    reasonCode: 'credential_reuse_inconclusive',
    safeMessage: `Credential reuse inconclusive (HTTP ${response.statusCode})`,
    evidenceId,
    networkDispatched: true,
    statusCode: response.statusCode,
  };
}

/**
 * Creates credential_reuse AttackCapabilityPort.
 * Injectable vault/transport/dnsResolver for hermetic proofs.
 */
export function createCredentialReuseCapability(
  options: CredentialReuseCapabilityOptions
): AttackCapabilityPort {
  const vault = options.vault;
  const defaultTransport = options.transport;
  const defaultDns = options.dnsResolver;
  const boundRef = options.credentialRef;

  return {
    capability: 'credential_reuse',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      const credentialRef = boundRef ?? ctx.credentialReference;
      if (!credentialRef) {
        return failed(
          'credential_reference_missing',
          'credential_reuse requires a CredentialReference'
        );
      }

      const result = await attemptCredentialReuse({
        vault: ctx.credentialVaultService ?? vault,
        credentialRef,
        targetHost: ctx.targetHost,
        targetUrl: ctx.targetUrl || `https://${ctx.targetHost}/`,
        token: ctx.token,
        scopeGrant: ctx.scopeGrant,
        transport: ctx.transport ?? defaultTransport,
        dnsResolver: ctx.dnsResolver ?? defaultDns,
      });

      switch (result.outcome) {
        case 'access_confirmed':
          return succeeded(result.reasonCode, result.safeMessage, result.evidenceId);
        case 'access_denied':
          return refuted(result.reasonCode, result.safeMessage);
        case 'denied':
        case 'preflight_denied':
          return failed(result.reasonCode, result.safeMessage);
        default: {
          const _exhaustive: never = result.outcome;
          return failed('credential_reuse_unexpected', `Unexpected: ${String(_exhaustive)}`);
        }
      }
    },
  };
}
