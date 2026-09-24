/**
 * Milestone A5 — Attack Execution Engine Contracts
 * Contract version: fixguard-attack-execution/v0
 *
 * Executes human-authorized defensive verification capabilities only.
 * Requires a runtime-branded AttackAuthorizationToken (WeakSet) from A4.
 * Plans remain non-executable without brand + 7 safety gates.
 */

import type { AttackAuthorizationToken, AuthorizableBlastRadiusClass } from '../attack-authorization/AttackAuthorizationContracts.js';
import type { AttackCapabilityKind, AttackPlan, AttackStep } from '../attack-planning/AttackPlanContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { VerificationState } from '../core/VerificationStateContracts.js';
import type { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import type { CredentialReference } from '../post-exploitation/PostExploitationContracts.js';
import type { CredentialVaultService } from '../post-exploitation/CredentialVaultService.js';

export type AttackExecutionContractVersion = 'fixguard-attack-execution/v0';
export const ATTACK_EXECUTION_CONTRACT_VERSION: AttackExecutionContractVersion =
  'fixguard-attack-execution/v0';

/**
 * Execution-time step view: AttackPlan advisory step + required blast-radius class.
 * blastRadiusClass is bound from the human-authorized token (exact class; no cascade).
 */
export interface AttackExecutionStep extends AttackStep {
  readonly blastRadiusClass: AuthorizableBlastRadiusClass;
}

export type AttackStepExecutionOutcome =
  | 'succeeded'
  | 'observed'
  | 'refuted'
  | 'failed'
  | 'preflight_denied'
  | 'capability_not_implemented';

export type AttackExecutionGateFailureCode =
  | 'gate_authorization_brand'
  | 'gate_plan_binding'
  | 'gate_assessment_binding'
  | 'gate_ssrf_egress'
  | 'gate_dns_rebinding'
  | 'gate_scope'
  | 'gate_circuit_open'
  | 'plan_not_found'
  | 'token_missing'
  | 'token_not_branded'
  | 'capability_not_registered'
  | 'request_invalid'
  | 'target_host_invalid'
  | 'dns_resolution_failed';

export interface AttackCapabilityExecutionResult {
  readonly outcome: AttackStepExecutionOutcome;
  readonly reasonCode: string;
  readonly safeMessage: string;
  readonly evidenceId?: string;
}

export interface AttackCapabilityIdentityRef {
  readonly identityId: string;
  readonly headers?: Readonly<Record<string, string>>;
}

export interface AttackCapabilityInvocationContext {
  readonly plan: AttackPlan;
  readonly step: AttackExecutionStep;
  readonly token: AttackAuthorizationToken;
  readonly targetHost: string;
  readonly targetUrl: string;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly findings: readonly Finding[];
  /** Optional primary (resource-owner) identity for differential capabilities. */
  readonly primaryIdentity?: AttackCapabilityIdentityRef;
  /** Optional secondary (cross-identity) identity for differential capabilities. */
  readonly secondaryIdentity?: AttackCapabilityIdentityRef;
  /**
   * Runtime-branded authorization decision required by detection-backed capabilities
   * (CORS / auth bypass / JWT). Missing → fail closed (never synthetic success).
   * MUST be the WeakSet-sealed object from establishVerifiedAuthorizationDecision /
   * assessment getRuntimeVerifiedAuthorizationDecision — never a JSON lookalike.
   */
  readonly verifiedAuthorizationDecision?: VerifiedAuthorizationDecision;
  /**
   * Optional hermetic HTTP transport for detection-backed capabilities.
   * In-process function reference only (not serializable).
   */
  readonly transport?: IdorHttpProbeTransport;
  /** Optional DNS resolver for detection preflight. */
  readonly dnsResolver?: PreSpawnDnsResolver;
  /** Milestone A11 — credential reference for credential_reuse capability. */
  readonly credentialReference?: CredentialReference;
  /** Milestone A11 — vault override for credential_reuse (else capability-bound). */
  readonly credentialVaultService?: CredentialVaultService;
}

/**
 * Port wrapping an existing verified defensive capability.
 * Implementations MUST NOT invent exploitation — they delegate to verified services.
 */
export interface AttackCapabilityPort {
  readonly capability: AttackCapabilityKind;
  execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult>;
}

export interface AttackStepExecutionRecord {
  readonly stepId: string;
  readonly ordinal: number;
  readonly capability: AttackCapabilityKind;
  readonly blastRadiusClass: AuthorizableBlastRadiusClass;
  readonly targetHost: string;
  readonly outcome: AttackStepExecutionOutcome;
  readonly reasonCode: string;
  readonly safeMessage: string;
  readonly gatesPassed: true | AttackExecutionGateFailureCode;
  readonly verificationStateBefore?: VerificationState;
  readonly verificationStateAfter?: VerificationState;
  readonly evidenceId?: string;
  readonly completedAt: string;
}

export interface AttackExecutionRecord {
  readonly contractVersion: AttackExecutionContractVersion;
  readonly kind: 'attack_execution_record';
  readonly executionId: string;
  readonly planId: string;
  readonly assessmentId: string;
  readonly capability: AttackCapabilityKind;
  readonly operatorId: string;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly status: 'completed' | 'preflight_denied' | 'failed';
  readonly stepRecords: readonly AttackStepExecutionRecord[];
  readonly updatedFindings: readonly Finding[];
}

export interface AttackExecutionRequest {
  readonly contractVersion: AttackExecutionContractVersion;
  readonly kind: 'attack_execution_request';
  readonly planId: string;
  readonly assessmentId: string;
  readonly token: AttackAuthorizationToken;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly coordinator: TargetExecutionCoordinator;
  readonly dnsResolver: PreSpawnDnsResolver;
  readonly findings: readonly Finding[];
  readonly operatorId: string;
  readonly executedAt?: string;
  readonly primaryIdentity?: AttackCapabilityIdentityRef;
  readonly secondaryIdentity?: AttackCapabilityIdentityRef;
  /** Runtime-branded decision for detection-backed capabilities (in-process WeakSet only). */
  readonly verifiedAuthorizationDecision?: VerifiedAuthorizationDecision;
  /** Optional hermetic HTTP transport forwarded to detection-backed capabilities. */
  readonly transport?: IdorHttpProbeTransport;
}

export type AttackExecutionResult =
  | {
      readonly status: 'completed';
      readonly reasonCode: 'attack_execution_completed';
      readonly record: AttackExecutionRecord;
    }
  | {
      readonly status: 'preflight_denied';
      readonly reasonCode: AttackExecutionGateFailureCode;
      readonly safeMessage: string;
      readonly record?: AttackExecutionRecord;
    }
  | {
      readonly status: 'failed';
      readonly reasonCode: AttackExecutionGateFailureCode | 'capability_execution_failed';
      readonly safeMessage: string;
      readonly record?: AttackExecutionRecord;
    };

/**
 * Scope host membership helper used as safety gate 6.
 * Fail-closed: empty/unsafe host or grant without matching host/domain/origin → false.
 */
export function isScopeAllowed(targetHost: string, scopeGrant: AuthorizedScopeGrant): boolean {
  if (typeof targetHost !== 'string' || targetHost.trim().length === 0) return false;
  const host = targetHost.trim().toLowerCase();

  const allowedHosts = scopeGrant.boundaries.allowedHosts;
  if (Array.isArray(allowedHosts) && allowedHosts.length > 0) {
    return allowedHosts.some((h) => typeof h === 'string' && h.toLowerCase() === host);
  }

  const allowedDomains = scopeGrant.boundaries.allowedDomains;
  if (Array.isArray(allowedDomains) && allowedDomains.length > 0) {
    return allowedDomains.some((d) => {
      if (typeof d !== 'string') return false;
      const domain = d.toLowerCase();
      return host === domain || host.endsWith(`.${domain}`);
    });
  }

  const allowedOrigins = scopeGrant.boundaries.allowedOrigins;
  if (Array.isArray(allowedOrigins) && allowedOrigins.length > 0) {
    return allowedOrigins.some((origin) => {
      if (typeof origin !== 'string') return false;
      try {
        return new URL(origin).hostname.toLowerCase() === host;
      } catch {
        return false;
      }
    });
  }

  const subject = scopeGrant.subject;
  if (subject.targetKind === 'host' && typeof subject.host === 'string') {
    return subject.host.toLowerCase() === host;
  }
  if (subject.targetKind === 'domain' && typeof subject.domain === 'string') {
    const domain = subject.domain.toLowerCase();
    return host === domain || host.endsWith(`.${domain}`);
  }
  if (subject.targetKind === 'origin' && typeof subject.normalizedOrigin === 'string') {
    try {
      return new URL(subject.normalizedOrigin).hostname.toLowerCase() === host;
    } catch {
      return false;
    }
  }

  return false;
}
