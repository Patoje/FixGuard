/**
 * Milestone A5 / A7 / A8 / A9 — Attack Capability Registry
 *
 * Registers wrappers around EXISTING verified defensive services plus
 * native A7 capabilities (LFI path traversal, SQL oracle advancement),
 * A8 nuclei XSS scan (allowlisted templates only), and
 * A9 sqlmap error-based SQL injection verification (technique=E only).
 * Capabilities are authorized verification — not free exploitation.
 * Unregistered plan kinds fail closed (not-implemented), never fake success.
 */

import type { AttackCapabilityKind } from '../attack-planning/AttackPlanContracts.js';
import type {
  AttackCapabilityPort,
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
} from './AttackExecutionContracts.js';
import { ControlledActiveVerificationService } from '../verification/ControlledActiveVerificationService.js';
import { createLfiPathTraversalCapability } from './capabilities/LFIPathTraversalCapability.js';
import { createSqlOracleAdvancementCapability } from './capabilities/SqlOracleAdvancementCapability.js';
import { createNucleiXssScanCapability } from './capabilities/NucleiXssScanCapability.js';
import { createSqlInjectionVerificationCapability } from './capabilities/SqlInjectionVerificationCapability.js';
import { createCorsChainExploitCapability } from './capabilities/CorsChainExploitCapability.js';
import { createAuthBypassProbeCapability } from './capabilities/AuthBypassProbeCapability.js';
import { createJwtAlgNoneProbeCapability } from './capabilities/JwtAlgNoneProbeCapability.js';
import { createCredentialReuseCapability } from './capabilities/CredentialReuseCapability.js';
import { CredentialVaultService } from '../post-exploitation/CredentialVaultService.js';

function succeeded(reasonCode: string, safeMessage: string, evidenceId?: string): AttackCapabilityExecutionResult {
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

/**
 * IDOR differential read — invokes ControlledActiveVerificationService.execute().
 * Succeeds only when a real cross-identity differential is observed.
 * Refutes on 401/403/404 or denial. Fail-closed on missing identities / service errors.
 */
export function createIdorReadDifferentialCapability(
  service?: ControlledActiveVerificationService
): AttackCapabilityPort {
  const verificationService = service ?? new ControlledActiveVerificationService();
  return {
    capability: 'idor_read_differential',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.length === 0) {
        return failed('idor_target_missing', 'IDOR capability requires a target URL');
      }

      const primary = ctx.primaryIdentity;
      const secondary = ctx.secondaryIdentity;
      if (
        !primary ||
        typeof primary.identityId !== 'string' ||
        primary.identityId.trim().length === 0 ||
        !secondary ||
        typeof secondary.identityId !== 'string' ||
        secondary.identityId.trim().length === 0
      ) {
        return failed(
          'idor_identities_missing',
          'IDOR differential requires primaryIdentity and secondaryIdentity'
        );
      }

      const result = await verificationService.execute({
        targetUrl: ctx.targetUrl,
        primaryIdentity: {
          identityId: primary.identityId,
          ...(primary.headers ? { headers: primary.headers } : {}),
        },
        secondaryIdentity: {
          identityId: secondary.identityId,
          ...(secondary.headers ? { headers: secondary.headers } : {}),
        },
      });

      switch (result.status) {
        case 'differential_access_observed':
          return succeeded(
            'idor_differential_access_observed',
            result.evidenceSummary,
            `ev_idor_${ctx.step.stepId}`
          );
        case 'access_denied':
          return refuted(result.reasonCode, result.evidenceSummary);
        case 'preflight_denied':
          return failed(result.reasonCode, result.safeMessage);
        case 'failed':
          return failed(result.reasonCode, result.safeMessage);
        default: {
          const _exhaustive: never = result;
          return failed('idor_unexpected_result', `Unexpected IDOR execute result: ${JSON.stringify(_exhaustive)}`);
        }
      }
    },
  };
}

export class AttackCapabilityRegistry {
  private readonly ports = new Map<AttackCapabilityKind, AttackCapabilityPort>();

  constructor(ports?: readonly AttackCapabilityPort[]) {
    const initial =
      ports ??
      ([
        createIdorReadDifferentialCapability(),
        createCorsChainExploitCapability(),
        createAuthBypassProbeCapability(),
        createJwtAlgNoneProbeCapability(),
        createLfiPathTraversalCapability(),
        createSqlOracleAdvancementCapability(),
        createNucleiXssScanCapability(),
        createSqlInjectionVerificationCapability(),
        createCredentialReuseCapability({ vault: new CredentialVaultService() }),
      ] as const);
    for (const port of initial) {
      this.ports.set(port.capability, port);
    }
  }

  public get(capability: AttackCapabilityKind): AttackCapabilityPort | null {
    return this.ports.get(capability) ?? null;
  }

  public register(port: AttackCapabilityPort): void {
    this.ports.set(port.capability, port);
  }

  public static createDefault(): AttackCapabilityRegistry {
    return new AttackCapabilityRegistry();
  }
}

/** Fail-closed stub for plan kinds without a registered capability wrapper. */
export function createNotImplementedCapability(capability: AttackCapabilityKind): AttackCapabilityPort {
  return {
    capability,
    async execute(): Promise<AttackCapabilityExecutionResult> {
      return {
        outcome: 'capability_not_implemented',
        reasonCode: 'capability_not_implemented',
        safeMessage: `Capability "${capability}" is not registered for execution`,
      };
    },
  };
}

export { succeeded as capabilitySucceeded, refuted as capabilityRefuted, failed as capabilityFailed };
export { createCorsChainExploitCapability } from './capabilities/CorsChainExploitCapability.js';
export { createAuthBypassProbeCapability } from './capabilities/AuthBypassProbeCapability.js';
export { createJwtAlgNoneProbeCapability } from './capabilities/JwtAlgNoneProbeCapability.js';
export { createLfiPathTraversalCapability } from './capabilities/LFIPathTraversalCapability.js';
export { createSqlOracleAdvancementCapability } from './capabilities/SqlOracleAdvancementCapability.js';
export { createNucleiXssScanCapability } from './capabilities/NucleiXssScanCapability.js';
export { createSqlInjectionVerificationCapability } from './capabilities/SqlInjectionVerificationCapability.js';
export {
  createCredentialReuseCapability,
  attemptCredentialReuse,
} from './capabilities/CredentialReuseCapability.js';
