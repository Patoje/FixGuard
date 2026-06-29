/**
 * EgressPolicyAuditContracts.ts
 *
 * Defines the sanitized control-plane audit event shape for M30 egress policy decisions.
 *
 * These events represent allow/block/candidate decisions as auditable control-plane records.
 * They are NOT findings, NOT evidence, NOT vulnerability claims, NOT risk scores.
 *
 * Forbidden fields (never appear in event payloads):
 *   - raw URLs with credentials / secrets
 *   - CapabilityRequest / ExecutionRequest / binary / args / env / shell / command / stdin
 *   - response bodies / request bodies / raw headers / cookies / authorization tokens
 *   - riskScore / severity / impact / exploit / payload / finding / scannerOutput
 */

/**
 * A sanitized egress policy audit event.
 *
 * eventKind is always "egress_policy_decision".
 * classification and safety flags make it structurally impossible to confuse
 * these events with findings, evidence, vulnerabilities, or risk claims.
 */
export interface EgressPolicyAuditEvent {
  readonly eventKind: 'egress_policy_decision';
  readonly eventVersion: 1;
  readonly eventId: string;
  readonly observedAt: string; // ISO 8601

  readonly capabilityId: string;
  readonly decision: 'allow' | 'block' | 'candidate';

  readonly target: {
    readonly safeDisplayUrl: string;
    readonly scheme?: 'http' | 'https';
    readonly hostname?: string;
    readonly normalizedOrigin?: string;
  };

  readonly policy: {
    readonly reason?: string;
    readonly blockReason?: string;
    readonly candidateReason?: string;
  };

  readonly scope?: {
    readonly safeAllowedOrigins?: string[];
    readonly sameHostPathsAllowed?: boolean;
    readonly subdomainsAllowed?: boolean;
  };

  /**
   * Structural classification flags.
   * These are literal `true`/`false` (not configurable) to make
   * it structurally impossible to mistake events for findings/evidence/vulnerabilities.
   */
  readonly classification: {
    readonly controlPlaneEvent: true;
    readonly finding: false;
    readonly evidence: false;
    readonly vulnerability: false;
    readonly riskClaim: false;
  };

  /**
   * Explicit safety assertions embedded in the event.
   * All values are literal `true`/`false`.
   */
  readonly safety: {
    readonly sensitiveValuesRedacted: true;
    readonly containsRawSecret: false;
    readonly rawRequestPersisted: false;
    readonly executablePayloadPersisted: false;
  };
}

/**
 * Result type returned when recording an event succeeds or is rejected.
 */
export type EgressPolicyAuditRecordResult =
  | { recorded: true; eventId: string }
  | { recorded: false; reason: string };
