/**
 * Milestone A11 — Lateral Movement Subsystem Contracts
 * Contract version: fixguard-lateral-movement/v0
 *
 * Four DISJOINT structural types — never collapsed into one status enum.
 * DiscoveredReachableHost ALWAYS has inScope: false (discovery ≠ authorization).
 * ActuallyAccessedTarget / SuccessfullyPivotedTarget use epistemicStatus VERIFIED
 * only when real access evidence exists.
 *
 * A10 LateralMovementHypothesis remains INFERRED until promoted through this subsystem.
 */

import type { CapabilityGained } from './AttackPlanContracts.js';
import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';

export type LateralMovementContractVersion = 'fixguard-lateral-movement/v0';
export const LATERAL_MOVEMENT_CONTRACT_VERSION: LateralMovementContractVersion =
  'fixguard-lateral-movement/v0';

export type LateralMovementMechanism =
  | 'credential_reuse'
  | 'session_token_reuse'
  | 'api_key_reuse'
  | 'oauth_token_scope'
  | 'shared_auth_backend'
  | 'cors_credential_relay'
  | 'trust_relationship'
  | 'subdomain_session_share';

export type LateralMovementRecordStatus =
  | 'pivot_complete'
  | 'access_confirmed'
  | 'access_denied'
  | 'unauthorized';

/**
 * Safe evidence summary for lateral-movement records.
 * No raw payloads, secrets, or executable fields.
 */
export interface AttackEvidence {
  readonly evidenceId: string;
  readonly reasonCode: string;
  readonly safeMessage: string;
  readonly recordedAt: string;
}

/**
 * Discovery-only host. MUST keep inScope: false.
 * Discovery never implies authorization or network permission.
 */
export interface DiscoveredReachableHost {
  readonly contractVersion: LateralMovementContractVersion;
  readonly kind: 'discovered_reachable_host';
  readonly hostname: string;
  readonly discoveredInStepId: string;
  readonly inScope: false;
  readonly discoveredAt: string;
}

/**
 * Explicitly authorized lateral target under an AuthorizedScopeGrant.
 * Promotion requires a real scope grant — never auto from discovery.
 */
export interface AuthorizedLateralTarget {
  readonly contractVersion: LateralMovementContractVersion;
  readonly kind: 'authorized_lateral_target';
  readonly hostname: string;
  readonly scopeGrantId: string;
  readonly authorizedAt: string;
  readonly authorizedBy: string;
}

/**
 * Confirmed access with real evidence. epistemicStatus is always VERIFIED.
 */
export interface ActuallyAccessedTarget {
  readonly contractVersion: LateralMovementContractVersion;
  readonly kind: 'actually_accessed_target';
  readonly hostname: string;
  readonly evidenceId: string;
  readonly epistemicStatus: 'VERIFIED';
  readonly accessedAt: string;
}

/**
 * Confirmed pivot with capability gained. epistemicStatus is always VERIFIED.
 */
export interface SuccessfullyPivotedTarget {
  readonly contractVersion: LateralMovementContractVersion;
  readonly kind: 'successfully_pivoted_target';
  readonly hostname: string;
  readonly capabilityGained: CapabilityGained;
  readonly epistemicStatus: 'VERIFIED';
  readonly pivotedAt: string;
}

export type LateralMovementTarget =
  | DiscoveredReachableHost
  | AuthorizedLateralTarget
  | ActuallyAccessedTarget
  | SuccessfullyPivotedTarget;

export interface LateralMovementRecord {
  readonly contractVersion: LateralMovementContractVersion;
  readonly kind: 'lateral_movement_record';
  readonly recordId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly mechanism: LateralMovementMechanism;
  readonly sourceHost: string;
  readonly destinationHost: string;
  readonly credentialRefId?: string;
  readonly status: LateralMovementRecordStatus;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly evidence: readonly AttackEvidence[];
  readonly recordedAt: string;
}

export interface LateralMovementSnapshot {
  readonly contractVersion: LateralMovementContractVersion;
  readonly kind: 'lateral_movement_snapshot';
  readonly assessmentId: string;
  readonly scanId: string;
  readonly discoveredHosts: readonly DiscoveredReachableHost[];
  readonly authorizedTargets: readonly AuthorizedLateralTarget[];
  readonly accessedTargets: readonly ActuallyAccessedTarget[];
  readonly pivotedTargets: readonly SuccessfullyPivotedTarget[];
  readonly records: readonly LateralMovementRecord[];
  readonly updatedAt: string;
}

export function isLateralMovementMechanism(value: unknown): value is LateralMovementMechanism {
  return (
    value === 'credential_reuse' ||
    value === 'session_token_reuse' ||
    value === 'api_key_reuse' ||
    value === 'oauth_token_scope' ||
    value === 'shared_auth_backend' ||
    value === 'cors_credential_relay' ||
    value === 'trust_relationship' ||
    value === 'subdomain_session_share'
  );
}
