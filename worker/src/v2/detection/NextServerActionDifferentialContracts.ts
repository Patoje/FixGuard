/**
 * Plan A Fase 5 thin — Next.js Server Action differential contracts.
 * Discovery/detection-only. Never invents action IDs; caller supplies OBSERVED ids.
 */

import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type {
  AuthorizedExecutionLineageTuple,
  IdorHttpProbeTransport,
  ProbeAuthContext,
} from './DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';

export const NEXT_SERVER_ACTION_DIFF_CONTRACT_VERSION =
  'fixguard-next-server-action-diff/v0' as const;
export type NextServerActionDiffContractVersion =
  typeof NEXT_SERVER_ACTION_DIFF_CONTRACT_VERSION;

export type NextServerActionDiffStatus =
  | 'differential_observed'
  | 'secure_target_abstained'
  | 'preflight_denied'
  | 'prerequisite_missing'
  | 'unexpected_failure';

export interface NextServerActionDiffRequest {
  readonly contractVersion: NextServerActionDiffContractVersion;
  readonly kind: 'next_server_action_diff_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  /** Absolute page/action endpoint URL (OBSERVED). */
  readonly endpointUrl: string;
  /** Next-Action id (OBSERVED from RSC/network). */
  readonly actionId: string;
  /** Optional authenticated identity (BYOT). Compared vs unauth. */
  readonly authenticatedContext?: ProbeAuthContext;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly timeoutMs?: number;
  /** Optional minimal POST body (never secrets). */
  readonly bodyText?: string;
}

export interface NextServerActionDiffObservation {
  readonly unauthStatusCode: number;
  readonly authStatusCode?: number;
  readonly unauthBodyHash: string;
  readonly authBodyHash?: string;
  readonly actionAcceptedUnauth: boolean;
  readonly authzDifferential: boolean;
}

export interface NextServerActionDiffResult {
  readonly contractVersion: NextServerActionDiffContractVersion;
  readonly kind: 'next_server_action_diff_result';
  readonly detectionId: string;
  readonly status: NextServerActionDiffStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly endpointUrl: string;
  readonly actionIdRedacted: string;
  readonly observation?: NextServerActionDiffObservation;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}
