/**
 * Supabase RLS / Data API abuse detection contracts (Fase 2).
 */

import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type {
  AuthorizedExecutionLineageTuple,
  IdorHttpProbeTransport,
  ProbeAuthContext,
} from '../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { PostgrestTableProbePairResult } from './PostgrestTableProbeContracts.js';

export type SupabaseRlsAbuseDetectionContractVersion =
  'fixguard-supabase-rls-abuse-detection/v0';
export const SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION: SupabaseRlsAbuseDetectionContractVersion =
  'fixguard-supabase-rls-abuse-detection/v0';

export type SupabaseRlsAbuseDetectionStatus =
  | 'vulnerability_detected'
  | 'pending_human_review'
  | 'secure_target_abstained'
  | 'inconclusive_observation'
  | 'preflight_denied'
  | 'prerequisite_missing'
  | 'unexpected_failure';

export type SupabaseRlsAbuseClaimKind =
  | 'SUPABASE_RLS_WORLD_READABLE'
  | 'SUPABASE_RLS_INCONCLUSIVE';

export interface SupabaseRlsAbuseDetectionRequest {
  readonly contractVersion: SupabaseRlsAbuseDetectionContractVersion;
  readonly kind: 'supabase_rls_abuse_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly restBaseUrl: string;
  /** OBSERVED anon key — in-process only. */
  readonly anonApiKey: string;
  readonly tableNames: readonly string[];
  readonly authenticatedContext?: ProbeAuthContext;
  /** Optional precomputed probe pairs (skips re-probe when provided). */
  readonly probePairs?: readonly PostgrestTableProbePairResult[];
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface SupabaseRlsAbuseObservation {
  readonly tableName: string;
  readonly tableUrl: string;
  readonly claimKind: SupabaseRlsAbuseClaimKind;
  readonly anonStatusCode: number;
  readonly authenticatedStatusCode?: number;
  readonly anonBodyHash: string;
  readonly authenticatedBodyHash?: string;
  readonly anonIsJson: boolean;
  readonly topLevelJsonKeys: readonly string[];
  readonly rowCountHint: number | null;
  readonly anonEqualsAuth: boolean;
  readonly bodySnippet?: string;
}

export interface SupabaseRlsAbuseDetectionResult {
  readonly contractVersion: SupabaseRlsAbuseDetectionContractVersion;
  readonly kind: 'supabase_rls_abuse_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: SupabaseRlsAbuseDetectionStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly restBaseUrl: string;
  readonly observations: readonly SupabaseRlsAbuseObservation[];
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}
