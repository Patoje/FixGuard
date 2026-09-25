/**
 * Plan A Fase 6 lite — Supabase Storage / signed-URL probe contracts.
 * Discovery/detection-only. Never mints signed URLs (no POST /object/sign).
 * Caller supplies OBSERVED storage paths; never invents bucket names as findings.
 */

import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type {
  AuthorizedExecutionLineageTuple,
  IdorHttpProbeTransport,
} from '../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';

export const SUPABASE_STORAGE_SIGNED_URL_PROBE_CONTRACT_VERSION =
  'fixguard-supabase-storage-signed-url-probe/v0' as const;
export type SupabaseStorageSignedUrlProbeContractVersion =
  typeof SUPABASE_STORAGE_SIGNED_URL_PROBE_CONTRACT_VERSION;

export type SupabaseStorageProbeStatus =
  | 'public_object_observed'
  | 'secure_target_abstained'
  | 'preflight_denied'
  | 'prerequisite_missing'
  | 'unexpected_failure';

export type SupabaseStorageClaimKind =
  | 'SUPABASE_STORAGE_PUBLIC_OBJECT'
  | 'SUPABASE_STORAGE_BUCKET_LIST_OPEN';

export interface SupabaseStorageObjectObservation {
  readonly objectPath: string;
  readonly requestUrl: string;
  readonly statusCode: number;
  readonly bodyHash: string;
  readonly contentTypeHint?: string;
  readonly claimKind: SupabaseStorageClaimKind;
  readonly publicReadable: boolean;
}

export interface SupabaseStorageSignedUrlProbeRequest {
  readonly contractVersion: SupabaseStorageSignedUrlProbeContractVersion;
  readonly kind: 'supabase_storage_signed_url_probe_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  /** Absolute storage base, e.g. https://xyz.supabase.co/storage/v1 */
  readonly storageBaseUrl: string;
  /** OBSERVED anon/publishable key — in-process only. */
  readonly anonApiKey: string;
  /**
   * OBSERVED object paths: "bucket/key" or "/object/public/bucket/key".
   * Never invents paths.
   */
  readonly objectPaths: readonly string[];
  /** Optional: probe GET /bucket (list) with anon — observation only. */
  readonly probeBucketList?: boolean;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly timeoutMs?: number;
  readonly maxObjects?: number;
}

export interface SupabaseStorageSignedUrlProbeResult {
  readonly contractVersion: SupabaseStorageSignedUrlProbeContractVersion;
  readonly kind: 'supabase_storage_signed_url_probe_result';
  readonly detectionId: string;
  readonly status: SupabaseStorageProbeStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly storageBaseUrl: string;
  readonly observations: readonly SupabaseStorageObjectObservation[];
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}
