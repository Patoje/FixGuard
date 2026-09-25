/**
 * PostgREST OpenAPI enumeration contracts (Fase 1).
 * GET /rest/v1/ Accept: application/openapi+json → relation inventory.
 */

import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedExecutionLineageTuple, IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import type {
  PostgrestExposedRelation,
  SupabaseEpistemicStatus,
} from './SupabaseSurfaceContracts.js';

export type PostgrestOpenApiEnumContractVersion = 'fixguard-postgrest-openapi-enum/v0';
export const POSTGREST_OPENAPI_ENUM_CONTRACT_VERSION: PostgrestOpenApiEnumContractVersion =
  'fixguard-postgrest-openapi-enum/v0';

export type PostgrestOpenApiEnumStatus =
  | 'inventory_observed'
  | 'openapi_unavailable'
  | 'preflight_denied'
  | 'unexpected_failure';

export interface PostgrestOpenApiEnumRequest {
  readonly contractVersion: PostgrestOpenApiEnumContractVersion;
  readonly kind: 'postgrest_openapi_enum_request';
  readonly enumId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  /** Absolute REST base, e.g. https://ref.supabase.co/rest/v1 */
  readonly restBaseUrl: string;
  /** OBSERVED anon key — in-process only; never copied into result DTOs. */
  readonly anonApiKey: string;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  /** Optional seed table names when OpenAPI is closed (from jsluice/URL OBSERVED). */
  readonly seedTableNames?: readonly string[];
}

export interface PostgrestOpenApiEnumResult {
  readonly contractVersion: PostgrestOpenApiEnumContractVersion;
  readonly kind: 'postgrest_openapi_enum_result';
  readonly enumId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: PostgrestOpenApiEnumStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly restBaseUrl: string;
  readonly relations: readonly PostgrestExposedRelation[];
  readonly inventoryEpistemicStatus: SupabaseEpistemicStatus;
  readonly openApiStatusCode?: number;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}
