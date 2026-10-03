/**
 * PostgREST table probe contracts (Fase 1).
 * GET /rest/v1/{table}?select=*&limit=1 — anon vs authenticated.
 */

import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type {
  AuthorizedExecutionLineageTuple,
  IdorHttpProbeTransport,
  ProbeAuthContext,
} from '../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';

export type PostgrestTableProbeContractVersion = 'fixguard-postgrest-table-probe/v0';
export const POSTGREST_TABLE_PROBE_CONTRACT_VERSION: PostgrestTableProbeContractVersion =
  'fixguard-postgrest-table-probe/v0';

export type PostgrestTableProbeStatus =
  | 'probe_completed'
  | 'preflight_denied'
  | 'batch_preflight_denied'
  | 'unexpected_failure';

export interface PostgrestTableProbeSnapshot {
  readonly roleHint: 'anon' | 'authenticated';
  readonly statusCode: number;
  readonly bodyHash: string;
  readonly contentType: string;
  readonly isJsonBody: boolean;
  readonly isHtmlBody: boolean;
  readonly topLevelJsonKeys: readonly string[];
  readonly rowCountHint: number | null;
  readonly bodySnippet?: string;
}

export interface PostgrestTableProbePairResult {
  readonly tableName: string;
  readonly tableUrl: string;
  readonly anon: PostgrestTableProbeSnapshot;
  readonly authenticated?: PostgrestTableProbeSnapshot;
}

export interface PostgrestTableProbeRequest {
  readonly contractVersion: PostgrestTableProbeContractVersion;
  readonly kind: 'postgrest_table_probe_request';
  readonly probeId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly restBaseUrl: string;
  readonly tableNames: readonly string[];
  /** OBSERVED anon key — in-process only. */
  readonly anonApiKey: string;
  /** Optional authenticated identity (BYOT user JWT). */
  readonly authenticatedContext?: ProbeAuthContext;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly maxTables?: number;
}

export interface PostgrestTableProbeResult {
  readonly contractVersion: PostgrestTableProbeContractVersion;
  readonly kind: 'postgrest_table_probe_result';
  readonly probeId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: PostgrestTableProbeStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly restBaseUrl: string;
  readonly pairs: readonly PostgrestTableProbePairResult[];
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}
