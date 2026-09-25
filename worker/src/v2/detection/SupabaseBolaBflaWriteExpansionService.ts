/**
 * Supabase BOLA/BFLA write expansion (Plan A Fase 4 / A4 thin).
 *
 * Runs authz-matrix write pairs (A↔B, unauth↔credentialed) as differential
 * canary POSTs against a Data API table URL. Fail-closed without mutation
 * scope. Never auto-creates Critical findings; observations are HITL-bound.
 *
 * Live: skip without two JWTs. Hermetic smoke covers gates + differentials.
 */

import { randomBytes } from 'node:crypto';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type {
  AuthorizedExecutionLineageTuple,
  IdorHttpProbeTransport,
  ProbeAuthContext,
} from './DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import { defaultHttpProbeTransport } from './IdorDifferentialDetectionService.js';
import { buildPostgrestHeaders } from '../supabase/adapters/PostgrestHttpTransportAdapter.js';
import {
  buildAuthzMatrixWritePairs,
  type AuthzMatrixWritePairKind,
} from './MultiIdentityAuthzMatrixService.js';

export const SUPABASE_BOLA_BFLA_WRITE_CONTRACT_VERSION =
  'fixguard-supabase-bola-bfla-write/v0' as const;
export type SupabaseBolaBflaWriteContractVersion =
  typeof SUPABASE_BOLA_BFLA_WRITE_CONTRACT_VERSION;

export type SupabaseBolaBflaWriteStatus =
  | 'differential_observed'
  | 'secure_target_abstained'
  | 'scope_denied'
  | 'preflight_denied'
  | 'prerequisite_missing'
  | 'unexpected_failure';

export interface SupabaseBolaBflaWritePairObservation {
  readonly pairKind: AuthzMatrixWritePairKind;
  readonly leftStatusCode: number;
  readonly rightStatusCode: number;
  readonly leftAcceptedWrite: boolean;
  readonly rightAcceptedWrite: boolean;
  /** Weaker/left identity accepted a write that right also (or alone) accepted. */
  readonly writeAuthzDifferential: boolean;
  readonly canaryMarker: string;
}

export interface SupabaseBolaBflaWriteExpansionRequest {
  readonly contractVersion: SupabaseBolaBflaWriteContractVersion;
  readonly kind: 'supabase_bola_bfla_write_expansion_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly tableUrl: string;
  /** OBSERVED anon key — in-process only. */
  readonly anonApiKey: string;
  readonly identityA: ProbeAuthContext;
  readonly identityB: ProbeAuthContext;
  readonly maxPairs?: number;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly timeoutMs?: number;
  /** Optional canary JSON body fields (never secrets). */
  readonly canaryBody?: Readonly<Record<string, string>>;
}

export interface SupabaseBolaBflaWriteExpansionResult {
  readonly contractVersion: SupabaseBolaBflaWriteContractVersion;
  readonly kind: 'supabase_bola_bfla_write_expansion_result';
  readonly detectionId: string;
  readonly status: SupabaseBolaBflaWriteStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly pairsExecuted: number;
  readonly pairObservations: readonly SupabaseBolaBflaWritePairObservation[];
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

function writeAccepted(statusCode: number): boolean {
  return statusCode === 200 || statusCode === 201;
}

function mergeHeaders(
  base: Record<string, string>,
  identity: ProbeAuthContext
): Record<string, string> {
  const out: Record<string, string> = { ...base };
  if (identity.headers) {
    for (const [k, v] of Object.entries(identity.headers)) {
      out[k] = v;
    }
  }
  return out;
}

function canaryMarker(): string {
  return `fg_bola_${randomBytes(6).toString('hex')}`;
}

export async function runSupabaseBolaBflaWriteExpansion(
  request: SupabaseBolaBflaWriteExpansionRequest
): Promise<SupabaseBolaBflaWriteExpansionResult> {
  const lineage: AuthorizedExecutionLineageTuple = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const deny = (
    status: SupabaseBolaBflaWriteStatus,
    reasonCode: string,
    safeMessage: string
  ): SupabaseBolaBflaWriteExpansionResult => ({
    contractVersion: SUPABASE_BOLA_BFLA_WRITE_CONTRACT_VERSION,
    kind: 'supabase_bola_bfla_write_expansion_result',
    detectionId: request.detectionId,
    status,
    reasonCode,
    lineage,
    pairsExecuted: 0,
    pairObservations: Object.freeze([]),
    error: { code: reasonCode, safeMessage },
  });

  if (!request.scopeGrant.constraints.allowStateChangingRequests) {
    return deny(
      'scope_denied',
      'state_changing_requests_denied',
      'Scope grant does not allow state-changing requests'
    );
  }

  const allowedMethods = request.scopeGrant.boundaries.allowedMethods ?? [];
  if (!allowedMethods.includes('POST')) {
    return deny(
      'scope_denied',
      'post_method_not_in_scope',
      'Scope grant boundaries do not include POST'
    );
  }

  const anonKey = request.anonApiKey.trim();
  if (anonKey.length < 20) {
    return deny(
      'prerequisite_missing',
      'anon_key_not_observed',
      'OBSERVED anon API key required for Data API write matrix'
    );
  }

  const tableUrl = request.tableUrl.trim();
  if (!tableUrl) {
    return deny(
      'prerequisite_missing',
      'table_url_missing',
      'Data API table URL required'
    );
  }

  const preflight = await runAdapterPreflight({
    target: tableUrl,
    targetKind: 'url',
    verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
    authorizedScopeGrant: request.scopeGrant,
    lineage: {
      assessmentId: request.assessmentId,
      scanId: request.scanId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
    },
    permissionCheck: (ps) =>
      Boolean(ps.activeValidation || ps.lightValidation || ps.authenticatedTesting),
    dnsResolver: request.dnsResolver,
  });

  if (!preflight.ok) {
    return deny(
      'preflight_denied',
      preflight.reasonCode,
      `Preflight denied: ${preflight.reasonCode}`
    );
  }

  const pairs = buildAuthzMatrixWritePairs(request.identityA, request.identityB);
  const maxPairs =
    typeof request.maxPairs === 'number' && request.maxPairs > 0
      ? Math.min(request.maxPairs, pairs.length)
      : pairs.length;

  const transport = request.transport ?? defaultHttpProbeTransport;
  const baseHeaders = buildPostgrestHeaders({ anonApiKey: anonKey });
  const observations: SupabaseBolaBflaWritePairObservation[] = [];
  let differentialCount = 0;

  for (const pair of pairs.slice(0, maxPairs)) {
    const marker = canaryMarker();
    const body = JSON.stringify({
      ...(request.canaryBody ?? {}),
      fg_canary: marker,
    });

    const leftHeaders = mergeHeaders(
      {
        ...baseHeaders,
        Prefer: 'return=minimal',
        'Content-Type': 'application/json',
      },
      pair.left
    );
    const rightHeaders = mergeHeaders(
      {
        ...baseHeaders,
        Prefer: 'return=minimal',
        'Content-Type': 'application/json',
      },
      pair.right
    );

    let leftStatus = 0;
    let rightStatus = 0;
    try {
      const leftRes = await transport({
        url: tableUrl,
        method: 'POST',
        headers: leftHeaders,
        body,
        timeoutMs: request.timeoutMs ?? 8_000,
      });
      leftStatus = leftRes.statusCode;
      const rightRes = await transport({
        url: tableUrl,
        method: 'POST',
        headers: rightHeaders,
        body: JSON.stringify({
          ...(request.canaryBody ?? {}),
          fg_canary: `${marker}_b`,
        }),
        timeoutMs: request.timeoutMs ?? 8_000,
      });
      rightStatus = rightRes.statusCode;
    } catch {
      observations.push({
        pairKind: pair.pairKind,
        leftStatusCode: leftStatus,
        rightStatusCode: rightStatus,
        leftAcceptedWrite: false,
        rightAcceptedWrite: false,
        writeAuthzDifferential: false,
        canaryMarker: marker,
      });
      continue;
    }

    const leftOk = writeAccepted(leftStatus);
    const rightOk = writeAccepted(rightStatus);
    // Differential: weaker/left can write while identities diverge, or unauth writes.
    const writeAuthzDifferential =
      (pair.pairKind.startsWith('unauth_') && leftOk) ||
      (pair.pairKind === 'identity_a_vs_b_write' && leftOk !== rightOk);

    if (writeAuthzDifferential) differentialCount += 1;

    observations.push({
      pairKind: pair.pairKind,
      leftStatusCode: leftStatus,
      rightStatusCode: rightStatus,
      leftAcceptedWrite: leftOk,
      rightAcceptedWrite: rightOk,
      writeAuthzDifferential,
      canaryMarker: marker,
    });
  }

  return {
    contractVersion: SUPABASE_BOLA_BFLA_WRITE_CONTRACT_VERSION,
    kind: 'supabase_bola_bfla_write_expansion_result',
    detectionId: request.detectionId,
    status:
      differentialCount > 0 ? 'differential_observed' : 'secure_target_abstained',
    reasonCode:
      differentialCount > 0
        ? 'write_authz_differential_observed'
        : 'no_write_authz_differential',
    lineage,
    pairsExecuted: observations.length,
    pairObservations: Object.freeze(observations),
  };
}
