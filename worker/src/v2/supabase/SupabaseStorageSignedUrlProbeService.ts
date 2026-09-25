/**
 * Plan A Fase 6 lite — Supabase Storage / public-object probe.
 *
 * GETs OBSERVED /object/public/{path} with anon key. Optionally lists /bucket.
 * Never POSTs to create signed URLs. Never fabricates Critical findings.
 */

import { createHash } from 'node:crypto';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import { defaultHttpProbeTransport } from '../detection/IdorDifferentialDetectionService.js';
import { buildPostgrestHeaders } from './adapters/PostgrestHttpTransportAdapter.js';
import {
  SUPABASE_STORAGE_SIGNED_URL_PROBE_CONTRACT_VERSION,
  type SupabaseStorageObjectObservation,
  type SupabaseStorageSignedUrlProbeRequest,
  type SupabaseStorageSignedUrlProbeResult,
} from './SupabaseStorageSignedUrlProbeContracts.js';

function sha256(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

function normalizeObjectPath(raw: string): string | undefined {
  let p = raw.trim();
  if (p.length === 0 || p.length > 512) return undefined;
  // Strip absolute URL → path
  try {
    if (/^https?:\/\//i.test(p)) {
      const u = new URL(p);
      p = u.pathname;
    }
  } catch {
    return undefined;
  }
  p = p.replace(/^\/+/, '');
  // Accept object/public/bucket/key or bucket/key
  if (p.startsWith('object/public/')) {
    p = p.slice('object/public/'.length);
  } else if (p.startsWith('storage/v1/object/public/')) {
    p = p.slice('storage/v1/object/public/'.length);
  }
  if (!/^[A-Za-z0-9_./-]+$/.test(p) || !p.includes('/')) return undefined;
  return p;
}

function contentTypeHint(headers: Readonly<Record<string, string>>): string | undefined {
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === 'content-type' && v.trim().length > 0) {
      return v.trim().slice(0, 80);
    }
  }
  return undefined;
}

export async function runSupabaseStorageSignedUrlProbe(
  request: SupabaseStorageSignedUrlProbeRequest
): Promise<SupabaseStorageSignedUrlProbeResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const deny = (
    status: SupabaseStorageSignedUrlProbeResult['status'],
    reasonCode: string,
    safeMessage: string
  ): SupabaseStorageSignedUrlProbeResult => ({
    contractVersion: SUPABASE_STORAGE_SIGNED_URL_PROBE_CONTRACT_VERSION,
    kind: 'supabase_storage_signed_url_probe_result',
    detectionId: request.detectionId,
    status,
    reasonCode,
    lineage,
    storageBaseUrl: request.storageBaseUrl,
    observations: Object.freeze([]),
    error: { code: reasonCode, safeMessage },
  });

  const anonKey = request.anonApiKey.trim();
  if (anonKey.length < 20) {
    return deny(
      'prerequisite_missing',
      'anon_key_not_observed',
      'OBSERVED anon API key required for Storage probe'
    );
  }

  let storageBase = request.storageBaseUrl.trim().replace(/\/$/, '');
  if (!storageBase) {
    return deny(
      'prerequisite_missing',
      'storage_base_missing',
      'Storage base URL required'
    );
  }
  if (!/\/storage\/v1$/i.test(storageBase)) {
    // Allow project host → append /storage/v1
    try {
      const u = new URL(storageBase);
      storageBase = `${u.protocol}//${u.host}/storage/v1`;
    } catch {
      return deny(
        'prerequisite_missing',
        'storage_base_invalid',
        'Storage base URL invalid'
      );
    }
  }

  const normalizedPaths: string[] = [];
  const seen = new Set<string>();
  const maxObjects =
    typeof request.maxObjects === 'number' && request.maxObjects > 0
      ? Math.min(request.maxObjects, 8)
      : 5;
  for (const raw of request.objectPaths) {
    const n = normalizeObjectPath(raw);
    if (!n || seen.has(n)) continue;
    seen.add(n);
    normalizedPaths.push(n);
    if (normalizedPaths.length >= maxObjects) break;
  }

  if (normalizedPaths.length === 0 && request.probeBucketList !== true) {
    return deny(
      'prerequisite_missing',
      'storage_paths_not_observed',
      'OBSERVED storage object paths required (or probeBucketList=true)'
    );
  }

  const preflight = await runAdapterPreflight({
    target: `${storageBase}/`,
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
      Boolean(ps.passiveRecon || ps.endpointDiscovery || ps.lightValidation || ps.activeValidation),
    dnsResolver: request.dnsResolver,
  });

  if (!preflight.ok) {
    return deny(
      'preflight_denied',
      preflight.reasonCode,
      `Preflight denied: ${preflight.reasonCode}`
    );
  }

  const transport = request.transport ?? defaultHttpProbeTransport;
  const headers = buildPostgrestHeaders({ anonApiKey: anonKey });
  const timeoutMs = request.timeoutMs ?? 12_000;
  const observations: SupabaseStorageObjectObservation[] = [];

  for (const objectPath of normalizedPaths) {
    const requestUrl = `${storageBase}/object/public/${objectPath}`;
    try {
      const res = await transport({
        url: requestUrl,
        method: 'GET',
        headers,
        timeoutMs,
      });
      const bodyText = res.bodyText ?? '';
      const publicReadable =
        res.statusCode === 200 && bodyText.length > 0 && !/not\s+found|unauthorized|jwt/i.test(bodyText.slice(0, 200));
      observations.push({
        objectPath,
        requestUrl,
        statusCode: res.statusCode,
        bodyHash: sha256(bodyText),
        ...(contentTypeHint(res.headers) ? { contentTypeHint: contentTypeHint(res.headers) } : {}),
        claimKind: 'SUPABASE_STORAGE_PUBLIC_OBJECT',
        publicReadable,
      });
    } catch {
      observations.push({
        objectPath,
        requestUrl,
        statusCode: 0,
        bodyHash: sha256(''),
        claimKind: 'SUPABASE_STORAGE_PUBLIC_OBJECT',
        publicReadable: false,
      });
    }
  }

  if (request.probeBucketList === true) {
    const bucketUrl = `${storageBase}/bucket`;
    try {
      const res = await transport({
        url: bucketUrl,
        method: 'GET',
        headers,
        timeoutMs,
      });
      const bodyText = res.bodyText ?? '';
      const openList =
        res.statusCode === 200 &&
        (bodyText.trim().startsWith('[') || bodyText.trim().startsWith('{'));
      observations.push({
        objectPath: '(bucket-list)',
        requestUrl: bucketUrl,
        statusCode: res.statusCode,
        bodyHash: sha256(bodyText),
        ...(contentTypeHint(res.headers) ? { contentTypeHint: contentTypeHint(res.headers) } : {}),
        claimKind: 'SUPABASE_STORAGE_BUCKET_LIST_OPEN',
        publicReadable: openList,
      });
    } catch {
      // fail-soft on bucket list
    }
  }

  const publicHits = observations.filter((o) => o.publicReadable);
  if (publicHits.length > 0) {
    return {
      contractVersion: SUPABASE_STORAGE_SIGNED_URL_PROBE_CONTRACT_VERSION,
      kind: 'supabase_storage_signed_url_probe_result',
      detectionId: request.detectionId,
      status: 'public_object_observed',
      reasonCode: 'supabase_storage_public_readable_observed',
      lineage,
      storageBaseUrl: storageBase,
      observations: Object.freeze(observations),
    };
  }

  return {
    contractVersion: SUPABASE_STORAGE_SIGNED_URL_PROBE_CONTRACT_VERSION,
    kind: 'supabase_storage_signed_url_probe_result',
    detectionId: request.detectionId,
    status: 'secure_target_abstained',
    reasonCode:
      observations.length === 0
        ? 'no_storage_probes_executed'
        : 'no_public_storage_objects',
    lineage,
    storageBaseUrl: storageBase,
    observations: Object.freeze(observations),
  };
}
