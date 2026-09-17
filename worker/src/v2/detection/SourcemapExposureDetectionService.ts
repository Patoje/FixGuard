/**
 * Milestone P4-3 — Sourcemap Exposure Detection Engine
 *
 * Targets Single-Page Applications (SPA) and modern web frontends:
 * - Detects accessible .js.map files that expose frontend source code and internal API surfaces.
 * - Inspects //# sourceMappingURL= comments, SourceMap: / X-SourceMap: HTTP headers, or deterministic .map paths.
 * - Verifies accessibility via 7-pass SSRF preflight and validates JSON format ("version", "sources", "mappings").
 * - Returns status: 'potential_weakness' and category: 'INFORMATION_DISCLOSURE'.
 * - Cleanly abstains (secure_target_abstained) when .map files are 404/403 or invalid JSON.
 */

import type {
  SourcemapExposureDetectionRequest,
  SourcemapExposureDetectionResult,
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from './DetectionContracts.js';
import { DETECTION_CONTRACT_VERSION } from './DetectionContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import { defaultHttpProbeTransport } from './IdorDifferentialDetectionService.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : '001';
}

function resolveMapUrl(sourceJsUrl: string, candidatePath: string): string | null {
  try {
    const parsed = new URL(candidatePath, sourceJsUrl);
    return parsed.toString();
  } catch {
    return null;
  }
}

export function extractSourcemapUrlAndSignal(
  sourceJsUrl: string,
  explicitMapUrl?: string,
  jsBodyText?: string,
  jsHeaders?: Readonly<Record<string, string>>
): { mapUrl: string; signal: 'sourcemapping_url_comment' | 'sourcemap_header' | 'deterministic_path_probe' } | null {
  // 1. Explicitly provided map URL
  if (explicitMapUrl) {
    const resolved = resolveMapUrl(sourceJsUrl, explicitMapUrl);
    if (resolved) {
      return { mapUrl: resolved, signal: 'deterministic_path_probe' };
    }
  }

  // 2. HTTP Response Headers: SourceMap or X-SourceMap
  if (jsHeaders) {
    for (const [k, v] of Object.entries(jsHeaders)) {
      if (k.toLowerCase() === 'sourcemap' || k.toLowerCase() === 'x-sourcemap') {
        if (v && typeof v === 'string' && v.trim().length > 0) {
          const resolved = resolveMapUrl(sourceJsUrl, v.trim());
          if (resolved) {
            return { mapUrl: resolved, signal: 'sourcemap_header' };
          }
        }
      }
    }
  }

  // 3. JavaScript Body Comments: //# sourceMappingURL=... or /*# sourceMappingURL=... */
  if (jsBodyText && jsBodyText.length > 0) {
    const commentMatch =
      jsBodyText.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/i) ??
      jsBodyText.match(/\/\*[#@]\s*sourceMappingURL=([^\s'"]+)\s*\*\//i);

    if (commentMatch && commentMatch[1]) {
      const trimmed = commentMatch[1].trim();
      // Exclude data: URIs (inline sourcemaps)
      if (!trimmed.startsWith('data:')) {
        const resolved = resolveMapUrl(sourceJsUrl, trimmed);
        if (resolved) {
          return { mapUrl: resolved, signal: 'sourcemapping_url_comment' };
        }
      }
    }
  }

  // 4. Deterministic fallback: append .map to sourceJsUrl
  const deterministicUrl = `${sourceJsUrl.split('?')[0]}.map`;
  return { mapUrl: deterministicUrl, signal: 'deterministic_path_probe' };
}

export async function runSourcemapExposureDetection(
  request: SourcemapExposureDetectionRequest
): Promise<SourcemapExposureDetectionResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const safeSeed = sanitizeToSafeId(request.detectionId);
  const nowIso = new Date().toISOString();

  // 1. Resolve Sourcemap Target URL & Extraction Signal
  const extracted = extractSourcemapUrlAndSignal(
    request.sourceJsUrl,
    request.exposedMapUrl,
    request.jsBodyText,
    request.jsHeaders
  );

  if (!extracted) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'sourcemap_exposure_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'no_sourcemap_target_resolved',
      lineage,
      sourceJsUrl: request.sourceJsUrl,
    };
  }

  const { mapUrl: targetMapUrl, signal: detectionSignal } = extracted;

  // 2. 7-Pass Preflight Pipeline on targetMapUrl
  const preflight = await runAdapterPreflight({
    target: targetMapUrl,
    targetKind: 'url',
    verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
    authorizedScopeGrant: request.scopeGrant,
    lineage,
    permissionCheck: (ps) => Boolean(ps.endpointDiscovery || ps.lightValidation || ps.activeValidation),
    dnsResolver: request.dnsResolver,
  });

  if (!preflight.ok) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'sourcemap_exposure_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: preflight.reasonCode,
      lineage,
      sourceJsUrl: request.sourceJsUrl,
      exposedMapUrl: targetMapUrl,
      detectionSignal,
      error: {
        code: preflight.reasonCode,
        safeMessage: `Preflight denied: ${preflight.reasonCode}`,
      },
    };
  }

  // 3. Dispatch Verification Probe
  const transport = request.transport ?? defaultHttpProbeTransport;
  const probeReq: HttpProbeRequest = {
    url: targetMapUrl,
    method: 'GET',
    headers: {
      accept: 'application/json, text/javascript, */*',
      'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
    },
    timeoutMs: 5000,
  };

  let probeResponse: HttpProbeResponse;
  try {
    probeResponse = await transport(probeReq);
  } catch (err) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'sourcemap_exposure_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'sourcemap_probe_failed',
      lineage,
      sourceJsUrl: request.sourceJsUrl,
      exposedMapUrl: targetMapUrl,
      detectionSignal,
      error: {
        code: 'sourcemap_probe_failed',
        safeMessage: err instanceof Error ? err.message : 'Sourcemap probe failed',
      },
    };
  }

  // 4. Evaluate Response (Must be 200 OK and valid Sourcemap JSON)
  if (probeResponse.statusCode < 200 || probeResponse.statusCode >= 300 || probeResponse.bodyText.trim().length === 0) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'sourcemap_exposure_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'sourcemap_not_accessible',
      lineage,
      sourceJsUrl: request.sourceJsUrl,
      exposedMapUrl: targetMapUrl,
      detectionSignal,
    };
  }

  let sampleSourcesCount: number | undefined;
  let sampleSources: string[] = [];
  try {
    const parsed = JSON.parse(probeResponse.bodyText) as Record<string, unknown>;
    const hasVersion = typeof parsed.version === 'number' || typeof parsed.version === 'string';
    const hasSources = Array.isArray(parsed.sources);
    const hasMappings = typeof parsed.mappings === 'string';

    if (!hasVersion && !hasSources && !hasMappings) {
      // HTML 404 error page or non-sourcemap payload returned with 200 OK
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'sourcemap_exposure_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'secure_target_abstained',
        reasonCode: 'non_sourcemap_payload',
        lineage,
        sourceJsUrl: request.sourceJsUrl,
        exposedMapUrl: targetMapUrl,
        detectionSignal,
      };
    }

    if (hasSources && Array.isArray(parsed.sources)) {
      sampleSourcesCount = parsed.sources.length;
      sampleSources = parsed.sources
        .filter((s): s is string => typeof s === 'string')
        .slice(0, 5);
    }
  } catch {
    // Non-JSON body (e.g. text/html soft 404)
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'sourcemap_exposure_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'invalid_sourcemap_json',
      lineage,
      sourceJsUrl: request.sourceJsUrl,
      exposedMapUrl: targetMapUrl,
      detectionSignal,
    };
  }

  const mapFileSizeBytes = probeResponse.bodyText.length;
  let parsedMapPath = '/';
  try {
    parsedMapPath = new URL(targetMapUrl).pathname;
  } catch {
    // fallback
  }

  // 5. Human Review Routing & Finding Construction
  const draftId = `dft_smap_${safeSeed}`;
  const candidateId = `cnd_smap_${safeSeed}`;
  const evidenceRecordId = `evd_smap_${safeSeed}`;

  if (request.humanReviewDecision) {
    if (request.humanReviewDecision.decision === 'approve_evidence') {
      const finding: Finding = {
        id: `fnd_smap_${safeSeed}`,
        type: 'INFORMATION_DISCLOSURE',
        severity: 'medium',
        title: `Exposed JavaScript Source Map on ${parsedMapPath}`,
        description: `Target application exposes source map file '${targetMapUrl}' containing ${sampleSourcesCount ?? 'multiple'} source files (${mapFileSizeBytes} bytes), disclosing frontend architectural logic and internal API routes.`,
        target: targetMapUrl,
        evidence: sanitizeEvidenceFragment(
          JSON.stringify({
            exposedMapUrl: targetMapUrl,
            sourceJsUrl: request.sourceJsUrl,
            detectionSignal,
            mapFileSizeBytes,
            sampleSourcesCount,
            sampleSources,
            reviewedBy: request.humanReviewDecision.reviewerId,
            reviewedAt: request.humanReviewDecision.reviewedAt,
          })
        ),
        confidence: 0.95,
        metadata: {
          kind: 'sourcemap_exposure_metadata',
          category: 'INFORMATION_DISCLOSURE',
          exposedMapUrl: targetMapUrl,
          sourceJsUrl: request.sourceJsUrl,
          detectionSignal,
          mapFileSizeBytes,
          sampleSourcesCount,
          observedAt: nowIso,
          candidateId,
          evidenceRecordId,
          lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}`,
        },
      };

      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'sourcemap_exposure_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'potential_weakness',
        reasonCode: 'sourcemap_exposure_confirmed',
        lineage,
        sourceJsUrl: request.sourceJsUrl,
        exposedMapUrl: targetMapUrl,
        detectionSignal,
        mapFileSizeBytes,
        sampleSourcesCount,
        finding,
      };
    }

    if (request.humanReviewDecision.decision === 'reject') {
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'sourcemap_exposure_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'secure_target_abstained',
        reasonCode: 'human_review_rejected',
        lineage,
        sourceJsUrl: request.sourceJsUrl,
        exposedMapUrl: targetMapUrl,
        detectionSignal,
      };
    }
  }

  // 6. Unreviewed -> Produce EvidenceDraftEnvelope for HITL Triage
  const evidenceDraft: EvidenceDraftEnvelope = {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId,
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: 'moderate',
    sourceComparisonId: `cmp_smap_${safeSeed}`,
    sourceSnapshotIds: {
      baselineSnapshotId: `snp_smap_${safeSeed}_base`,
      validationSnapshotId: `snp_smap_${safeSeed}_val`,
    },
    requiresHumanReview: true,
    notPersisted: true,
    notARealFinding: true,
    notConfirmedEvidence: true,
    notForExternalDelivery: true,
    notM45EvidenceRecord: true,
    safeRationale: `Target application exposed source map ${targetMapUrl} (${mapFileSizeBytes} bytes, ${sampleSourcesCount ?? 0} sources) via signal '${detectionSignal}'`,
  };

  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'sourcemap_exposure_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'pending_human_review',
    reasonCode: 'sourcemap_exposure_observed',
    lineage,
    sourceJsUrl: request.sourceJsUrl,
    exposedMapUrl: targetMapUrl,
    detectionSignal,
    mapFileSizeBytes,
    sampleSourcesCount,
    evidenceDraft,
  };
}

export class SourcemapExposureDetectionService {
  public async execute(
    request: SourcemapExposureDetectionRequest
  ): Promise<SourcemapExposureDetectionResult> {
    return runSourcemapExposureDetection(request);
  }
}
