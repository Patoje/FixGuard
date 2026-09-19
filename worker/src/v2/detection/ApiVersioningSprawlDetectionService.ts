/**
 * Milestone P5-2 — API Versioning Sprawl Detection Engine
 *
 * Probes whether older, unmaintained API versions (/v1 vs /v2) remain publicly accessible
 * without the authorization controls enforced on current endpoints.
 *
 * Strict Invariants:
 * - Read-only inspection bounded to response status and body.
 * - 7-pass SSRF preflight protection blocking internal IP and metadata probing.
 * - Anti-leak evidence sanitization via sanitizeEvidenceFragment().
 * - Clean abstention (secure_target_abstained) when legacy endpoints return 404 or enforce identical auth.
 * - HITL Routing: Unattended runs produce pending_human_review with EvidenceDraftEnvelope.
 * - 0 occurrences of 'as any'.
 */

import type {
  ApiVersioningSprawlDetectionRequest,
  ApiVersioningSprawlDetectionResult,
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

export interface LegacyVersionCandidate {
  readonly legacyUrl: string;
  readonly legacyVersion: string;
  readonly currentVersion: string;
}

/**
 * Generates down-versioned candidate URLs from a given current API endpoint URL.
 */
export function generateLegacyVersionCandidates(currentUrl: string): LegacyVersionCandidate[] {
  const candidates: LegacyVersionCandidate[] = [];
  try {
    const parsed = new URL(currentUrl);
    const pathname = parsed.pathname;

    // Pattern 1: /api/v[2-9]/ or /api/v[2-9]$
    const apiVersionMatch = pathname.match(/(.*\/api\/)v([2-9])(\/.*|$)/i);
    if (apiVersionMatch) {
      const prefix = apiVersionMatch[1] ?? '/api/';
      const currentVerNum = parseInt(apiVersionMatch[2] ?? '2', 10);
      const suffix = apiVersionMatch[3] ?? '';

      for (let v = currentVerNum - 1; v >= 1; v--) {
        const legacyPath = `${prefix}v${v}${suffix}`;
        const u = new URL(currentUrl);
        u.pathname = legacyPath;
        candidates.push({
          legacyUrl: u.toString(),
          legacyVersion: `v${v}`,
          currentVersion: `v${currentVerNum}`,
        });
      }

      // Also unversioned variant: /api/...
      const unversionedPath = `${prefix.replace(/\/api\/$/, '/api')}${suffix.startsWith('/') ? suffix : `/${suffix}`}`.replace(/\/+/g, '/');
      const uUnv = new URL(currentUrl);
      uUnv.pathname = unversionedPath;
      if (uUnv.toString() !== currentUrl) {
        candidates.push({
          legacyUrl: uUnv.toString(),
          legacyVersion: 'v0_unversioned',
          currentVersion: `v${currentVerNum}`,
        });
      }
      return candidates;
    }

    // Pattern 2: /v[2-9]/ or /v[2-9]$
    const versionMatch = pathname.match(/(.*\/)v([2-9])(\/.*|$)/i);
    if (versionMatch) {
      const prefix = versionMatch[1] ?? '/';
      const currentVerNum = parseInt(versionMatch[2] ?? '2', 10);
      const suffix = versionMatch[3] ?? '';

      for (let v = currentVerNum - 1; v >= 1; v--) {
        const legacyPath = `${prefix}v${v}${suffix}`;
        const u = new URL(currentUrl);
        u.pathname = legacyPath;
        candidates.push({
          legacyUrl: u.toString(),
          legacyVersion: `v${v}`,
          currentVersion: `v${currentVerNum}`,
        });
      }
      return candidates;
    }

    // Fallback: If URL doesn't contain /v2/ but contains /api/, try /api/v1/
    if (pathname.includes('/api/')) {
      const u = new URL(currentUrl);
      u.pathname = pathname.replace('/api/', '/api/v1/');
      if (u.toString() !== currentUrl) {
        candidates.push({
          legacyUrl: u.toString(),
          legacyVersion: 'v1',
          currentVersion: 'current',
        });
      }
    }
  } catch {
    // Malformed URL handling
  }

  return candidates;
}

export async function runApiVersioningSprawlDetection(
  request: ApiVersioningSprawlDetectionRequest
): Promise<ApiVersioningSprawlDetectionResult> {
  const transport = request.transport ?? defaultHttpProbeTransport;
  const safeSeed = sanitizeToSafeId(request.detectionId);
  const lineage = {
    assessmentId: request.assessmentId,
    scanId: request.scanId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  // 1. SSRF Preflight for Current Endpoint
  const currentPreflight = await runAdapterPreflight({
    target: request.currentEndpointUrl,
    targetKind: 'url',
    verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
    authorizedScopeGrant: request.scopeGrant,
    lineage,
    permissionCheck: (ps) => Boolean(ps.endpointDiscovery || ps.lightValidation || ps.activeValidation),
    dnsResolver: request.dnsResolver,
  });

  if (!currentPreflight.ok) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'api_versioning_sprawl_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: currentPreflight.reasonCode,
      lineage,
      currentEndpointUrl: request.currentEndpointUrl,
      legacyEndpointUrl: '',
      currentStatusCode: 0,
      legacyStatusCode: 0,
      detectedVersions: [],
      unauthenticatedExposure: false,
      error: {
        code: currentPreflight.reasonCode,
        safeMessage: currentPreflight.reason ?? 'Current endpoint preflight denied',
      },
    };
  }

  // 2. Candidate Generation
  const candidates = generateLegacyVersionCandidates(request.currentEndpointUrl);
  if (candidates.length === 0) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'api_versioning_sprawl_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'no_versioning_candidates_identifiable',
      lineage,
      currentEndpointUrl: request.currentEndpointUrl,
      legacyEndpointUrl: '',
      currentStatusCode: 0,
      legacyStatusCode: 0,
      detectedVersions: [],
      unauthenticatedExposure: false,
    };
  }

  // 3. Probe Current Endpoint (to establish current status & auth posture)
  let currentStatusCode = 0;
  try {
    const headers: Record<string, string> = {
      Accept: 'application/json, text/plain, */*',
    };
    if (request.identityAContext?.cookies) {
      const cookieStr = Object.entries(request.identityAContext.cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join('; ');
      if (cookieStr.length > 0) headers['Cookie'] = cookieStr;
    }
    if (request.identityAContext?.headers) {
      for (const [k, v] of Object.entries(request.identityAContext.headers)) {
        if (typeof v === 'string') {
          headers[k] = v;
        }
      }
    }

    const currentResp = await transport({
      url: request.currentEndpointUrl,
      method: 'GET',
      headers,
      timeoutMs: 5000,
    });
    currentStatusCode = currentResp.statusCode;
  } catch (err) {
    // If current probe fails, return unexpected_failure
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'api_versioning_sprawl_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'current_endpoint_probe_failed',
      lineage,
      currentEndpointUrl: request.currentEndpointUrl,
      legacyEndpointUrl: '',
      currentStatusCode: 0,
      legacyStatusCode: 0,
      detectedVersions: [],
      unauthenticatedExposure: false,
      error: {
        code: 'current_endpoint_probe_failed',
        safeMessage: err instanceof Error ? err.message : 'Failed to probe current endpoint',
      },
    };
  }

  // 4. Probe Legacy Candidate URLs Unauthenticated
  for (const candidate of candidates) {
    const legacyPreflight = await runAdapterPreflight({
      target: candidate.legacyUrl,
      targetKind: 'url',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.scopeGrant,
      lineage,
      permissionCheck: (ps) => Boolean(ps.endpointDiscovery || ps.lightValidation || ps.activeValidation),
      dnsResolver: request.dnsResolver,
    });

    if (!legacyPreflight.ok) {
      continue; // Skip preflight denied candidates
    }

    let legacyResp: HttpProbeResponse | undefined;
    try {
      legacyResp = await transport({
        url: candidate.legacyUrl,
        method: 'GET',
        headers: {
          Accept: 'application/json, text/plain, */*',
        },
        timeoutMs: 5000,
      });
    } catch {
      continue; // Skip network failures for this candidate
    }

    const legacyStatusCode = legacyResp.statusCode;
    const legacyBody = legacyResp.bodyText ?? '';
    const isSuccess = legacyStatusCode >= 200 && legacyStatusCode < 300;
    const hasData = legacyBody.trim().length > 0;

    // Disparity Condition 1: Legacy returns 200 OK unauthenticated while Current enforces Auth (401/403)
    const isAuthDisparity = isSuccess && hasData && (currentStatusCode === 401 || currentStatusCode === 403);

    // Disparity Condition 2: Legacy returns 200 OK unauthenticated while Current is 200 (version sprawl)
    const isVersionSprawl = isSuccess && hasData && currentStatusCode === 200;

    if (isAuthDisparity || isVersionSprawl) {
      const unauthenticatedExposure = isAuthDisparity;
      const category = isAuthDisparity ? 'BROKEN_AUTHENTICATION' : 'SECURITY_MISCONFIGURATION';
      const severity = isAuthDisparity ? 'high' : 'low';
      const detectedVersions = [candidate.legacyVersion, candidate.currentVersion];

      const draftId = `dft_vsprawl_${safeSeed}`;
      const candidateId = `cnd_vsprawl_${safeSeed}`;
      const evidenceRecordId = `evd_vsprawl_${safeSeed}`;

      const sanitizedLegacyUrl = sanitizeEvidenceFragment(candidate.legacyUrl);
      const sanitizedCurrentUrl = sanitizeEvidenceFragment(request.currentEndpointUrl);

      // A. Human Review Decision Handling
      if (request.humanReviewDecision) {
        if (request.humanReviewDecision.decision === 'approve_evidence') {
          const finding: Finding = {
            id: `fnd_vsprawl_${safeSeed}`,
            type: category,
            severity,
            title: isAuthDisparity
              ? `Unauthenticated Legacy API Version Exposure (${candidate.legacyVersion}) on ${sanitizedLegacyUrl}`
              : `Deprecated API Versioning Sprawl (${candidate.legacyVersion} vs ${candidate.currentVersion}) on ${sanitizedLegacyUrl}`,
            description: isAuthDisparity
              ? `Legacy API endpoint '${sanitizedLegacyUrl}' (${candidate.legacyVersion}) responds with 200 OK without authentication, while current version '${sanitizedCurrentUrl}' (${candidate.currentVersion}) enforces HTTP ${currentStatusCode} authorization.`
              : `Legacy API endpoint '${sanitizedLegacyUrl}' (${candidate.legacyVersion}) remains accessible alongside current endpoint '${sanitizedCurrentUrl}' (${candidate.currentVersion}), increasing maintenance attack surface.`,
            target: candidate.legacyUrl,
            evidence: JSON.stringify({
              currentEndpointUrl: sanitizedCurrentUrl,
              legacyEndpointUrl: sanitizedLegacyUrl,
              currentStatusCode,
              legacyStatusCode,
              detectedVersions,
              unauthenticatedExposure,
              bodySampleSnippet: sanitizeEvidenceFragment(legacyBody.slice(0, 200)),
            }),
            confidence: isAuthDisparity ? 0.95 : 0.75,
            verificationState: 'observed_anomaly',
            metadata: {
              kind: 'api_versioning_sprawl_metadata',
              category,
              currentEndpointUrl: candidate.legacyUrl,
              legacyEndpointUrl: candidate.legacyUrl,
              currentStatusCode,
              legacyStatusCode,
              detectedVersions,
              unauthenticatedExposure,
              observedAt: new Date().toISOString(),
              candidateId,
              evidenceRecordId,
              lineage,
            },
          };

          return {
            contractVersion: DETECTION_CONTRACT_VERSION,
            kind: 'api_versioning_sprawl_detection_result',
            detectionId: request.detectionId,
            scanId: request.scanId,
            assessmentId: request.assessmentId,
            authorizationGrantId: request.authorizationGrantId,
            authorizationDecisionId: request.authorizationDecisionId,
            actorId: request.actorId,
            status: isAuthDisparity ? 'vulnerability_detected' : 'potential_weakness',
            reasonCode: isAuthDisparity
              ? 'unauthenticated_legacy_api_version_exposed'
              : 'api_versioning_sprawl_detected',
            lineage,
            currentEndpointUrl: request.currentEndpointUrl,
            legacyEndpointUrl: candidate.legacyUrl,
            currentStatusCode,
            legacyStatusCode,
            detectedVersions,
            unauthenticatedExposure,
            finding,
          };
        }

        // Rejected by human operator
        return {
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'api_versioning_sprawl_detection_result',
          detectionId: request.detectionId,
          scanId: request.scanId,
          assessmentId: request.assessmentId,
          authorizationGrantId: request.authorizationGrantId,
          authorizationDecisionId: request.authorizationDecisionId,
          actorId: request.actorId,
          status: 'secure_target_abstained',
          reasonCode: 'human_operator_rejected_sprawl_draft',
          lineage,
          currentEndpointUrl: request.currentEndpointUrl,
          legacyEndpointUrl: candidate.legacyUrl,
          currentStatusCode,
          legacyStatusCode,
          detectedVersions,
          unauthenticatedExposure,
        };
      }

      // B. Unattended Run -> Evidence Draft for HITL operator
      const nowIso = new Date().toISOString();
      const evidenceDraft: EvidenceDraftEnvelope = {
        draftKind: 'non_persisted_comparison_evidence_draft',
        draftId,
        suggestedEvidenceType: 'http_difference',
        suggestedStrength: isAuthDisparity ? 'strong' : 'moderate',
        sourceComparisonId: `cmp_vsprawl_${safeSeed}`,
        sourceSnapshotIds: {
          baselineSnapshotId: `snp_curr_${safeSeed}`,
          validationSnapshotId: `snp_leg_${safeSeed}`,
        },
        requiresHumanReview: true,
        notPersisted: true,
        notARealFinding: true,
        notConfirmedEvidence: true,
        notForExternalDelivery: true,
        notM45EvidenceRecord: true,
        safeRationale: isAuthDisparity
          ? `Legacy API version '${candidate.legacyVersion}' at ${sanitizedLegacyUrl} responds with 200 OK without authentication while ${candidate.currentVersion} requires authentication (${currentStatusCode}).`
          : `Legacy API version '${candidate.legacyVersion}' at ${sanitizedLegacyUrl} remains exposed alongside current version ${candidate.currentVersion}.`,
      };

      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'api_versioning_sprawl_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'pending_human_review',
        reasonCode: isAuthDisparity
          ? 'unauthenticated_legacy_api_version_pending_review'
          : 'api_versioning_sprawl_pending_review',
        lineage,
        currentEndpointUrl: request.currentEndpointUrl,
        legacyEndpointUrl: candidate.legacyUrl,
        currentStatusCode,
        legacyStatusCode,
        detectedVersions,
        unauthenticatedExposure,
        evidenceDraft,
      };
    }
  }

  // 5. Clean Abstention
  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'api_versioning_sprawl_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'secure_target_abstained',
    reasonCode: 'legacy_api_versions_inaccessible_or_unexposed',
    lineage,
    currentEndpointUrl: request.currentEndpointUrl,
    legacyEndpointUrl: '',
    currentStatusCode,
    legacyStatusCode: 0,
    detectedVersions: [],
    unauthenticatedExposure: false,
  };
}
