/**
 * FixGuard V2 — Milestone P2-2 Open Redirect Detection Engine
 *
 * Implements high-precision active probing for unvalidated URL redirection vulnerabilities.
 * Employs safe canary targets (https://canary.fixguard.internal/) and enforces SSRF egress gates.
 *
 * Invariants:
 * - Employs safe, non-executable canary URLs.
 * - Inspects Location header across redirect status codes (301, 302, 303, 307, 308).
 * - SSRF egress gate validates that redirect destinations do not hop to private or metadata IP spaces.
 * - Routes unreviewed detections into pendingEvidenceDrafts for human triage.
 */

import { createHash } from 'node:crypto';
import type {
  OpenRedirectDetectionRequest,
  OpenRedirectDetectionResult,
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from './DetectionContracts.js';
import { DETECTION_CONTRACT_VERSION } from './DetectionContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import { isInternalOrSsrfTarget } from '../recon/policy/PassiveEgressPolicy.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import { validateSessionHealth } from '../core/SessionLifecycleService.js';
import { defaultHttpProbeTransport } from './IdorDifferentialDetectionService.js';
import type { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';

export const DEFAULT_CANARY_DESTINATION = 'https://canary.fixguard.internal/';

export const DEFAULT_REDIRECT_PARAMETERS: readonly string[] = [
  'redirect',
  'next',
  'url',
  'return',
  'dest',
  'return_to',
  'redirect_uri',
  'continue',
  'target',
  'to',
];

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : '001';
}

async function dispatchProbe(
  req: HttpProbeRequest,
  transport: IdorHttpProbeTransport,
  coordinator?: TargetExecutionCoordinator
): Promise<HttpProbeResponse> {
  if (coordinator) {
    const host = new URL(req.url).host;
    return coordinator.execute(host, () => transport(req));
  }
  return transport(req);
}

function isCanaryRedirection(location: string, canaryUrl: string): boolean {
  if (!location) return false;
  const trimmed = location.trim();
  if (trimmed === canaryUrl) return true;
  if (trimmed.startsWith(canaryUrl)) return true;

  try {
    const parsedCanary = new URL(canaryUrl);
    if (trimmed.startsWith(`//${parsedCanary.host}`)) return true;
    const parsedLoc = new URL(trimmed);
    return parsedLoc.hostname.toLowerCase() === parsedCanary.hostname.toLowerCase();
  } catch {
    return false;
  }
}

export async function runOpenRedirectDetection(
  request: OpenRedirectDetectionRequest
): Promise<OpenRedirectDetectionResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const safeSeed = sanitizeToSafeId(request.detectionId);
  const nowIso = new Date().toISOString();
  const canaryDestination = request.canaryDestination ?? DEFAULT_CANARY_DESTINATION;

  // 1. Adapter Preflight Pipeline Gate (7-pass check with SSRF / DNS rebinding prevention)
  const preflight = await runAdapterPreflight({
    target: request.endpointUrl,
    targetKind: 'url',
    verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
    authorizedScopeGrant: request.scopeGrant,
    lineage,
    permissionCheck: (ps) =>
      Boolean(ps.endpointDiscovery || ps.lightValidation || ps.activeValidation || ps.passiveRecon),
    dnsResolver: request.dnsResolver,
  });

  if (!preflight.ok) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'open_redirect_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: preflight.reasonCode,
      lineage,
      error: {
        code: preflight.reasonCode,
        safeMessage: `Preflight denied: ${preflight.reasonCode}`,
      },
    };
  }

  // 2. Prepare Base URL
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(request.endpointUrl);
  } catch {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'open_redirect_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: 'invalid_target_url',
      lineage,
      error: {
        code: 'invalid_target_url',
        safeMessage: 'Target URL is invalid',
      },
    };
  }

  const transport = request.transport ?? defaultHttpProbeTransport;
  const method = request.method ?? 'GET';

  // 3. Session Lifecycle Health Check
  let sessionHeaders: Record<string, string> = { ...(request.authContext?.headers ?? {}) };
  if (request.authContext?.cookies) {
    const cookieHeader = Object.entries(request.authContext.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    if (cookieHeader.length > 0) {
      sessionHeaders['cookie'] = cookieHeader;
    }
  }

  if (request.authContext?.sessionState) {
    const sessionHealth = await validateSessionHealth(request.authContext.sessionState, nowIso);
    if (!sessionHealth.ok) {
      const reason = sessionHealth.reasonCode ?? 'session_expired';
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'open_redirect_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'preflight_denied',
        reasonCode: reason,
        lineage,
        error: {
          code: reason,
          safeMessage: `Session health check failed: ${reason}`,
        },
      };
    }
    if (sessionHealth.updatedHeaders) {
      sessionHeaders = { ...sessionHeaders, ...sessionHealth.updatedHeaders };
    }
  }

  // 4. Candidate Parameter Enumeration
  const paramsToTest = request.parameterName
    ? [request.parameterName]
    : request.testParameters && request.testParameters.length > 0
      ? request.testParameters
      : DEFAULT_REDIRECT_PARAMETERS;

  // 5. Parameter Probing Loop
  for (const param of paramsToTest) {
    const probeUrl = new URL(request.endpointUrl);
    probeUrl.searchParams.set(param, canaryDestination);

    let probeResponse: HttpProbeResponse;
    try {
      probeResponse = await dispatchProbe(
        {
          url: probeUrl.toString(),
          method,
          headers: {
            ...sessionHeaders,
            'User-Agent': 'FixGuard-V2-OpenRedirectDetector/1.0',
          },
        },
        transport,
        request.coordinator
      );
    } catch (err: unknown) {
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'open_redirect_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'unexpected_failure',
        reasonCode: 'probe_dispatch_failed',
        lineage,
        error: {
          code: 'probe_dispatch_failed',
          safeMessage: err instanceof Error ? err.message : 'HTTP probe dispatch failed',
        },
      };
    }

    const locationHeader =
      probeResponse.headers['location'] || probeResponse.headers['Location'];

    if (locationHeader) {
      // Egress SSRF Gate on Destination: Validate redirect destination hostname
      try {
        let destHostname: string | undefined;
        if (locationHeader.startsWith('http://') || locationHeader.startsWith('https://')) {
          destHostname = new URL(locationHeader).hostname;
        } else if (locationHeader.startsWith('//')) {
          destHostname = new URL(`https:${locationHeader}`).hostname;
        }

        if (destHostname && isInternalOrSsrfTarget(destHostname)) {
          return {
            contractVersion: DETECTION_CONTRACT_VERSION,
            kind: 'open_redirect_detection_result',
            detectionId: request.detectionId,
            scanId: request.scanId,
            assessmentId: request.assessmentId,
            authorizationGrantId: request.authorizationGrantId,
            authorizationDecisionId: request.authorizationDecisionId,
            actorId: request.actorId,
            status: 'preflight_denied',
            reasonCode: 'ssrf_destination_blocked',
            lineage,
            parameterName: param,
            injectedCanary: canaryDestination,
            finalDestination: locationHeader,
            error: {
              code: 'ssrf_destination_blocked',
              safeMessage: `Redirect destination points to forbidden internal or metadata host '${destHostname}'`,
            },
          };
        }
      } catch {
        // Safe parse fallback
      }

      // Check if location redirects blindly to our injected canary
      if (isCanaryRedirection(locationHeader, canaryDestination)) {
        const candidateId = `cnd_redir_${safeSeed}`;
        const evidenceRecordId = `evd_redir_${safeSeed}`;
        const draftId = `dft_redir_${safeSeed}`;
        const redirectChain = [locationHeader];

        // If Human Review Decision is provided:
        if (request.humanReviewDecision) {
          if (request.humanReviewDecision.decision === 'approve_evidence') {
            const finding: Finding = {
              id: `fnd_redir_${safeSeed}`,
              type: 'INPUT_VALIDATION_FLAW',
              severity: 'medium',
              title: `Open Redirect Vulnerability via '${param}' on ${parsedUrl.hostname}`,
              description: `The application accepts unvalidated user input via parameter '${param}' and issues an HTTP redirect (${probeResponse.statusCode}) to arbitrary external destination '${locationHeader}'.`,
              target: request.endpointUrl,
              evidence: JSON.stringify({
                parameterName: param,
                injectedCanary: canaryDestination,
                finalDestination: locationHeader,
                statusCode: probeResponse.statusCode,
                redirectChain,
                reviewedBy: request.humanReviewDecision.reviewerId,
                reviewedAt: request.humanReviewDecision.reviewedAt,
              }),
              confidence: 1.0,
              verificationState: 'observed_anomaly',
              metadata: {
                kind: 'open_redirect_metadata',
                category: 'INPUT_VALIDATION_FLAW',
                parameterName: param,
                injectedCanary: canaryDestination,
                finalDestination: locationHeader,
                redirectChain,
                observedAt: nowIso,
                endpointUrl: request.endpointUrl,
                candidateId,
                evidenceRecordId,
                lineage,
              },
            };

            return {
              contractVersion: DETECTION_CONTRACT_VERSION,
              kind: 'open_redirect_detection_result',
              detectionId: request.detectionId,
              scanId: request.scanId,
              assessmentId: request.assessmentId,
              authorizationGrantId: request.authorizationGrantId,
              authorizationDecisionId: request.authorizationDecisionId,
              actorId: request.actorId,
              status: 'exploit_confirmed',
              reasonCode: 'open_redirect_confirmed',
              lineage,
              parameterName: param,
              injectedCanary: canaryDestination,
              finalDestination: locationHeader,
              redirectChain,
              finding,
            };
          }

          if (request.humanReviewDecision.decision === 'reject') {
            return {
              contractVersion: DETECTION_CONTRACT_VERSION,
              kind: 'open_redirect_detection_result',
              detectionId: request.detectionId,
              scanId: request.scanId,
              assessmentId: request.assessmentId,
              authorizationGrantId: request.authorizationGrantId,
              authorizationDecisionId: request.authorizationDecisionId,
              actorId: request.actorId,
              status: 'secure_target_abstained',
              reasonCode: 'human_review_rejected',
              lineage,
              parameterName: param,
              injectedCanary: canaryDestination,
              finalDestination: locationHeader,
              redirectChain,
            };
          }
        }

        // Unreviewed — produce EvidenceDraft for Human Triage
        const draftEnvelope: EvidenceDraftEnvelope = {
          draftKind: 'non_persisted_comparison_evidence_draft',
          draftId,
          suggestedEvidenceType: 'http_difference',
          suggestedStrength: 'strong',
          sourceComparisonId: `cmp_${safeSeed}`,
          sourceSnapshotIds: {
            baselineSnapshotId: `snp_${safeSeed}_base`,
            validationSnapshotId: `snp_${safeSeed}_val`,
          },
          requiresHumanReview: true,
          notPersisted: true,
          notARealFinding: true,
          notConfirmedEvidence: true,
          notForExternalDelivery: true,
          notM45EvidenceRecord: true,
          safeRationale: `Target issues an HTTP redirect (${probeResponse.statusCode}) on parameter '${param}' to canary destination '${locationHeader}'.`,
        };

        return {
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'open_redirect_detection_result',
          detectionId: request.detectionId,
          scanId: request.scanId,
          assessmentId: request.assessmentId,
          authorizationGrantId: request.authorizationGrantId,
          authorizationDecisionId: request.authorizationDecisionId,
          actorId: request.actorId,
          status: 'pending_human_review',
          reasonCode: 'unvalidated_canary_redirection',
          lineage,
          parameterName: param,
          injectedCanary: canaryDestination,
          finalDestination: locationHeader,
          redirectChain,
          evidenceDraft: draftEnvelope,
        };
      }
    }
  }

  // 6. Target safely abstains if destinations are sanitized/allowlisted or no redirection occurs
  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'open_redirect_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'secure_target_abstained',
    reasonCode: 'destination_validated_or_no_redirect',
    lineage,
    injectedCanary: canaryDestination,
  };
}
