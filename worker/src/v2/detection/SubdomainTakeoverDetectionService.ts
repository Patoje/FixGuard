/**
 * FixGuard V2 — Milestone P2-4 Subdomain Takeover Detection Engine
 *
 * Implements cross-recon verification probe for dangling CNAME DNS records:
 * - Identifies cloud hosting provider from CNAME target (GitHub Pages, Heroku, AWS S3, Azure, Fastly, Netlify, Shopify)
 * - Executes safe HTTP GET verification probe through TargetExecutionCoordinator & Preflight SSRF gates
 * - Verifies provider-specific unclaimed error fingerprints in response body
 *
 * Crucial Invariants:
 * - Evidence Discipline: A CNAME pointing to a cloud provider is NOT confirmed vulnerable by itself.
 *   The engine must actively verify the specific unclaimed error fingerprint before generating an evidence draft.
 * - Clean Abstention: Active/claimed services (200 OK or legitimate non-error content) cleanly return status: 'secure_target_abstained'.
 * - Lineage Preservation: Continuous lineage tuple preserved across all detection results.
 * - Human-in-the-loop: Unattended runs return status: 'pending_human_review' routing to pendingEvidenceDrafts.
 */

import type {
  SubdomainTakeoverDetectionRequest,
  SubdomainTakeoverDetectionResult,
  SubdomainTakeoverHostingProvider,
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from './DetectionContracts.js';
import { DETECTION_CONTRACT_VERSION } from './DetectionContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import { validateSessionHealth } from '../core/SessionLifecycleService.js';
import { defaultHttpProbeTransport } from './IdorDifferentialDetectionService.js';
import type { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : '001';
}

export function identifyHostingProvider(cnameTarget: string): SubdomainTakeoverHostingProvider {
  const target = cnameTarget.toLowerCase();
  if (target.includes('.github.io') || target.includes('.github.com')) return 'github_pages';
  if (target.includes('.herokudns.com') || target.includes('.herokuapp.com')) return 'heroku';
  if (target.includes('.s3.amazonaws.com') || target.includes('.s3-website') || target.includes('s3-')) return 'aws_s3';
  if (target.includes('.azurewebsites.net') || target.includes('.cloudapp.net')) return 'azure';
  if (target.includes('.fastly.net')) return 'fastly';
  if (target.includes('.netlify.app') || target.includes('.netlify.com')) return 'netlify';
  if (target.includes('.myshopify.com')) return 'shopify';
  return 'unknown';
}

export const TAKEOVER_FINGERPRINTS: Record<SubdomainTakeoverHostingProvider, readonly string[]> = {
  github_pages: [
    "There isn't a GitHub Pages site here.",
    "404 There isn't a GitHub Pages site here",
    "For root URLs (like http://example.com/) you must provide an index.html file",
  ],
  heroku: [
    "There's nothing here, yet.",
    "No such app",
    "Heroku | No such app",
    "<title>No such app</title>",
  ],
  aws_s3: [
    "<Code>NoSuchBucket</Code>",
    "The specified bucket does not exist",
  ],
  azure: [
    "404 Web Site not found",
    "Microsoft Azure Web App - Error 404",
    "The resource you are looking for has been removed",
  ],
  fastly: [
    "Fastly error: unknown domain",
  ],
  netlify: [
    "Not Found - Request ID",
    "page not found",
  ],
  shopify: [
    "Sorry, this shop is currently unavailable.",
  ],
  unknown: [],
};

function matchFingerprint(
  bodyText: string,
  provider: SubdomainTakeoverHostingProvider
): string | null {
  if (!bodyText) return null;

  // 1. Check provider-specific fingerprints first
  const specificFingerprints = TAKEOVER_FINGERPRINTS[provider] || [];
  for (const fp of specificFingerprints) {
    if (bodyText.includes(fp)) {
      return fp;
    }
  }

  // 2. If provider is unknown or not matched yet, check all fingerprints
  if (provider === 'unknown') {
    for (const [_, fps] of Object.entries(TAKEOVER_FINGERPRINTS)) {
      for (const fp of fps) {
        if (bodyText.includes(fp)) {
          return fp;
        }
      }
    }
  }

  return null;
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

export async function runSubdomainTakeoverDetection(
  request: SubdomainTakeoverDetectionRequest
): Promise<SubdomainTakeoverDetectionResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const safeSeed = sanitizeToSafeId(request.detectionId);
  const nowIso = new Date().toISOString();

  const provider = request.hostingProvider ?? identifyHostingProvider(request.cnameTarget);

  // Construct target probe URL
  let targetUrl: string;
  if (request.endpointUrl) {
    targetUrl = request.endpointUrl;
  } else {
    targetUrl = request.subdomain.startsWith('http://') || request.subdomain.startsWith('https://')
      ? request.subdomain
      : `https://${request.subdomain}`;
  }

  // 1. Adapter Preflight Pipeline Gate (7-pass check with SSRF / DNS rebinding prevention)
  const preflight = await runAdapterPreflight({
    target: targetUrl,
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
      kind: 'subdomain_takeover_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: preflight.reasonCode,
      lineage,
      subdomain: request.subdomain,
      cnameTarget: request.cnameTarget,
      hostingProvider: provider,
      error: {
        code: preflight.reasonCode,
        safeMessage: `Preflight denied: ${preflight.reasonCode}`,
      },
    };
  }

  // 2. Prepare Base URL
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'subdomain_takeover_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: 'invalid_target_url',
      lineage,
      subdomain: request.subdomain,
      cnameTarget: request.cnameTarget,
      hostingProvider: provider,
      error: {
        code: 'invalid_target_url',
        safeMessage: 'Target URL is invalid',
      },
    };
  }

  const transport = request.transport ?? defaultHttpProbeTransport;

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
        kind: 'subdomain_takeover_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'preflight_denied',
        reasonCode: reason,
        lineage,
        subdomain: request.subdomain,
        cnameTarget: request.cnameTarget,
        hostingProvider: provider,
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

  // 4. Dispatch Probe to inspect response body for unclaimed fingerprint
  let response: HttpProbeResponse;
  try {
    response = await dispatchProbe(
      {
        url: targetUrl,
        method: 'GET',
        headers: {
          ...sessionHeaders,
          'User-Agent': 'FixGuard-V2-SubdomainTakeoverDetector/1.0',
        },
      },
      transport,
      request.coordinator
    );
  } catch (err) {
    // If connection fails, check if http fallback is viable or treat as safe failure
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'subdomain_takeover_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'http_probe_transport_failed',
      lineage,
      subdomain: request.subdomain,
      cnameTarget: request.cnameTarget,
      hostingProvider: provider,
      error: {
        code: 'http_probe_transport_failed',
        safeMessage: err instanceof Error ? err.message : 'Network probe failed',
      },
    };
  }

  // 5. Fingerprint verification
  const matchedFingerprint = matchFingerprint(response.bodyText, provider);

  // If no fingerprint match -> cleanly abstain (claimed/active host)
  if (!matchedFingerprint) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'subdomain_takeover_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'no_takeover_fingerprint_matched',
      lineage,
      subdomain: request.subdomain,
      cnameTarget: request.cnameTarget,
      hostingProvider: provider,
    };
  }

  // 6. Matched fingerprint -> Human Review or Finding Generation
  const candidateId = `cnd_takeover_${safeSeed}`;
  const evidenceRecordId = `evd_takeover_${safeSeed}`;
  const draftId = `dft_takeover_${safeSeed}`;

  if (request.humanReviewDecision) {
    if (request.humanReviewDecision.decision === 'approve_evidence') {
      const finding: Finding = {
        id: `fnd_takeover_${safeSeed}`,
        type: 'DNS_HIJACKING_RISK',
        severity: 'high',
        title: `Subdomain Takeover Risk (${provider}) on ${request.subdomain}`,
        description: `Subdomain '${request.subdomain}' points via CNAME to '${request.cnameTarget}' (${provider}) which returned unclaimed resource fingerprint: "${matchedFingerprint}". An attacker could claim this resource to hijack the subdomain.`,
        target: targetUrl,
        evidence: JSON.stringify({
          subdomain: request.subdomain,
          cnameTarget: request.cnameTarget,
          hostingProvider: provider,
          fingerprintMatch: matchedFingerprint,
          statusCode: response.statusCode,
          reviewedBy: request.humanReviewDecision.reviewerId,
          reviewedAt: request.humanReviewDecision.reviewedAt,
        }),
        confidence: 0.95,
        metadata: {
          kind: 'subdomain_takeover_metadata',
          category: 'DNS_HIJACKING_RISK',
          subdomain: request.subdomain,
          cnameTarget: request.cnameTarget,
          hostingProvider: provider,
          fingerprintMatch: matchedFingerprint,
          observedAt: nowIso,
          endpointUrl: targetUrl,
          candidateId,
          evidenceRecordId,
          lineage,
        },
      };

      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'subdomain_takeover_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'vulnerability_detected',
        reasonCode: 'subdomain_takeover_confirmed',
        lineage,
        subdomain: request.subdomain,
        cnameTarget: request.cnameTarget,
        hostingProvider: provider,
        fingerprintMatch: matchedFingerprint,
        finding,
      };
    }

    if (request.humanReviewDecision.decision === 'reject') {
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'subdomain_takeover_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'secure_target_abstained',
        reasonCode: 'human_review_rejected',
        lineage,
        subdomain: request.subdomain,
        cnameTarget: request.cnameTarget,
        hostingProvider: provider,
      };
    }
  }

  // 7. Unreviewed -> Produce EvidenceDraft for Human Triage
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
    safeRationale: `Subdomain '${request.subdomain}' points via CNAME to '${request.cnameTarget}' (${provider}) with unclaimed fingerprint: "${matchedFingerprint}"`,
  };

  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'subdomain_takeover_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'pending_human_review',
    reasonCode: 'unclaimed_subdomain_fingerprint_observed',
    lineage,
    subdomain: request.subdomain,
    cnameTarget: request.cnameTarget,
    hostingProvider: provider,
    fingerprintMatch: matchedFingerprint,
    evidenceDraft: draftEnvelope,
  };
}
