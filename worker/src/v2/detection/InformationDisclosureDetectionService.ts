/**
 * FixGuard V2 — Milestone P2-3 Information Disclosure Detection Engine
 *
 * Implements passive and non-destructive active probing for information disclosure:
 * - Stack traces (Java, Node.js, Python/Django, PHP, ASP.NET)
 * - Detailed server banners & framework version over-sharing (Server, X-Powered-By)
 * - Leaked internal filesystem paths (Windows C:\inetpub, Linux /var/www/, /home/app/)
 *
 * Crucial Invariants:
 * - Hardening gap discipline: Information disclosures are configuration/hardening gaps,
 *   strictly classified as status: 'potential_weakness' with severity: 'low' or 'info' (NEVER 'exploit_confirmed').
 * - Sensitive data redaction: Any discovered credential, auth token, or secret pattern
 *   is redacted before constructing disclosed fragments.
 * - Clean abstention: Generic 404/400 templates without disclosures return status: 'secure_target_abstained'.
 */

import type {
  InformationDisclosureDetectionRequest,
  InformationDisclosureDetectionResult,
  DisclosedItem,
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

/**
 * Redacts sensitive credentials, tokens, and authorization headers from excerpts.
 */
export function sanitizeDisclosedExcerpt(raw: string): string {
  if (!raw) return '';
  let sanitized = raw;

  // Redact Bearer and Basic tokens
  sanitized = sanitized.replace(/(Bearer\s+)[A-Za-z0-9_\-\.]+/gi, '$1[REDACTED]');
  sanitized = sanitized.replace(/Basic\s+[A-Za-z0-9+/=]+/gi, 'Basic [REDACTED]');

  // Redact key=value pairs containing sensitive words
  sanitized = sanitized.replace(
    /((?:api[_\-]?key|secret|password|passwd|token|auth|access_token|private_key)\s*[:=]\s*['"]?)[^'"\s,;&]+(['"]?)/gi,
    '$1[REDACTED]$2'
  );

  // Truncate overly long excerpts
  if (sanitized.length > 300) {
    sanitized = sanitized.slice(0, 300) + '... [TRUNCATED]';
  }

  return sanitized.trim();
}

const STACK_TRACE_PATTERNS = [
  // Java
  /(?:Exception in thread\s+"[^"]+"\s+java\.[a-zA-Z0-9_\.]+:|at (?:org|com|java|javax)\.[a-zA-Z0-9_\.]+\([a-zA-Z0-9_\.]+\.java:\d+\)|java\.lang\.[A-Za-z0-9_]+Exception)/i,
  // Node.js / Express
  /(?:(?:TypeError|ReferenceError|SyntaxError|Error): [^\n]+[\r\n]+\s+at |at Function\.execute\s+\(|at Object\.<anonymous>\s+\(|at Module\._compile\s+\()/i,
  // Python / Django / Flask
  /(?:Traceback \(most recent call last\):|File "[^"]+", line \d+, in [a-zA-Z0-9_]+|django\.core\.exceptions|werkzeug\.exceptions)/i,
  // PHP
  /(?:Fatal error: [^\n]+ in \/[^\n]+ on line \d+|Stack trace:[\r\n]+#0 [^\n]+|Parse error: syntax error, [^\n]+ in \/[^\n]+ on line \d+)/i,
  // ASP.NET
  /(?:\[NullReferenceException: [^\n]+\]|System\.Web\.HttpUnhandledException|System\.NullReferenceException: Object reference not set|at System\.Web\.UI\.[a-zA-Z0-9_]+)/i,
];

const INTERNAL_PATH_PATTERNS = [
  /[a-zA-Z]:\\(?:inetpub|inetpub\\wwwroot|Windows\\System32|Users\\[a-zA-Z0-9_\-]+\\app|var\\www)\\[a-zA-Z0-9_\-\\\.]+/i,
  /(?:\/(?:var\/www|home\/[a-zA-Z0-9_\-]+\/app|usr\/local\/share|opt\/app|srv\/www)\/[a-zA-Z0-9_\-\/\.]+)/i,
];

const SERVER_BANNER_PATTERNS = [
  /(?:Apache\/\d\.[0-9\.]+|nginx\/\d\.[0-9\.]+|Microsoft-IIS\/\d\.[0-9\.]+|lighttpd\/\d\.[0-9\.]+|Tomcat\/\d\.[0-9\.]+|OpenSSL\/\d\.[0-9\.]+[a-z]?)/i,
];

const FRAMEWORK_HEADER_PATTERNS = [
  /(?:PHP\/\d\.[0-9\.]+|Express|ASP\.NET|Next\.js|Kestrel|Laravel|Django)/i,
];

function analyzeResponseForDisclosures(
  response: HttpProbeResponse,
  trigger: string
): DisclosedItem[] {
  const items: DisclosedItem[] = [];
  const bodyText = response.bodyText || '';

  // 1. Stack Trace Matching
  for (const pattern of STACK_TRACE_PATTERNS) {
    const match = bodyText.match(pattern);
    if (match && match[0]) {
      const matchIndex = match.index ?? 0;
      const snippet = bodyText.slice(
        Math.max(0, matchIndex - 20),
        Math.min(bodyText.length, matchIndex + 200)
      );
      items.push({
        disclosureKind: 'stack_trace',
        disclosedFragment: sanitizeDisclosedExcerpt(snippet),
        trigger,
      });
      break;
    }
  }

  // 2. Internal Path Matching
  for (const pattern of INTERNAL_PATH_PATTERNS) {
    const match = bodyText.match(pattern);
    if (match && match[0]) {
      items.push({
        disclosureKind: 'internal_path',
        disclosedFragment: sanitizeDisclosedExcerpt(match[0]),
        trigger,
      });
      break;
    }
  }

  // 3. Server Header Version Matching
  const serverHeader = response.headers['server'] || response.headers['Server'];
  if (serverHeader) {
    for (const pattern of SERVER_BANNER_PATTERNS) {
      const match = serverHeader.match(pattern);
      if (match && match[0]) {
        items.push({
          disclosureKind: 'server_banner',
          disclosedFragment: sanitizeDisclosedExcerpt(serverHeader),
          trigger: `${trigger} (Header: Server)`,
        });
        break;
      }
    }
  }

  // 4. Framework Version / Header Matching (X-Powered-By, etc.)
  const poweredBy = response.headers['x-powered-by'] || response.headers['X-Powered-By'];
  if (poweredBy) {
    for (const pattern of FRAMEWORK_HEADER_PATTERNS) {
      const match = poweredBy.match(pattern);
      if (match && match[0]) {
        items.push({
          disclosureKind: 'framework_version',
          disclosedFragment: sanitizeDisclosedExcerpt(poweredBy),
          trigger: `${trigger} (Header: X-Powered-By)`,
        });
        break;
      }
    }
  }

  return items;
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

export async function runInformationDisclosureDetection(
  request: InformationDisclosureDetectionRequest
): Promise<InformationDisclosureDetectionResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const safeSeed = sanitizeToSafeId(request.detectionId);
  const nowIso = new Date().toISOString();

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
      kind: 'information_disclosure_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: preflight.reasonCode,
      lineage,
      disclosures: [],
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
      kind: 'information_disclosure_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: 'invalid_target_url',
      lineage,
      disclosures: [],
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
        kind: 'information_disclosure_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'preflight_denied',
        reasonCode: reason,
        lineage,
        disclosures: [],
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

  const allDisclosures: DisclosedItem[] = [];

  // 4. Probe 1: Baseline inspection on root/endpoint
  try {
    const baseResp = await dispatchProbe(
      {
        url: request.endpointUrl,
        method,
        headers: {
          ...sessionHeaders,
          'User-Agent': 'FixGuard-V2-InfoDisclosureDetector/1.0',
        },
      },
      transport,
      request.coordinator
    );
    const baseItems = analyzeResponseForDisclosures(baseResp, 'Baseline Inspection');
    allDisclosures.push(...baseItems);
  } catch {
    // Safe error containment
  }

  // 5. Probe 2: Non-destructive 404 anomaly path inspection
  try {
    const anomalyUrl = new URL(request.endpointUrl);
    anomalyUrl.pathname = `${anomalyUrl.pathname.replace(/\/$/, '')}/_fixguard_anomaly_404_${safeSeed}`;
    const anomalyResp = await dispatchProbe(
      {
        url: anomalyUrl.toString(),
        method: 'GET',
        headers: {
          ...sessionHeaders,
          'User-Agent': 'FixGuard-V2-InfoDisclosureDetector/1.0',
        },
      },
      transport,
      request.coordinator
    );
    const anomalyItems = analyzeResponseForDisclosures(anomalyResp, '404 Anomaly Probe');
    allDisclosures.push(...anomalyItems);
  } catch {
    // Safe error containment
  }

  // Deduplicate discovered items
  const uniqueDisclosures = allDisclosures.filter(
    (item, index, self) =>
      index ===
      self.findIndex(
        (t) =>
          t.disclosureKind === item.disclosureKind &&
          t.disclosedFragment === item.disclosedFragment
      )
  );

  // 6. If no disclosures found -> Secure Target Abstained
  if (uniqueDisclosures.length === 0) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'information_disclosure_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'no_information_disclosure_observed',
      lineage,
      disclosures: [],
    };
  }

  // 7. Human Review Decision Supplied -> Produce Finding with Hardening Gap Invariant ('potential_weakness')
  const primaryItem = uniqueDisclosures[0];
  const candidateId = `cnd_infodisc_${safeSeed}`;
  const evidenceRecordId = `evd_infodisc_${safeSeed}`;
  const draftId = `dft_infodisc_${safeSeed}`;

  if (request.humanReviewDecision) {
    if (request.humanReviewDecision.decision === 'approve_evidence') {
      const finding: Finding = {
        id: `fnd_infodisc_${safeSeed}`,
        type: 'SECURITY_MISCONFIGURATION',
        severity: primaryItem.disclosureKind === 'stack_trace' ? 'low' : 'info',
        title: `Information Disclosure (${primaryItem.disclosureKind}) on ${parsedUrl.hostname}`,
        description: `Target application discloses internal system details (${primaryItem.disclosureKind}) under trigger '${primaryItem.trigger}': ${primaryItem.disclosedFragment}`,
        target: request.endpointUrl,
        evidence: JSON.stringify({
          disclosureKind: primaryItem.disclosureKind,
          disclosedFragment: primaryItem.disclosedFragment,
          trigger: primaryItem.trigger,
          allDisclosures: uniqueDisclosures,
          reviewedBy: request.humanReviewDecision.reviewerId,
          reviewedAt: request.humanReviewDecision.reviewedAt,
        }),
        confidence: 0.95,
        verificationState: 'observed_anomaly',
        metadata: {
          kind: 'information_disclosure_metadata',
          category: 'SECURITY_MISCONFIGURATION',
          disclosureKind: primaryItem.disclosureKind,
          disclosedFragment: primaryItem.disclosedFragment,
          trigger: primaryItem.trigger,
          observedAt: nowIso,
          endpointUrl: request.endpointUrl,
          candidateId,
          evidenceRecordId,
          lineage,
        },
      };

      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'information_disclosure_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'potential_weakness',
        reasonCode: 'information_disclosure_observed',
        lineage,
        disclosures: uniqueDisclosures,
        finding,
      };
    }

    if (request.humanReviewDecision.decision === 'reject') {
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'information_disclosure_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'secure_target_abstained',
        reasonCode: 'human_review_rejected',
        lineage,
        disclosures: uniqueDisclosures,
      };
    }
  }

  // 8. Unreviewed -> Produce EvidenceDraft for Human Triage
  const draftEnvelope: EvidenceDraftEnvelope = {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId,
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: 'moderate',
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
    safeRationale: `Target application leaked ${primaryItem.disclosureKind} under '${primaryItem.trigger}': ${primaryItem.disclosedFragment}`,
  };

  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'information_disclosure_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'pending_human_review',
    reasonCode: 'information_disclosure_observed',
    lineage,
    disclosures: uniqueDisclosures,
    evidenceDraft: draftEnvelope,
  };
}

export class InformationDisclosureDetectionService {
  public async detectInformationDisclosure(
    request: InformationDisclosureDetectionRequest
  ): Promise<InformationDisclosureDetectionResult> {
    return runInformationDisclosureDetection(request);
  }
}

