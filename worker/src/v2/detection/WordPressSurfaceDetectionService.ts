/**
 * Milestone P4-4 — WordPress XML-RPC and User Enumeration Probes
 *
 * Targets WordPress architectures:
 * 1. XML-RPC Capabilities:
 *    - Sends POST to /xmlrpc.php with safe system.listMethods payload.
 *    - Validates method response and checks for system.multicall amplification support.
 *    - Categorized as SECURITY_MISCONFIGURATION.
 * 2. REST API User Enumeration:
 *    - Sends GET to /wp-json/wp/v2/users.
 *    - Validates exposed user records and extracts author slugs.
 *    - Categorized as INFORMATION_DISCLOSURE.
 *
 * Strict Invariants:
 * - Strictly non-brute-force. Zero credential testing and zero denial-of-service attempts.
 * - 7-pass SSRF preflight protection.
 * - Clean abstention (secure_target_abstained) when surfaces return 401/403/404 or are disabled.
 * - HITL Routing: Unattended runs produce pending_human_review with EvidenceDraftEnvelope.
 */

import type {
  WordPressSurfaceDetectionRequest,
  WordPressSurfaceDetectionResult,
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

function extractXmlRpcMethods(xmlBody: string): string[] {
  const methods: string[] = [];
  const stringRegex = /<string>([^<]+)<\/string>/gi;
  let match: RegExpExecArray | null;
  while ((match = stringRegex.exec(xmlBody)) !== null) {
    if (match[1] && match[1].trim().length > 0) {
      methods.push(match[1].trim());
    }
  }
  return methods;
}

interface ExtractedWpUser {
  readonly id: number | string;
  readonly slug: string;
  readonly name?: string;
}

function parseWordPressUsers(jsonBody: string): ExtractedWpUser[] | null {
  try {
    const parsed = JSON.parse(jsonBody);
    if (!Array.isArray(parsed)) return null;

    const users: ExtractedWpUser[] = [];
    for (const item of parsed) {
      if (typeof item === 'object' && item !== null && 'id' in item && 'slug' in item) {
        users.push({
          id: item.id,
          slug: String(item.slug),
          name: typeof item.name === 'string' ? item.name : undefined,
        });
      }
    }
    return users.length > 0 ? users : null;
  } catch {
    return null;
  }
}

export async function runWordPressSurfaceDetection(
  request: WordPressSurfaceDetectionRequest
): Promise<WordPressSurfaceDetectionResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const safeSeed = sanitizeToSafeId(request.detectionId);
  const nowIso = new Date().toISOString();
  const transport = request.transport ?? defaultHttpProbeTransport;
  const baseUrl = request.targetBaseUrl.replace(/\/+$/, '');
  const probeMode = request.probeKind ?? 'all';

  // ---------------------------------------------------------------------------
  // Probe 1: XML-RPC Capabilities
  // ---------------------------------------------------------------------------
  if (probeMode === 'all' || probeMode === 'xmlrpc_capabilities') {
    const xmlRpcUrl = `${baseUrl}/xmlrpc.php`;

    // 1. SSRF Preflight for XML-RPC
    const preflightXmlRpc = await runAdapterPreflight({
      target: xmlRpcUrl,
      targetKind: 'url',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.scopeGrant,
      lineage,
      permissionCheck: (ps) => Boolean(ps.endpointDiscovery || ps.lightValidation || ps.activeValidation),
      dnsResolver: request.dnsResolver,
    });

    if (!preflightXmlRpc.ok) {
      if (probeMode === 'xmlrpc_capabilities') {
        return {
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'wordpress_surface_detection_result',
          detectionId: request.detectionId,
          scanId: request.scanId,
          assessmentId: request.assessmentId,
          authorizationGrantId: request.authorizationGrantId,
          authorizationDecisionId: request.authorizationDecisionId,
          actorId: request.actorId,
          status: 'preflight_denied',
          reasonCode: preflightXmlRpc.reasonCode,
          lineage,
          targetBaseUrl: baseUrl,
          probeKind: 'xmlrpc_capabilities',
          endpointUrl: xmlRpcUrl,
          error: {
            code: preflightXmlRpc.reasonCode,
            safeMessage: `Preflight denied for XML-RPC: ${preflightXmlRpc.reasonCode}`,
          },
        };
      }
    } else {
      // 2. Dispatch Safe system.listMethods POST Probe
      const xmlPayload = `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>`;
      const probeReq: HttpProbeRequest = {
        url: xmlRpcUrl,
        method: 'POST',
        headers: {
          'content-type': 'text/xml',
          accept: 'text/xml, application/xml, */*',
          'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
        },
        body: xmlPayload,
        timeoutMs: 5000,
      };

      let xmlRpcResp: HttpProbeResponse | undefined;
      try {
        xmlRpcResp = await transport(probeReq);
      } catch {
        // Network failure on XML-RPC probe
      }

      if (
        xmlRpcResp &&
        xmlRpcResp.statusCode === 200 &&
        (xmlRpcResp.bodyText.includes('<methodResponse>') || xmlRpcResp.bodyText.includes('<value>'))
      ) {
        const methods = extractXmlRpcMethods(xmlRpcResp.bodyText);
        if (methods.length > 0) {
          const multicallSupported = methods.some((m) => m.toLowerCase() === 'system.multicall');
          const draftId = `dft_wpxml_${safeSeed}`;
          const candidateId = `cnd_wpxml_${safeSeed}`;
          const evidenceRecordId = `evd_wpxml_${safeSeed}`;

          if (request.humanReviewDecision) {
            if (request.humanReviewDecision.decision === 'approve_evidence') {
              const finding: Finding = {
                id: `fnd_wpxml_${safeSeed}`,
                type: 'SECURITY_MISCONFIGURATION',
                severity: multicallSupported ? 'medium' : 'low',
                title: `Exposed WordPress XML-RPC API with ${multicallSupported ? 'Amplification' : 'Method Listing'} Support`,
                description: `Target application exposes active WordPress XML-RPC endpoint '${xmlRpcUrl}' with ${methods.length} callable methods.${multicallSupported ? ' Supports system.multicall which enables batch brute-force and amplification attacks.' : ''}`,
                target: xmlRpcUrl,
                evidence: sanitizeEvidenceFragment(
                  JSON.stringify({
                    endpointUrl: xmlRpcUrl,
                    probeKind: 'xmlrpc_capabilities',
                    methodsCount: methods.length,
                    sampleMethods: methods.slice(0, 10),
                    multicallSupported,
                    reviewedBy: request.humanReviewDecision.reviewerId,
                    reviewedAt: request.humanReviewDecision.reviewedAt,
                  })
                ),
                confidence: 0.95,
                metadata: {
                  kind: 'wordpress_surface_metadata',
                  category: 'SECURITY_MISCONFIGURATION',
                  probeKind: 'xmlrpc_capabilities',
                  endpointUrl: xmlRpcUrl,
                  xmlRpcMethodsExposed: methods.slice(0, 20),
                  multicallSupported,
                  observedAt: nowIso,
                  candidateId,
                  evidenceRecordId,
                  lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}`,
                },
              };

              return {
                contractVersion: DETECTION_CONTRACT_VERSION,
                kind: 'wordpress_surface_detection_result',
                detectionId: request.detectionId,
                scanId: request.scanId,
                assessmentId: request.assessmentId,
                authorizationGrantId: request.authorizationGrantId,
                authorizationDecisionId: request.authorizationDecisionId,
                actorId: request.actorId,
                status: 'potential_weakness',
                reasonCode: 'wordpress_xmlrpc_exposed',
                lineage,
                targetBaseUrl: baseUrl,
                probeKind: 'xmlrpc_capabilities',
                endpointUrl: xmlRpcUrl,
                xmlRpcMethodsExposed: methods.slice(0, 20),
                multicallSupported,
                finding,
              };
            }

            if (request.humanReviewDecision.decision === 'reject') {
              return {
                contractVersion: DETECTION_CONTRACT_VERSION,
                kind: 'wordpress_surface_detection_result',
                detectionId: request.detectionId,
                scanId: request.scanId,
                assessmentId: request.assessmentId,
                authorizationGrantId: request.authorizationGrantId,
                authorizationDecisionId: request.authorizationDecisionId,
                actorId: request.actorId,
                status: 'secure_target_abstained',
                reasonCode: 'human_review_rejected',
                lineage,
                targetBaseUrl: baseUrl,
                probeKind: 'xmlrpc_capabilities',
                endpointUrl: xmlRpcUrl,
              };
            }
          }

          // Unreviewed XML-RPC -> Produce Draft
          const evidenceDraft: EvidenceDraftEnvelope = {
            draftKind: 'non_persisted_comparison_evidence_draft',
            draftId,
            suggestedEvidenceType: 'http_difference',
            suggestedStrength: 'moderate',
            sourceComparisonId: `cmp_wpxml_${safeSeed}`,
            sourceSnapshotIds: {
              baselineSnapshotId: `snp_wpxml_${safeSeed}_base`,
              validationSnapshotId: `snp_wpxml_${safeSeed}_val`,
            },
            requiresHumanReview: true,
            notPersisted: true,
            notARealFinding: true,
            notConfirmedEvidence: true,
            notForExternalDelivery: true,
            notM45EvidenceRecord: true,
            safeRationale: `Target application exposed XML-RPC endpoint (${methods.length} methods, multicall: ${multicallSupported}) at ${xmlRpcUrl}`,
          };

          return {
            contractVersion: DETECTION_CONTRACT_VERSION,
            kind: 'wordpress_surface_detection_result',
            detectionId: request.detectionId,
            scanId: request.scanId,
            assessmentId: request.assessmentId,
            authorizationGrantId: request.authorizationGrantId,
            authorizationDecisionId: request.authorizationDecisionId,
            actorId: request.actorId,
            status: 'pending_human_review',
            reasonCode: 'wordpress_xmlrpc_observed',
            lineage,
            targetBaseUrl: baseUrl,
            probeKind: 'xmlrpc_capabilities',
            endpointUrl: xmlRpcUrl,
            xmlRpcMethodsExposed: methods.slice(0, 20),
            multicallSupported,
            evidenceDraft,
          };
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Probe 2: REST API User Enumeration (/wp-json/wp/v2/users)
  // ---------------------------------------------------------------------------
  if (probeMode === 'all' || probeMode === 'rest_user_enumeration') {
    const usersRestUrl = `${baseUrl}/wp-json/wp/v2/users`;

    // 1. SSRF Preflight for REST Users
    const preflightRest = await runAdapterPreflight({
      target: usersRestUrl,
      targetKind: 'url',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.scopeGrant,
      lineage,
      permissionCheck: (ps) => Boolean(ps.endpointDiscovery || ps.lightValidation || ps.activeValidation),
      dnsResolver: request.dnsResolver,
    });

    if (!preflightRest.ok) {
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'wordpress_surface_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'preflight_denied',
        reasonCode: preflightRest.reasonCode,
        lineage,
        targetBaseUrl: baseUrl,
        probeKind: 'rest_user_enumeration',
        endpointUrl: usersRestUrl,
        error: {
          code: preflightRest.reasonCode,
          safeMessage: `Preflight denied for WordPress REST users: ${preflightRest.reasonCode}`,
        },
      };
    }

    // 2. Dispatch GET Probe
    const probeReq: HttpProbeRequest = {
      url: usersRestUrl,
      method: 'GET',
      headers: {
        accept: 'application/json, text/plain, */*',
        'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
      },
      timeoutMs: 5000,
    };

    let usersResp: HttpProbeResponse | undefined;
    try {
      usersResp = await transport(probeReq);
    } catch {
      // Network failure on REST users probe
    }

    if (usersResp && usersResp.statusCode === 200 && usersResp.bodyText.trim().length > 0) {
      const parsedUsers = parseWordPressUsers(usersResp.bodyText);
      if (parsedUsers && parsedUsers.length > 0) {
        const sampleUserSlugs = parsedUsers.map((u) => u.slug).slice(0, 5);
        const exposedUsersCount = parsedUsers.length;
        const draftId = `dft_wpusr_${safeSeed}`;
        const candidateId = `cnd_wpusr_${safeSeed}`;
        const evidenceRecordId = `evd_wpusr_${safeSeed}`;

        if (request.humanReviewDecision) {
          if (request.humanReviewDecision.decision === 'approve_evidence') {
            const finding: Finding = {
              id: `fnd_wpusr_${safeSeed}`,
              type: 'INFORMATION_DISCLOSURE',
              severity: 'medium',
              title: `Exposed WordPress REST API User Enumeration Endpoint`,
              description: `Target application publicly exposes user identities via '${usersRestUrl}', disclosing ${exposedUsersCount} author slugs (${sampleUserSlugs.join(', ')}).`,
              target: usersRestUrl,
              evidence: sanitizeEvidenceFragment(
                JSON.stringify({
                  endpointUrl: usersRestUrl,
                  probeKind: 'rest_user_enumeration',
                  exposedUsersCount,
                  sampleUserSlugs,
                  reviewedBy: request.humanReviewDecision.reviewerId,
                  reviewedAt: request.humanReviewDecision.reviewedAt,
                })
              ),
              confidence: 0.95,
              metadata: {
                kind: 'wordpress_surface_metadata',
                category: 'INFORMATION_DISCLOSURE',
                probeKind: 'rest_user_enumeration',
                endpointUrl: usersRestUrl,
                exposedUsersCount,
                sampleUserSlugs,
                observedAt: nowIso,
                candidateId,
                evidenceRecordId,
                lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}`,
              },
            };

            return {
              contractVersion: DETECTION_CONTRACT_VERSION,
              kind: 'wordpress_surface_detection_result',
              detectionId: request.detectionId,
              scanId: request.scanId,
              assessmentId: request.assessmentId,
              authorizationGrantId: request.authorizationGrantId,
              authorizationDecisionId: request.authorizationDecisionId,
              actorId: request.actorId,
              status: 'information_disclosure',
              reasonCode: 'wordpress_user_enumeration_confirmed',
              lineage,
              targetBaseUrl: baseUrl,
              probeKind: 'rest_user_enumeration',
              endpointUrl: usersRestUrl,
              exposedUsersCount,
              sampleUserSlugs,
              finding,
            };
          }

          if (request.humanReviewDecision.decision === 'reject') {
            return {
              contractVersion: DETECTION_CONTRACT_VERSION,
              kind: 'wordpress_surface_detection_result',
              detectionId: request.detectionId,
              scanId: request.scanId,
              assessmentId: request.assessmentId,
              authorizationGrantId: request.authorizationGrantId,
              authorizationDecisionId: request.authorizationDecisionId,
              actorId: request.actorId,
              status: 'secure_target_abstained',
              reasonCode: 'human_review_rejected',
              lineage,
              targetBaseUrl: baseUrl,
              probeKind: 'rest_user_enumeration',
              endpointUrl: usersRestUrl,
            };
          }
        }

        // Unreviewed User Enumeration -> Produce Draft
        const evidenceDraft: EvidenceDraftEnvelope = {
          draftKind: 'non_persisted_comparison_evidence_draft',
          draftId,
          suggestedEvidenceType: 'http_difference',
          suggestedStrength: 'moderate',
          sourceComparisonId: `cmp_wpusr_${safeSeed}`,
          sourceSnapshotIds: {
            baselineSnapshotId: `snp_wpusr_${safeSeed}_base`,
            validationSnapshotId: `snp_wpusr_${safeSeed}_val`,
          },
          requiresHumanReview: true,
          notPersisted: true,
          notARealFinding: true,
          notConfirmedEvidence: true,
          notForExternalDelivery: true,
          notM45EvidenceRecord: true,
          safeRationale: `Target application exposed public user listings (${exposedUsersCount} users, slugs: ${sampleUserSlugs.join(', ')}) via ${usersRestUrl}`,
        };

        return {
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'wordpress_surface_detection_result',
          detectionId: request.detectionId,
          scanId: request.scanId,
          assessmentId: request.assessmentId,
          authorizationGrantId: request.authorizationGrantId,
          authorizationDecisionId: request.authorizationDecisionId,
          actorId: request.actorId,
          status: 'pending_human_review',
          reasonCode: 'wordpress_user_enumeration_observed',
          lineage,
          targetBaseUrl: baseUrl,
          probeKind: 'rest_user_enumeration',
          endpointUrl: usersRestUrl,
          exposedUsersCount,
          sampleUserSlugs,
          evidenceDraft,
        };
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Abstention: Neither surface was exposed
  // ---------------------------------------------------------------------------
  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'wordpress_surface_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'secure_target_abstained',
    reasonCode: 'wordpress_surfaces_hardened_or_absent',
    lineage,
    targetBaseUrl: baseUrl,
  };
}

export class WordPressSurfaceDetectionService {
  public async execute(
    request: WordPressSurfaceDetectionRequest
  ): Promise<WordPressSurfaceDetectionResult> {
    return runWordPressSurfaceDetection(request);
  }
}
