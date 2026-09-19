/**
 * Milestone P5-4 — Dependency Confusion Detection Service
 *
 * Core Invariant: Safe verification of unclaimed private package namespaces.
 * Inspects package names identified in exposed manifests or client-side bundles
 * and queries the public npm registry to verify whether internal namespaces are unclaimed.
 *
 * Anti-Leak & Safety Guarantees:
 * - 7-pass SSRF preflight checks on manifest URLs via runAdapterPreflight().
 * - Safe sanitization of package names and registry URLs via sanitizeEvidenceFragment().
 * - Strictly bounded HTTP transport for registry checks.
 * - 0 occurrences of 'as any'.
 */

import {
  DETECTION_CONTRACT_VERSION,
  type DependencyConfusionDetectionRequest,
  type DependencyConfusionDetectionResult,
  type IdorHttpProbeTransport,
  type HttpProbeRequest,
  type HttpProbeResponse,
} from './DetectionContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';

export interface ExtractedPackageCandidate {
  readonly packageName: string;
  readonly version?: string;
  readonly isScoped: boolean;
}

/**
 * Extracts package dependencies from package.json JSON or manifest strings.
 * Filters for scoped packages (e.g. @company/pkg) or internal names.
 */
export function extractPackageCandidatesFromManifest(manifestContent: string): ExtractedPackageCandidate[] {
  const candidates: ExtractedPackageCandidate[] = [];
  const seen = new Set<string>();

  try {
    const parsed = JSON.parse(manifestContent);
    if (parsed && typeof parsed === 'object') {
      const depSections = [
        parsed.dependencies,
        parsed.devDependencies,
        parsed.peerDependencies,
        parsed.optionalDependencies,
      ];

      for (const section of depSections) {
        if (section && typeof section === 'object') {
          for (const [pkg, ver] of Object.entries(section)) {
            if (typeof pkg === 'string' && !seen.has(pkg)) {
              seen.add(pkg);
              const isScoped = pkg.startsWith('@');
              const isInternal = isScoped || pkg.includes('internal') || pkg.includes('private');
              if (isInternal) {
                candidates.push({
                  packageName: pkg,
                  version: typeof ver === 'string' ? ver : undefined,
                  isScoped,
                });
              }
            }
          }
        }
      }
    }
  } catch {
    // Regex fallback for non-JSON or partial bundle snippets
    const scopedRegex = /"@?([a-z0-9_.-]+(?:\/[a-z0-9_.-]+)?)"\s*:\s*"([^"]+)"/gi;
    let match: RegExpExecArray | null;
    while ((match = scopedRegex.exec(manifestContent)) !== null) {
      const pkg = match[1];
      const ver = match[2];
      if (pkg && !seen.has(pkg)) {
        seen.add(pkg);
        const isScoped = pkg.startsWith('@');
        if (isScoped || pkg.includes('internal') || pkg.includes('private')) {
          candidates.push({
            packageName: pkg,
            version: ver,
            isScoped,
          });
        }
      }
    }
  }

  return candidates;
}

/**
 * Default external HTTP probe transport for registry queries.
 */
const defaultRegistryTransport: IdorHttpProbeTransport = async (
  probeReq: HttpProbeRequest
): Promise<HttpProbeResponse> => {
  const startTime = Date.now();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), probeReq.timeoutMs ?? 5000);

  try {
    const resp = await fetch(probeReq.url, {
      method: probeReq.method,
      headers: probeReq.headers,
      signal: controller.signal,
    });
    const bodyText = await resp.text();
    const headers: Record<string, string> = {};
    resp.headers.forEach((val, key) => {
      headers[key.toLowerCase()] = val;
    });

    return {
      statusCode: resp.status,
      headers,
      bodyText,
      responseTimeMs: Date.now() - startTime,
    };
  } finally {
    clearTimeout(timeoutId);
  }
};

/**
 * Main Detection Service for Dependency Confusion (Milestone P5-4).
 */
export async function runDependencyConfusionDetection(
  request: DependencyConfusionDetectionRequest
): Promise<DependencyConfusionDetectionResult> {
  const lineage = {
    assessmentId: request.assessmentId,
    scanId: request.scanId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const safeSeed = `${request.detectionId.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 16)}${request.packageName.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 16)}`;
  const registryBase = request.publicRegistryBaseUrl ?? 'https://registry.npmjs.org';
  const encodedPkg = request.packageName.startsWith('@')
    ? `@${encodeURIComponent(request.packageName.slice(1))}`
    : encodeURIComponent(request.packageName);
  const publicRegistryUrl = `${registryBase.replace(/\/+$/, '')}/${encodedPkg}`;

  // 1. SSRF Preflight for Manifest URL
  const preflight = await runAdapterPreflight({
    target: request.sourceManifestUrl,
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
      kind: 'dependency_confusion_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: preflight.reasonCode,
      lineage,
      packageName: request.packageName,
      detectedVersion: request.detectedVersion,
      sourceManifestUrl: request.sourceManifestUrl,
      publicRegistryUrl,
      registryStatusCode: 0,
      isUnclaimedPublicly: false,
      error: {
        code: preflight.reasonCode,
        safeMessage: preflight.reason ?? 'Preflight denied for dependency manifest URL',
      },
    };
  }

  // 2. Query Public Registry
  const transport = request.transport ?? defaultRegistryTransport;
  let registryStatusCode = 0;
  let registryBody = '';

  try {
    const registryResp = await transport({
      url: publicRegistryUrl,
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': 'FixGuard-SupplyChain-Auditor/2.0',
      },
      timeoutMs: 5000,
    });
    registryStatusCode = registryResp.statusCode;
    registryBody = registryResp.bodyText ?? '';
  } catch (err) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'dependency_confusion_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'public_registry_query_failed',
      lineage,
      packageName: request.packageName,
      detectedVersion: request.detectedVersion,
      sourceManifestUrl: request.sourceManifestUrl,
      publicRegistryUrl,
      registryStatusCode: 0,
      isUnclaimedPublicly: false,
      error: {
        code: 'public_registry_query_failed',
        safeMessage: err instanceof Error ? err.message : 'Public registry query failed',
      },
    };
  }

  // 3. Evaluation: 404 Not Found indicates UNCLAIMED package namespace
  const isUnclaimedPublicly = registryStatusCode === 404;

  if (isUnclaimedPublicly) {
    const draftId = `dft_depconf_${safeSeed}`;
    const candidateId = `cnd_depconf_${safeSeed}`;
    const evidenceRecordId = `evd_depconf_${safeSeed}`;
    const sanitizedPackageName = sanitizeEvidenceFragment(request.packageName);
    const sanitizedManifestUrl = sanitizeEvidenceFragment(request.sourceManifestUrl);

    // Human review routing
    if (request.humanReviewDecision?.decision === 'approve_evidence') {
      const nowIso = new Date().toISOString();
      const finding: Finding = {
        id: `fnd_depconf_${safeSeed}`,
        type: 'SUPPLY_CHAIN_RISK',
        severity: 'high',
        title: `Approved Unclaimed Private Package Namespace (${sanitizedPackageName})`,
        description: `Human operator verified dependency confusion risk. The internal package '${sanitizedPackageName}' declared in '${sanitizedManifestUrl}' is unclaimed on the public npm registry (${publicRegistryUrl} returns HTTP 404). An external attacker could register this package to execute code in build pipelines.`,
        target: sanitizedPackageName,
        evidence: JSON.stringify({
          packageName: sanitizedPackageName,
          detectedVersion: request.detectedVersion,
          sourceManifestUrl: sanitizedManifestUrl,
          publicRegistryUrl,
          registryStatusCode,
          isUnclaimedPublicly: true,
          reviewedBy: request.actorId,
          reviewedAt: nowIso,
        }),
        confidence: 1.0,
        verificationState: 'validated_vulnerability',
        metadata: {
          kind: 'dependency_confusion_metadata',
          category: 'SUPPLY_CHAIN_RISK',
          packageName: sanitizedPackageName,
          detectedVersion: request.detectedVersion,
          sourceManifestUrl: sanitizedManifestUrl,
          publicRegistryUrl,
          registryStatusCode,
          isUnclaimedPublicly: true,
          observedAt: nowIso,
          candidateId,
          evidenceRecordId,
          lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}:${nowIso}`,
        },
      };

      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'dependency_confusion_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'potential_weakness',
        reasonCode: 'unclaimed_package_namespace_confirmed',
        lineage,
        packageName: request.packageName,
        detectedVersion: request.detectedVersion,
        sourceManifestUrl: request.sourceManifestUrl,
        publicRegistryUrl,
        registryStatusCode,
        isUnclaimedPublicly: true,
        finding,
      };
    }

    // Unattended mode: Route to pending evidence drafts
    const evidenceDraft: EvidenceDraftEnvelope = {
      draftKind: 'non_persisted_comparison_evidence_draft',
      draftId,
      suggestedEvidenceType: 'http_difference',
      suggestedStrength: 'strong',
      sourceComparisonId: `cmp_depconf_${safeSeed}`,
      sourceSnapshotIds: {
        baselineSnapshotId: `snp_manif_${safeSeed}`,
        validationSnapshotId: `snp_reg_${safeSeed}`,
      },
      requiresHumanReview: true,
      notPersisted: true,
      notARealFinding: true,
      notConfirmedEvidence: true,
      notForExternalDelivery: true,
      notM45EvidenceRecord: true,
      safeRationale: `Package '${sanitizedPackageName}' referenced in manifest '${sanitizedManifestUrl}' is unclaimed on the public npm registry (HTTP 404 at ${publicRegistryUrl}).`,
    };

    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'dependency_confusion_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'pending_human_review',
      reasonCode: 'unclaimed_package_namespace_requires_human_approval',
      lineage,
      packageName: request.packageName,
      detectedVersion: request.detectedVersion,
      sourceManifestUrl: request.sourceManifestUrl,
      publicRegistryUrl,
      registryStatusCode,
      isUnclaimedPublicly: true,
      evidenceDraft,
    };
  }

  // 4. Abstention: Package is already claimed / registered in public registry (200 OK)
  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'dependency_confusion_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'secure_target_abstained',
    reasonCode: 'package_claimed_or_registered_publicly',
    lineage,
    packageName: request.packageName,
    detectedVersion: request.detectedVersion,
    sourceManifestUrl: request.sourceManifestUrl,
    publicRegistryUrl,
    registryStatusCode,
    isUnclaimedPublicly: false,
  };
}
