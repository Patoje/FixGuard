/**
 * Milestone P5-5 — Frontend Manifest and Environment Exposure Detection Engine
 *
 * Core Invariant: Safe, deterministic verification of exposed environment files (.env),
 * repository configuration (.git/config), and dependency manifests.
 * Strict anti-leak sanitization redacts raw secret values from evidence excerpts.
 *
 * Anti-Leak & Safety Guarantees:
 * - 7-pass SSRF preflight checks via runAdapterPreflight().
 * - Soft-404 / HTML Fallback discard to prevent SPA catch-all false positives.
 * - Secret value redaction: all KEY=VALUE variables in .env sanitized to KEY=[REDACTED].
 * - Evidence snippet capped to 128 chars and sanitized via sanitizeEvidenceFragment().
 * - 0 occurrences of 'as any'.
 */

import {
  DETECTION_CONTRACT_VERSION,
  type ManifestExposureDetectionRequest,
  type ManifestExposureDetectionResult,
  type IdorHttpProbeTransport,
  type HttpProbeRequest,
  type HttpProbeResponse,
} from './DetectionContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';
import { defaultHttpProbeTransport } from './IdorDifferentialDetectionService.js';

export const STANDARD_MANIFEST_PATHS = [
  '/.env',
  '/.env.local',
  '/.git/config',
  '/.git/HEAD',
  '/package.json',
  '/package-lock.json',
  '/composer.json',
  '/requirements.txt',
] as const;

export type StandardManifestPath = (typeof STANDARD_MANIFEST_PATHS)[number];

export interface FileClassification {
  readonly fileKind: 'env_file' | 'git_config' | 'package_manifest' | 'dependency_lockfile';
  readonly exposureSeverity: 'critical' | 'high' | 'medium';
}

export function classifyExposedFile(path: string): FileClassification {
  const lower = path.toLowerCase();
  if (lower.includes('.env')) {
    return { fileKind: 'env_file', exposureSeverity: 'critical' };
  }
  if (lower.includes('.git')) {
    return { fileKind: 'git_config', exposureSeverity: 'critical' };
  }
  if (lower.includes('lock') || lower.includes('requirements')) {
    return { fileKind: 'dependency_lockfile', exposureSeverity: 'medium' };
  }
  return { fileKind: 'package_manifest', exposureSeverity: 'medium' };
}

/**
 * Validates body content against deterministic signatures.
 * Returns false for HTML catch-all/soft-404 responses.
 */
export function validateContentSignature(
  path: string,
  body: string,
  contentType: string
): { isValid: boolean; sanitizedSnippet: string } {
  const cleanType = contentType.toLowerCase();
  const trimmed = body.trim();

  // 1. Discard soft-404 / HTML SPA fallbacks
  if (
    cleanType.includes('text/html') ||
    trimmed.startsWith('<!DOCTYPE html') ||
    trimmed.startsWith('<!doctype html') ||
    trimmed.startsWith('<html') ||
    trimmed.includes('<html') ||
    trimmed.includes('<head>') ||
    trimmed.includes('<body>')
  ) {
    return { isValid: false, sanitizedSnippet: '' };
  }

  const lowerPath = path.toLowerCase();

  // 2. .env files: must match KEY=VALUE lines
  if (lowerPath.includes('.env')) {
    const envLineRegex = /^[A-Za-z0-9_]+\s*=\s*.+/m;
    if (!envLineRegex.test(trimmed)) {
      return { isValid: false, sanitizedSnippet: '' };
    }
    // Redact secret values: KEY=secret -> KEY=[REDACTED]
    const redactedLines = trimmed
      .split(/\r?\n/)
      .slice(0, 5)
      .map((line) => {
        const eqIdx = line.indexOf('=');
        if (eqIdx > 0 && !line.startsWith('#')) {
          const key = line.slice(0, eqIdx).trim();
          return `${key}=[REDACTED]`;
        }
        return line;
      })
      .join('; ');
    const snippet = redactedLines.slice(0, 128);
    return { isValid: true, sanitizedSnippet: snippet };
  }

  // 3. .git/config or .git/HEAD
  if (lowerPath.includes('.git/config')) {
    if (trimmed.includes('[core]') || trimmed.includes('repositoryformatversion')) {
      const snippet = trimmed.slice(0, 128).replace(/[\r\n]+/g, ' ');
      return { isValid: true, sanitizedSnippet: snippet };
    }
    return { isValid: false, sanitizedSnippet: '' };
  }

  if (lowerPath.includes('.git/head')) {
    if (trimmed.startsWith('ref: refs/') || /^[a-f0-9]{40}$/i.test(trimmed)) {
      const snippet = trimmed.slice(0, 128).replace(/[\r\n]+/g, ' ');
      return { isValid: true, sanitizedSnippet: snippet };
    }
    return { isValid: false, sanitizedSnippet: '' };
  }

  // 4. package.json or composer.json
  if (lowerPath.endsWith('package.json') || lowerPath.endsWith('composer.json')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (
        parsed &&
        typeof parsed === 'object' &&
        (parsed.name || parsed.dependencies || parsed.devDependencies || parsed.require)
      ) {
        const snippet = JSON.stringify(parsed).slice(0, 128);
        return { isValid: true, sanitizedSnippet: snippet };
      }
    } catch {
      return { isValid: false, sanitizedSnippet: '' };
    }
    return { isValid: false, sanitizedSnippet: '' };
  }

  // 5. Lockfiles / requirements.txt
  if (lowerPath.endsWith('package-lock.json')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object' && (parsed.lockfileVersion || parsed.packages)) {
        const snippet = JSON.stringify(parsed).slice(0, 128);
        return { isValid: true, sanitizedSnippet: snippet };
      }
    } catch {
      return { isValid: false, sanitizedSnippet: '' };
    }
  }

  if (lowerPath.endsWith('requirements.txt')) {
    if (/^[A-Za-z0-9_.-]+(?:[><=~!]=?.*)?$/m.test(trimmed)) {
      const snippet = trimmed.slice(0, 128).replace(/[\r\n]+/g, ' ');
      return { isValid: true, sanitizedSnippet: snippet };
    }
  }

  return { isValid: false, sanitizedSnippet: '' };
}

/**
 * Main Detection Service for Frontend Manifest & Environment Exposure (Milestone P5-5).
 */
export async function runManifestExposureDetection(
  request: ManifestExposureDetectionRequest
): Promise<ManifestExposureDetectionResult> {
  const lineage = {
    assessmentId: request.assessmentId,
    scanId: request.scanId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const exposedFilePath = request.exposedFilePath ?? '/.env';
  const cleanPath = exposedFilePath.startsWith('/') ? exposedFilePath : `/${exposedFilePath}`;
  const base = request.targetBaseUrl.replace(/\/+$/, '');
  const endpointUrl = `${base}${cleanPath}`;
  const classification = classifyExposedFile(cleanPath);

  const safeSeed = `${request.detectionId.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 12)}${cleanPath.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 12)}`;

  // 1. SSRF Preflight
  const preflight = await runAdapterPreflight({
    target: endpointUrl,
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
      kind: 'manifest_exposure_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: preflight.reasonCode,
      lineage,
      exposedFilePath: cleanPath,
      endpointUrl,
      fileKind: classification.fileKind,
      exposureSeverity: classification.exposureSeverity,
      sanitizedSnippet: '',
      error: {
        code: preflight.reasonCode,
        safeMessage: preflight.reason ?? 'Preflight denied for manifest exposure probe',
      },
    };
  }

  // 2. Dispatch Bounded GET Probe
  const transport = request.transport ?? defaultHttpProbeTransport;
  let statusCode = 0;
  let bodyText = '';
  let contentType = '';

  try {
    const probeResp = await transport({
      url: endpointUrl,
      method: 'GET',
      headers: {
        Accept: 'application/json, text/plain, */*',
        'User-Agent': 'FixGuard-Defensive-Scanner/2.0',
      },
      timeoutMs: 5000,
    });
    statusCode = probeResp.statusCode;
    bodyText = probeResp.bodyText ?? '';
    contentType = probeResp.headers['content-type'] ?? '';
  } catch (err) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'manifest_exposure_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'manifest_probe_failed',
      lineage,
      exposedFilePath: cleanPath,
      endpointUrl,
      fileKind: classification.fileKind,
      exposureSeverity: classification.exposureSeverity,
      sanitizedSnippet: '',
      error: {
        code: 'manifest_probe_failed',
        safeMessage: err instanceof Error ? err.message : 'Manifest probe request failed',
      },
    };
  }

  // 3. Evaluate Status & Content Signature
  if (statusCode !== 200 || !bodyText || bodyText.trim().length === 0) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'manifest_exposure_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'non_200_or_empty_response',
      lineage,
      exposedFilePath: cleanPath,
      endpointUrl,
      fileKind: classification.fileKind,
      exposureSeverity: classification.exposureSeverity,
      sanitizedSnippet: '',
    };
  }

  const { isValid, sanitizedSnippet } = validateContentSignature(cleanPath, bodyText, contentType);

  if (!isValid) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'manifest_exposure_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'content_signature_mismatch_or_soft_404_html',
      lineage,
      exposedFilePath: cleanPath,
      endpointUrl,
      fileKind: classification.fileKind,
      exposureSeverity: classification.exposureSeverity,
      sanitizedSnippet: '',
    };
  }

  // 4. Vulnerability / Weakness Detected
  const sanitizedUrl = sanitizeEvidenceFragment(endpointUrl);
  const cleanSnippet = sanitizeEvidenceFragment(sanitizedSnippet);
  const draftId = `dft_manif_${safeSeed}`;
  const candidateId = `cnd_manif_${safeSeed}`;
  const evidenceRecordId = `evd_manif_${safeSeed}`;

  if (request.humanReviewDecision?.decision === 'approve_evidence') {
    const nowIso = new Date().toISOString();
    const isCritical = classification.exposureSeverity === 'critical';
    const finding: Finding = {
      id: `fnd_manif_${safeSeed}`,
      type: 'INFORMATION_DISCLOSURE',
      severity: classification.exposureSeverity,
      title: isCritical
        ? `Approved Critical Environment File Exposure (${cleanPath})`
        : `Approved Build/Dependency Manifest Exposure (${cleanPath})`,
      description: isCritical
        ? `Human operator verified sensitive environment/configuration file exposed on '${sanitizedUrl}'. The endpoint returns valid configuration content. Secret values have been redacted.`
        : `Human operator verified public exposure of manifest file on '${sanitizedUrl}'. The file exposes dependency topologies and package structure.`,
      target: sanitizedUrl,
      evidence: JSON.stringify({
        exposedFilePath: cleanPath,
        endpointUrl: sanitizedUrl,
        fileKind: classification.fileKind,
        exposureSeverity: classification.exposureSeverity,
        sanitizedSnippet: cleanSnippet,
        reviewedBy: request.actorId,
        reviewedAt: nowIso,
      }),
      confidence: 1.0,
      metadata: {
        kind: 'manifest_exposure_metadata',
        category: 'INFORMATION_DISCLOSURE',
        exposedFilePath: cleanPath,
        endpointUrl: sanitizedUrl,
        fileKind: classification.fileKind,
        exposureSeverity: classification.exposureSeverity,
        sanitizedSnippet: cleanSnippet,
        observedAt: nowIso,
        candidateId,
        evidenceRecordId,
        lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}:${nowIso}`,
      },
    };

    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'manifest_exposure_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: isCritical ? 'vulnerability_detected' : 'potential_weakness',
      reasonCode: 'manifest_exposure_confirmed_by_operator',
      lineage,
      exposedFilePath: cleanPath,
      endpointUrl: sanitizedUrl,
      fileKind: classification.fileKind,
      exposureSeverity: classification.exposureSeverity,
      sanitizedSnippet: cleanSnippet,
      finding,
    };
  }

  // Unattended mode: Route to pending evidence drafts
  const evidenceDraft: EvidenceDraftEnvelope = {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId,
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: 'strong',
    sourceComparisonId: `cmp_manif_${safeSeed}`,
    sourceSnapshotIds: {
      baselineSnapshotId: `snp_exp_${safeSeed}`,
      validationSnapshotId: `snp_val_${safeSeed}`,
    },
    requiresHumanReview: true,
    notPersisted: true,
    notARealFinding: true,
    notConfirmedEvidence: true,
    notForExternalDelivery: true,
    notM45EvidenceRecord: true,
    safeRationale: `Sensitive file '${cleanPath}' publicly accessible at '${sanitizedUrl}'. Sanitized excerpt: ${cleanSnippet}`,
  };

  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'manifest_exposure_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'pending_human_review',
    reasonCode: 'manifest_exposure_requires_human_approval',
    lineage,
    exposedFilePath: cleanPath,
    endpointUrl: sanitizedUrl,
    fileKind: classification.fileKind,
    exposureSeverity: classification.exposureSeverity,
    sanitizedSnippet: cleanSnippet,
    evidenceDraft,
  };
}
