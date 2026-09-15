/**
 * FixGuard V2 — Milestone P2-5 TLS Configuration Analysis Engine
 *
 * Implements pure analytical evaluation over Stage 3 TLS reconnaissance observations:
 * - Identifies insecure protocols (SSLv2, SSLv3) and deprecated protocols (TLS 1.0, TLS 1.1)
 * - Detects weak/insecure cipher suites (RC4, 3DES, DES, NULL, EXPORT, MD5)
 * - Evaluates certificate health (expired, self-signed, SAN mismatch)
 *
 * Crucial Invariants:
 * - Purely Analytical: Consumes existing DiscoveredTlsObservation records. Requires ZERO network calls.
 * - Evidence & Severity Discipline: Insecure protocols (SSLv2/SSLv3) produce 'vulnerability_detected' with severity: 'high'.
 *   Deprecated protocols, weak ciphers, and certificate flaws produce 'potential_weakness'.
 * - Clean Abstention: Modern configurations (TLS 1.2/1.3, strong ciphers, valid certificates) cleanly return status: 'secure_target_abstained'.
 * - Lineage Preservation: Continuous lineage tuple preserved across all detection results.
 * - Human-in-the-loop: Unattended runs return status: 'pending_human_review' routing to pendingEvidenceDrafts.
 */

import type {
  TlsConfigurationAnalysisRequest,
  TlsConfigurationAnalysisResult,
  TlsCertificateIssue,
  TlsAnalysisStatus,
} from './DetectionContracts.js';
import { DETECTION_CONTRACT_VERSION } from './DetectionContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import type { DiscoveredTlsObservation } from '../recon/adapters/TlsInspectionContracts.js';

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : '001';
}

const INSECURE_PROTOCOLS = new Set(['ssl2', 'ssl3', 'sslv2', 'sslv3', 'ssl 2.0', 'ssl 3.0']);
const DEPRECATED_PROTOCOLS = new Set(['tls10', 'tls11', 'tls1.0', 'tls1.1', 'tlsv1.0', 'tlsv1.1', 'tls 1.0', 'tls 1.1']);

const WEAK_CIPHER_PATTERNS = [
  /_RC4_/i,
  /RC4-/i,
  /_3DES_/i,
  /3DES-/i,
  /DES-CBC3/i,
  /_DES_/i,
  /DES-/i,
  /_NULL_/i,
  /NULL-/i,
  /_EXPORT_/i,
  /EXPORT-/i,
  /_RC2_/i,
  /RC2-/i,
  /_MD5/i,
  /-MD5/i,
];

export function isWeakCipher(cipherName: string): boolean {
  if (!cipherName) return false;
  return WEAK_CIPHER_PATTERNS.some((pattern) => pattern.test(cipherName));
}

export function matchesSan(host: string, san: string): boolean {
  const normHost = host.toLowerCase().trim();
  const normSan = san.toLowerCase().trim();

  if (normHost === normSan) return true;

  if (normSan.startsWith('*.')) {
    const domainPart = normSan.slice(2);
    if (normHost.endsWith(`.${domainPart}`)) {
      const prefix = normHost.slice(0, -(domainPart.length + 1));
      // Wildcard matches single sub-level
      return !prefix.includes('.');
    }
  }

  return false;
}

export function evaluateTlsObservation(
  targetHost: string,
  observation: DiscoveredTlsObservation
): {
  weakProtocols: string[];
  weakCiphers: string[];
  certificateIssues: TlsCertificateIssue[];
  supportedTlsVersions: string[];
  hasInsecureProtocol: boolean;
  hasDeprecatedProtocol: boolean;
} {
  const weakProtocols: string[] = [];
  const supportedTlsVersions: string[] = [...(observation.supportedProtocols || [])];
  let hasInsecureProtocol = false;
  let hasDeprecatedProtocol = false;

  for (const proto of observation.supportedProtocols || []) {
    const normalized = proto.toLowerCase().trim();
    if (INSECURE_PROTOCOLS.has(normalized)) {
      weakProtocols.push(proto);
      hasInsecureProtocol = true;
    } else if (DEPRECATED_PROTOCOLS.has(normalized)) {
      weakProtocols.push(proto);
      hasDeprecatedProtocol = true;
    }
  }

  const weakCiphers: string[] = [];
  for (const cipher of observation.cipherSuites || []) {
    if (isWeakCipher(cipher)) {
      weakCiphers.push(cipher);
    }
  }

  const certificateIssues: TlsCertificateIssue[] = [];

  // Certificate Expiry check
  if (observation.expired === true) {
    certificateIssues.push('expired');
  } else if (observation.notAfter) {
    try {
      const expiryTime = new Date(observation.notAfter).getTime();
      if (!Number.isNaN(expiryTime) && expiryTime < Date.now()) {
        certificateIssues.push('expired');
      }
    } catch {
      // Safe error containment
    }
  }

  // Self-signed certificate check
  if (observation.selfSigned === true) {
    certificateIssues.push('self_signed');
  } else if (observation.issuer) {
    const issuerLower = observation.issuer.toLowerCase();
    if (issuerLower.includes('self-signed') || issuerLower.includes('self signed') || issuerLower.includes('localhost')) {
      certificateIssues.push('self_signed');
    }
  }

  // SAN matching check (if SANs are provided)
  if (observation.subjectAlternativeNames && observation.subjectAlternativeNames.length > 0) {
    const matchesAny = observation.subjectAlternativeNames.some((san) =>
      matchesSan(targetHost, san)
    );
    if (!matchesAny) {
      certificateIssues.push('invalid_san');
    }
  }

  return {
    weakProtocols,
    weakCiphers,
    certificateIssues,
    supportedTlsVersions,
    hasInsecureProtocol,
    hasDeprecatedProtocol,
  };
}

export function analyzeTlsConfiguration(
  request: TlsConfigurationAnalysisRequest
): TlsConfigurationAnalysisResult {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const safeSeed = sanitizeToSafeId(request.detectionId);
  const nowIso = new Date().toISOString();
  const port = request.port ?? request.tlsObservation.port ?? 443;

  const {
    weakProtocols,
    weakCiphers,
    certificateIssues,
    supportedTlsVersions,
    hasInsecureProtocol,
    hasDeprecatedProtocol,
  } = evaluateTlsObservation(request.targetHost, request.tlsObservation);

  const totalFlawsCount = weakProtocols.length + weakCiphers.length + certificateIssues.length;

  // 1. If no weak protocols, weak ciphers, or certificate issues -> Cleanly Abstain
  if (totalFlawsCount === 0) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'tls_configuration_analysis_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'tls_configuration_secure',
      lineage,
      targetHost: request.targetHost,
      port,
      weakProtocols: [],
      weakCiphers: [],
      certificateIssues: [],
      supportedTlsVersions,
    };
  }

  // 2. Human Review Decision Supplied -> Produce Finding
  const candidateId = `cnd_tls_${safeSeed}`;
  const evidenceRecordId = `evd_tls_${safeSeed}`;
  const draftId = `dft_tls_${safeSeed}`;

  if (request.humanReviewDecision) {
    if (request.humanReviewDecision.decision === 'approve_evidence') {
      const status: TlsAnalysisStatus = hasInsecureProtocol ? 'vulnerability_detected' : 'potential_weakness';
      const severity: 'high' | 'medium' | 'low' = hasInsecureProtocol
        ? 'high'
        : hasDeprecatedProtocol || certificateIssues.includes('expired') || certificateIssues.includes('self_signed')
        ? 'medium'
        : 'low';

      const flawDescriptions: string[] = [];
      if (weakProtocols.length > 0) flawDescriptions.push(`Protocols: ${weakProtocols.join(', ')}`);
      if (weakCiphers.length > 0) flawDescriptions.push(`Weak Ciphers: ${weakCiphers.join(', ')}`);
      if (certificateIssues.length > 0) flawDescriptions.push(`Cert Issues: ${certificateIssues.join(', ')}`);

      const finding: Finding = {
        id: `fnd_tls_${safeSeed}`,
        type: 'SECURITY_MISCONFIGURATION',
        severity,
        title: `Weak TLS Configuration on ${request.targetHost}:${port}`,
        description: `Target host '${request.targetHost}:${port}' exhibits TLS configuration weaknesses: ${flawDescriptions.join(' | ')}.`,
        target: `https://${request.targetHost}:${port}`,
        evidence: JSON.stringify({
          targetHost: request.targetHost,
          port,
          weakProtocols,
          weakCiphers,
          certificateIssues,
          supportedTlsVersions,
          reviewedBy: request.humanReviewDecision.reviewerId,
          reviewedAt: request.humanReviewDecision.reviewedAt,
        }),
        confidence: 0.95,
        metadata: {
          kind: 'weak_tls_metadata',
          category: 'SECURITY_MISCONFIGURATION',
          targetHost: request.targetHost,
          port,
          weakProtocols,
          weakCiphers,
          certificateIssues,
          supportedTlsVersions,
          observedAt: nowIso,
          endpointUrl: `https://${request.targetHost}:${port}`,
          candidateId,
          evidenceRecordId,
          lineage,
        },
      };

      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'tls_configuration_analysis_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status,
        reasonCode: hasInsecureProtocol ? 'insecure_tls_protocol_detected' : 'weak_tls_configuration_observed',
        lineage,
        targetHost: request.targetHost,
        port,
        weakProtocols,
        weakCiphers,
        certificateIssues,
        supportedTlsVersions,
        finding,
      };
    }

    if (request.humanReviewDecision.decision === 'reject') {
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'tls_configuration_analysis_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'secure_target_abstained',
        reasonCode: 'human_review_rejected',
        lineage,
        targetHost: request.targetHost,
        port,
        weakProtocols,
        weakCiphers,
        certificateIssues,
        supportedTlsVersions,
      };
    }
  }

  // 3. Unreviewed -> Produce EvidenceDraft for Human Triage
  const rationaleParts: string[] = [];
  if (weakProtocols.length > 0) rationaleParts.push(`Insecure/deprecated protocols (${weakProtocols.join(', ')})`);
  if (weakCiphers.length > 0) rationaleParts.push(`Weak ciphers (${weakCiphers.join(', ')})`);
  if (certificateIssues.length > 0) rationaleParts.push(`Certificate anomalies (${certificateIssues.join(', ')})`);

  const draftEnvelope: EvidenceDraftEnvelope = {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId,
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: hasInsecureProtocol ? 'strong' : 'moderate',
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
    safeRationale: `Target host '${request.targetHost}:${port}' exhibits TLS weaknesses: ${rationaleParts.join('; ')}`,
  };

  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'tls_configuration_analysis_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'pending_human_review',
    reasonCode: 'weak_tls_configuration_observed',
    lineage,
    targetHost: request.targetHost,
    port,
    weakProtocols,
    weakCiphers,
    certificateIssues,
    supportedTlsVersions,
    evidenceDraft: draftEnvelope,
  };
}
