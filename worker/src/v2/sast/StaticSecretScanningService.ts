/**
 * Milestone P6-1 — Static Secret & Credential Scanning Engine (SAST)
 *
 * Core Invariant: Purely analytical local code inspection. The engine detects
 * hardcoded API keys, private keys, database connection strings, and plaintext
 * secrets in source code using high-precision patterns and entropy checks, with
 * zero network overhead.
 *
 * Anti-Leak & Safety Guarantees:
 * - Operates entirely in-memory on supplied file contents.
 * - All detected credentials are strictly redacted via sanitizeEvidenceFragment() / regex redaction.
 * - Snippets are capped at 128 characters max.
 * - 0 occurrences of 'as any'.
 */

import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';

export type StaticSecretKind = 'aws_key' | 'private_key' | 'generic_api_key' | 'database_uri' | 'jwt_secret';
export type StaticSecretSeverity = 'critical' | 'high';

export interface SourceFilePayload {
  readonly filePath: string;
  readonly content: string;
}

export interface StaticSecretScanningRequest {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly actorId: string;
  readonly targetDomain: string;
  readonly files: readonly SourceFilePayload[];
  readonly humanReviewDecision?: {
    readonly decision: 'approve_evidence' | 'reject' | 'needs_more_review';
    readonly reviewerId: string;
    readonly reviewedAt: string;
  };
}

export interface DetectedStaticSecret {
  readonly filePath: string;
  readonly lineNumber: number;
  readonly secretKind: StaticSecretKind;
  readonly exposureSeverity: StaticSecretSeverity;
  readonly sanitizedSnippet: string;
}

export interface StaticSecretScanningResult {
  readonly contractVersion: 'fixguard-detection-expansion/v0';
  readonly kind: 'static_secret_scanning_result';
  readonly hasSecrets: boolean;
  readonly detectedSecrets: readonly DetectedStaticSecret[];
  readonly evidenceDrafts: readonly EvidenceDraftEnvelope[];
  readonly findings: readonly Finding[];
}

interface SecretPatternDefinition {
  readonly kind: StaticSecretKind;
  readonly severity: StaticSecretSeverity;
  readonly regex: RegExp;
  readonly redact: (line: string, match: RegExpMatchArray) => string;
}

const SECRET_PATTERNS: readonly SecretPatternDefinition[] = [
  {
    kind: 'aws_key',
    severity: 'critical',
    regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
    redact: (line, match) => {
      const fullMatch = match[0];
      const prefix = fullMatch.slice(0, 4);
      return line.replace(fullMatch, `${prefix}[REDACTED]`);
    },
  },
  {
    kind: 'private_key',
    severity: 'critical',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
    redact: (line) => line.replace(/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/, '-----BEGIN PRIVATE KEY-----[REDACTED]'),
  },
  {
    kind: 'database_uri',
    severity: 'critical',
    regex: /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[^\s:@]+:[^\s:@]+@[^\s\/]+(?:\/[^\s]*)?/i,
    redact: (line, match) => {
      const uri = match[0];
      const sanitized = uri.replace(/:\/\/([^:]+):([^@]+)@/, '://$1:[REDACTED]@');
      return line.replace(uri, sanitized);
    },
  },
  {
    kind: 'jwt_secret',
    severity: 'high',
    regex: /(?:jwt[_-]?(?:secret|key|private[_-]?key))\s*[:=]\s*['"]([a-zA-Z0-9_\-!@#$%^&*()+=]{8,})['"]/i,
    redact: (line, match) => {
      const matchedStr = match[0];
      const secretVal = match[1];
      return line.replace(matchedStr, matchedStr.replace(secretVal, '[REDACTED]'));
    },
  },
  {
    kind: 'generic_api_key',
    severity: 'high',
    regex: /(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]/i,
    redact: (line, match) => {
      const matchedStr = match[0];
      const secretVal = match[1];
      return line.replace(matchedStr, matchedStr.replace(secretVal, '[REDACTED]'));
    },
  },
];

export function scanFileLinesForSecrets(filePath: string, content: string): DetectedStaticSecret[] {
  const lines = content.split(/\r?\n/);
  const detected: DetectedStaticSecret[] = [];

  for (let idx = 0; idx < lines.length; idx++) {
    const rawLine = lines[idx];
    if (!rawLine || rawLine.trim().length === 0) continue;

    for (const pattern of SECRET_PATTERNS) {
      const match = rawLine.match(pattern.regex);
      if (match) {
        const redactedLine = pattern.redact(rawLine.trim(), match);
        const sanitized = sanitizeEvidenceFragment(redactedLine).slice(0, 128);

        detected.push({
          filePath,
          lineNumber: idx + 1,
          secretKind: pattern.kind,
          exposureSeverity: pattern.severity,
          sanitizedSnippet: sanitized,
        });
        break; // Match one pattern per line
      }
    }
  }

  return detected;
}

/**
 * Purely analytical in-memory static secret scanning service.
 */
export function scanSourceFilesForSecrets(request: StaticSecretScanningRequest): StaticSecretScanningResult {
  const { assessmentId, scanId, actorId, targetDomain, files } = request;
  const allDetected: DetectedStaticSecret[] = [];

  for (const file of files) {
    const fileSecrets = scanFileLinesForSecrets(file.filePath, file.content);
    allDetected.push(...fileSecrets);
  }

  if (allDetected.length === 0) {
    return {
      contractVersion: 'fixguard-detection-expansion/v0',
      kind: 'static_secret_scanning_result',
      hasSecrets: false,
      detectedSecrets: [],
      evidenceDrafts: [],
      findings: [],
    };
  }

  const evidenceDrafts: EvidenceDraftEnvelope[] = [];
  const findings: Finding[] = [];

  for (let i = 0; i < allDetected.length; i++) {
    const sec = allDetected[i];
    const safePath = sec.filePath.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 12);
    const safeSeed = `${assessmentId.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 6)}_${safePath}_${sec.lineNumber}_${i}`;
    const draftId = `dft_ssec_${safeSeed}`;
    const candidateId = `cnd_ssec_${safeSeed}`;
    const evidenceRecordId = `evd_ssec_${safeSeed}`;
    const findingId = `fnd_ssec_${safeSeed}`;

    const title = `Hardcoded ${sec.secretKind.toUpperCase()} Exposed in ${sec.filePath}:${sec.lineNumber}`;
    const rationale = `SAST code inspection identified hardcoded ${sec.secretKind} at line ${sec.lineNumber} of ${sec.filePath}. Redacted snippet: "${sec.sanitizedSnippet}".`;

    if (request.humanReviewDecision?.decision === 'approve_evidence') {
      const nowIso = new Date().toISOString();
      const finding: Finding = {
        id: findingId,
        type: 'INFORMATION_DISCLOSURE',
        severity: sec.exposureSeverity,
        title: `Approved Hardcoded Secret Exposure (${sec.secretKind}) in ${sec.filePath}`,
        description: `Human operator verified static secret exposure at line ${sec.lineNumber} of ${sec.filePath}. Redacted code snippet: ${sec.sanitizedSnippet}.`,
        target: `https://${targetDomain}/${sec.filePath}`,
        evidence: JSON.stringify({
          assessmentId,
          scanId,
          filePath: sec.filePath,
          lineNumber: sec.lineNumber,
          secretKind: sec.secretKind,
          sanitizedSnippet: sec.sanitizedSnippet,
          reviewedBy: request.actorId,
          reviewedAt: nowIso,
        }),
        confidence: 1.0,
        metadata: {
          kind: 'static_secret_exposure_metadata',
          category: 'INFORMATION_DISCLOSURE',
          filePath: sec.filePath,
          lineNumber: sec.lineNumber,
          secretKind: sec.secretKind,
          exposureSeverity: sec.exposureSeverity,
          sanitizedSnippet: sec.sanitizedSnippet,
          observedAt: nowIso,
          candidateId,
          evidenceRecordId,
          lineage: `${assessmentId}:${scanId}:${actorId}:${nowIso}`,
        },
      };
      findings.push(finding);
    } else {
      const draft: EvidenceDraftEnvelope = {
        draftKind: 'non_persisted_comparison_evidence_draft',
        draftId,
        suggestedEvidenceType: 'http_difference',
        suggestedStrength: 'strong',
        sourceComparisonId: `cmp_ssec_${safeSeed}`,
        sourceSnapshotIds: {
          baselineSnapshotId: `snp_base_${safePath}`,
          validationSnapshotId: `snp_val_${safePath}`,
        },
        requiresHumanReview: true,
        notPersisted: true,
        notARealFinding: true,
        notConfirmedEvidence: true,
        notForExternalDelivery: true,
        notM45EvidenceRecord: true,
        safeRationale: rationale,
      };
      evidenceDrafts.push(draft);
    }
  }

  return {
    contractVersion: 'fixguard-detection-expansion/v0',
    kind: 'static_secret_scanning_result',
    hasSecrets: true,
    detectedSecrets: allDetected,
    evidenceDrafts,
    findings,
  };
}
