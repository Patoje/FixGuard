import type { ProcessRunner } from '../../core/ProcessRunner.js';
import {
  runAdapterPreflight,
  type PreSpawnDnsResolver,
} from './AdapterPreflightPipeline.js';
import {
  SECRET_DISCOVERY_CONTRACT_VERSION,
  SECRET_DISCOVERY_NON_CLAIMS,
  type DiscoveredSecretObservation,
  type SecretDiscoveryRequest,
  type SecretDiscoveryResult,
  type SecretScannerTool,
} from './SecretDiscoveryContracts.js';

export function maskSecret(secret: string): string {
  if (!secret || typeof secret !== 'string') {
    return '[REDACTED]';
  }
  const trimmed = secret.trim();
  if (trimmed.length <= 4) {
    return '****';
  }
  const prefix = trimmed.slice(0, 4);
  const maskLength = Math.max(4, Math.min(trimmed.length - 4, 32));
  return `${prefix}${'*'.repeat(maskLength)}`;
}

function determineLocationUrl(rawTarget: string, relativeFilePath?: string): string {
  if (!relativeFilePath) {
    return rawTarget;
  }
  if (rawTarget.startsWith('http://') || rawTarget.startsWith('https://')) {
    const cleanTarget = rawTarget.replace(/\/$/, '');
    const cleanFile = relativeFilePath.replace(/^\//, '');
    return `${cleanTarget}/${cleanFile}`;
  }
  if (relativeFilePath.startsWith('/')) {
    return relativeFilePath;
  }
  const cleanTarget = rawTarget.replace(/\/$/, '');
  const cleanFile = relativeFilePath.replace(/^\//, '');
  return `${cleanTarget}/${cleanFile}`;
}

export class TrufflehogAdapter implements SecretScannerTool {
  constructor(
    private readonly processRunner: ProcessRunner,
    private readonly dnsResolver?: PreSpawnDnsResolver
  ) {}

  async scanSecrets(request: SecretDiscoveryRequest): Promise<SecretDiscoveryResult> {
    const rawTarget = typeof request.targetUrlOrPath === 'string' ? request.targetUrlOrPath.trim() : '';

    // Unified Atomic Preflight Gate
    const preflight = await runAdapterPreflight({
      target: rawTarget,
      targetKind: 'git_url_or_filesystem',
      scanType: request.scanType,
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.authorizedScopeGrant,
      lineage: request.lineage,
      permissionCheck: (ps) =>
        Boolean(
          ps.endpointDiscovery ||
          ps.passiveRecon ||
          ps.activeValidation ||
          ps.lightValidation ||
          ps.technologyFingerprinting ||
          ('activeRecon' in ps && (ps as { activeRecon?: boolean }).activeRecon)
        ),
      missingPermissionReason: 'Scope grant does not permit secret scanning or reconnaissance',
      targetOutOfScopeReason: 'Target URL host is outside authorized scope boundaries',
      dnsResolver: this.dnsResolver,
    });

    if (!preflight.ok) {
      return {
        status: 'preflight_denied',
        contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrPath: rawTarget,
        reasonCode: preflight.reasonCode,
        reason: preflight.reason,
        explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    const looksLikeUrl = rawTarget.startsWith('http://') || rawTarget.startsWith('https://');
    const isGit = looksLikeUrl || request.scanType === 'git';

    // Execution Phase: Spawn trufflehog via ProcessRunner with isolated argument array
    const args = isGit
      ? ['git', rawTarget, '--json', '--no-verification']
      : ['filesystem', rawTarget, '--json'];

    const timeoutMs = request.timeoutMs ?? 60_000;

    let output;
    try {
      output = await this.processRunner.execute({
        binary: 'trufflehog',
        args,
        timeoutMs,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        status: 'execution_failed',
        contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrPath: rawTarget,
        reasonCode: 'process_launch_failed',
        reason: msg,
        explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    if (output.timedOut) {
      return {
        status: 'execution_failed',
        contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrPath: rawTarget,
        reasonCode: 'execution_timed_out',
        reason: `Trufflehog execution timed out after ${timeoutMs}ms`,
        explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: output.exitCode,
        stderr: output.stderr,
        durationMs: output.durationMs,
      };
    }

    // Trufflehog exits with 0 (clean) or 183 (findings detected) on success
    if (output.exitCode !== 0 && output.exitCode !== 183) {
      return {
        status: 'execution_failed',
        contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrPath: rawTarget,
        reasonCode: 'process_execution_failed',
        reason: output.stderr.trim() || `Trufflehog exited with code ${output.exitCode}`,
        explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: output.exitCode,
        stderr: output.stderr,
        durationMs: output.durationMs,
      };
    }

    // Parsing & Strict Secret Redaction Phase
    const observations: DiscoveredSecretObservation[] = [];
    const seen = new Set<string>();

    const lines = output.stdout.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        // Corrupted or non-JSON lines fail closed safely
        continue;
      }

      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        continue;
      }

      const rec = parsed as Record<string, unknown>;

      const detectorName =
        typeof rec.DetectorName === 'string' && rec.DetectorName.trim()
          ? rec.DetectorName.trim()
          : 'UnknownDetector';

      // Extract raw secret candidate for immediate masking ONLY
      let rawSecretCandidate = '';
      if (typeof rec.Redacted === 'string' && rec.Redacted.trim()) {
        rawSecretCandidate = rec.Redacted;
      } else if (typeof rec.Raw === 'string' && rec.Raw.trim()) {
        rawSecretCandidate = rec.Raw;
      } else if (typeof rec.RawV2 === 'string' && rec.RawV2.trim()) {
        rawSecretCandidate = rec.RawV2;
      }

      // Enforce strict redaction — raw plaintext secret is never assigned to output DTO
      const redactedSecret = maskSecret(rawSecretCandidate);
      rawSecretCandidate = ''; // Clear immediate variable

      let relativeFilePath = '';
      if (rec.SourceMetadata && typeof rec.SourceMetadata === 'object') {
        const sm = rec.SourceMetadata as Record<string, unknown>;
        if (sm.Data && typeof sm.Data === 'object') {
          const data = sm.Data as Record<string, unknown>;
          if (data.Git && typeof data.Git === 'object') {
            const git = data.Git as Record<string, unknown>;
            if (typeof git.file === 'string') {
              relativeFilePath = git.file;
            }
          } else if (data.Filesystem && typeof data.Filesystem === 'object') {
            const fsData = data.Filesystem as Record<string, unknown>;
            if (typeof fsData.file === 'string') {
              relativeFilePath = fsData.file;
            }
          } else if (typeof data.file === 'string') {
            relativeFilePath = data.file;
          }
        }
      }

      const locationUrl = determineLocationUrl(rawTarget, relativeFilePath);
      const verified = typeof rec.Verified === 'boolean' ? rec.Verified : undefined;

      const dedupKey = `${locationUrl}|${detectorName}|${redactedSecret}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      observations.push({
        locationUrl,
        detectorName,
        redactedSecret,
        discoveredAt: new Date().toISOString(),
        collectedAt: new Date().toISOString(),
        freshness: 'live',
        sourceReliability: 'direct_observation',
        ...(verified !== undefined ? { verified } : {}),
      });
    }

    return {
      status: 'success',
      contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
      targetUrlOrPath: rawTarget,
      observations,
      explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
      lineage: request.lineage,
      durationMs: output.durationMs,
    };
  }
}
