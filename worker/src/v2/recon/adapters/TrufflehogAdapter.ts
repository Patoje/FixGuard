import path from 'node:path';
import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { isRuntimeEstablishedVerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionService.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
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

const FORBIDDEN_PATH_PREFIXES = [
  '/etc',
  '/root',
  '/var/run',
  '/proc',
  '/sys',
  '/dev',
  '/boot',
  '/sbin',
  '/bin',
];

export class TrufflehogAdapter implements SecretScannerTool {
  constructor(private readonly processRunner: ProcessRunner) {}

  async scanSecrets(request: SecretDiscoveryRequest): Promise<SecretDiscoveryResult> {
    const rawTarget = typeof request.targetUrlOrPath === 'string' ? request.targetUrlOrPath.trim() : '';

    // 1. Atomic Preflight: Target validation (URL or Safe Filesystem Path)
    if (!rawTarget) {
      return {
        status: 'preflight_denied',
        contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrPath: request.targetUrlOrPath,
        reasonCode: 'invalid_target_format',
        reason: 'Target URL or filesystem path cannot be empty',
        explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    const looksLikeUrl = rawTarget.startsWith('http://') || rawTarget.startsWith('https://');
    const isGit = looksLikeUrl || request.scanType === 'git';

    let targetHost = '';
    if (isGit) {
      try {
        const u = new URL(rawTarget);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') {
          return {
            status: 'preflight_denied',
            contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
            targetUrlOrPath: rawTarget,
            reasonCode: 'invalid_target_format',
            reason: 'Git target URL protocol must be HTTP or HTTPS',
            explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
            lineage: request.lineage,
          };
        }
        targetHost = u.hostname.trim().toLowerCase().replace(/\.$/, '');
      } catch {
        return {
          status: 'preflight_denied',
          contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
          targetUrlOrPath: rawTarget,
          reasonCode: 'invalid_target_format',
          reason: 'Git target URL is malformed',
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: request.lineage,
        };
      }

      if (!targetHost) {
        return {
          status: 'preflight_denied',
          contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
          targetUrlOrPath: rawTarget,
          reasonCode: 'invalid_target_host',
          reason: 'Git target URL does not contain a valid host',
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: request.lineage,
        };
      }
    } else {
      // Filesystem target path safety check
      if (rawTarget.includes('..')) {
        return {
          status: 'preflight_denied',
          contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
          targetUrlOrPath: rawTarget,
          reasonCode: 'unsafe_target_path',
          reason: 'Path traversal (..) is strictly prohibited in filesystem targets',
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: request.lineage,
        };
      }

      const normalized = path.normalize(rawTarget);
      if (normalized.includes('..')) {
        return {
          status: 'preflight_denied',
          contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
          targetUrlOrPath: rawTarget,
          reasonCode: 'unsafe_target_path',
          reason: 'Path traversal (..) is strictly prohibited in filesystem targets',
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: request.lineage,
        };
      }

      for (const prefix of FORBIDDEN_PATH_PREFIXES) {
        if (normalized === prefix || normalized.startsWith(prefix + '/')) {
          return {
            status: 'preflight_denied',
            contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
            targetUrlOrPath: rawTarget,
            reasonCode: 'unsafe_target_path',
            reason: `Filesystem target path accesses forbidden system directory: ${prefix}`,
            explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
            lineage: request.lineage,
          };
        }
      }
    }

    // 2. Atomic Preflight: Runtime-branded authorization verification
    if (
      !request.verifiedAuthorizationDecision ||
      !isRuntimeEstablishedVerifiedAuthorizationDecision(request.verifiedAuthorizationDecision)
    ) {
      return {
        status: 'preflight_denied',
        contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrPath: rawTarget,
        reasonCode: 'authorization_unconfirmed',
        reason: 'Authorization decision is not runtime-established or lacks valid verification brand',
        explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    if (request.verifiedAuthorizationDecision.decision !== 'authorized') {
      return {
        status: 'preflight_denied',
        contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrPath: rawTarget,
        reasonCode: 'authorization_denied',
        reason: 'Authorization decision is not in authorized state',
        explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 3. Atomic Preflight: Continuous Lineage tuple integrity verification
    const dec = request.verifiedAuthorizationDecision;
    const grant = request.authorizedScopeGrant;
    const lin = request.lineage;

    if (
      lin.scanId !== dec.scanId ||
      lin.assessmentId !== dec.assessmentId ||
      lin.authorizationGrantId !== grant.grantId ||
      lin.authorizationDecisionId !== dec.authorizationDecisionId
    ) {
      return {
        status: 'preflight_denied',
        contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrPath: rawTarget,
        reasonCode: 'lineage_mismatch',
        reason: 'Execution lineage does not match authorization decision and scope grant',
        explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 4. Atomic Preflight: Scope permissions check
    const ps = grant.permissionSet;
    let hasPermission = Boolean(
      ps.endpointDiscovery ||
      ps.passiveRecon ||
      ps.activeValidation ||
      ps.lightValidation ||
      ps.technologyFingerprinting
    );
    if (!hasPermission && 'activeRecon' in ps) {
      const ext = ps as typeof ps & { activeRecon?: boolean };
      if (ext.activeRecon) {
        hasPermission = true;
      }
    }

    if (!hasPermission) {
      return {
        status: 'preflight_denied',
        contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrPath: rawTarget,
        reasonCode: 'missing_permission',
        reason: 'Scope grant does not permit secret scanning or reconnaissance',
        explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 5. Atomic Preflight: Scope boundaries & SSRF check (for Git/URL targets)
    if (isGit && targetHost) {
      // 5a. SSRF containment on target hostname
      if (isInternalOrSsrfTarget(targetHost)) {
        return {
          status: 'preflight_denied',
          contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
          targetUrlOrPath: rawTarget,
          reasonCode: 'ssrf_target_blocked',
          reason: 'Target URL host points to prohibited internal, loopback, or metadata address',
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: request.lineage,
        };
      }

      // 5b. Scope boundaries check
      const allowedDomains = (grant.boundaries.allowedDomains ?? []).map((d) =>
        d.trim().toLowerCase().replace(/\.$/, '')
      );
      const allowedHosts = (grant.boundaries.allowedHosts ?? []).map((h) =>
        h.trim().toLowerCase().replace(/\.$/, '')
      );
      const subjectDomain = grant.subject.domain?.trim().toLowerCase().replace(/\.$/, '');
      const subjectHost = grant.subject.host?.trim().toLowerCase().replace(/\.$/, '');

      const originHosts: string[] = [];
      for (const origin of grant.boundaries.allowedOrigins ?? []) {
        try {
          const u = new URL(origin);
          originHosts.push(u.hostname.trim().toLowerCase().replace(/\.$/, ''));
        } catch {
          // ignore
        }
      }

      const isHostInScope =
        allowedDomains.includes(targetHost) ||
        allowedDomains.some((d) => targetHost.endsWith('.' + d)) ||
        allowedHosts.includes(targetHost) ||
        subjectDomain === targetHost ||
        subjectHost === targetHost ||
        originHosts.includes(targetHost) ||
        originHosts.some((h) => targetHost.endsWith('.' + h));

      if (!isHostInScope) {
        return {
          status: 'preflight_denied',
          contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
          targetUrlOrPath: rawTarget,
          reasonCode: 'target_out_of_scope',
          reason: 'Target URL host is outside authorized scope boundaries',
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: request.lineage,
        };
      }
    }

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
