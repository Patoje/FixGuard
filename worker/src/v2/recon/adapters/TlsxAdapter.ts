import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  runAdapterPreflight,
  type PreSpawnDnsResolver,
} from './AdapterPreflightPipeline.js';
import {
  TLS_INSPECTION_CONTRACT_VERSION,
  TLS_INSPECTION_NON_CLAIMS,
  type DiscoveredTlsObservation,
  type TlsInspectionRequest,
  type TlsInspectionResult,
  type TlsInspectionTool,
} from './TlsInspectionContracts.js';

export class TlsxAdapter implements TlsInspectionTool {
  constructor(
    private readonly processRunner: ProcessRunner,
    private readonly dnsResolver?: PreSpawnDnsResolver
  ) {}

  async inspectTls(request: TlsInspectionRequest): Promise<TlsInspectionResult> {
    const rawInput = typeof request.targetHostOrUrl === 'string' ? request.targetHostOrUrl.trim() : '';

    // Unified Atomic Preflight Gate
    const preflight = await runAdapterPreflight({
      target: rawInput,
      targetKind: 'host_or_url',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.authorizedScopeGrant,
      lineage: request.lineage,
      permissionCheck: (ps) =>
        Boolean(
          ps.technologyFingerprinting ||
          ps.endpointDiscovery ||
          ps.activeValidation ||
          ps.lightValidation ||
          ps.passiveRecon ||
          ('activeRecon' in ps && (ps as { activeRecon?: boolean }).activeRecon)
        ),
      missingPermissionReason: 'Scope grant does not permit TLS inspection or technology fingerprinting',
      targetOutOfScopeReason: 'Target host is outside authorized scope boundaries',
      dnsResolver: this.dnsResolver,
    });

    if (!preflight.ok) {
      return {
        status: 'preflight_denied',
        contractVersion: TLS_INSPECTION_CONTRACT_VERSION,
        targetHost: rawInput,
        reasonCode: preflight.reasonCode,
        reason: preflight.reason,
        explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    const targetHost = preflight.targetHost!;
    const extractedPort = preflight.extractedPort;

    // Execution Phase: Assemble isolated tlsx CLI arguments
    const args = [
      '-u', targetHost,
      '-json',
      '-san',
      '-ve',
    ];

    // Determine target ports
    const targetPortsSet = new Set<number>();
    if (extractedPort) {
      targetPortsSet.add(extractedPort);
    }
    if (request.targetPorts && request.targetPorts.length > 0) {
      for (const p of request.targetPorts) {
        if (typeof p === 'number' && p > 0 && p <= 65535) {
          targetPortsSet.add(p);
        }
      }
    }

    if (targetPortsSet.size > 0) {
      const sortedPorts = Array.from(targetPortsSet).sort((a, b) => a - b);
      args.push('-p', sortedPorts.join(','));
    }

    const timeoutMs = request.timeoutMs ?? 60_000;

    let output;
    try {
      output = await this.processRunner.execute({
        binary: 'tlsx',
        args,
        timeoutMs,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        status: 'execution_failed',
        contractVersion: TLS_INSPECTION_CONTRACT_VERSION,
        targetHost,
        reasonCode: 'process_launch_failed',
        reason: msg,
        explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    if (output.timedOut) {
      return {
        status: 'execution_failed',
        contractVersion: TLS_INSPECTION_CONTRACT_VERSION,
        targetHost,
        reasonCode: 'execution_timed_out',
        reason: `tlsx execution timed out after ${timeoutMs}ms`,
        explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: output.exitCode,
        stderr: output.stderr,
        durationMs: output.durationMs,
      };
    }

    if (output.exitCode !== 0) {
      return {
        status: 'execution_failed',
        contractVersion: TLS_INSPECTION_CONTRACT_VERSION,
        targetHost,
        reasonCode: 'process_execution_failed',
        reason: output.stderr.trim() || `tlsx exited with non-zero exit code: ${output.exitCode}`,
        explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: output.exitCode,
        stderr: output.stderr,
        durationMs: output.durationMs,
      };
    }

    // Parsing & Deep SSRF Post-Execution Gate Phase
    const observations: DiscoveredTlsObservation[] = [];
    const seen = new Set<string>();

    const lines = output.stdout.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      let rec: Record<string, unknown>;
      try {
        const parsed = JSON.parse(trimmed);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          continue;
        }
        rec = parsed as Record<string, unknown>;
      } catch {
        // Malformed non-JSON lines fail closed safely
        continue;
      }

      // Deep SSRF Post-Execution Gate on resolved target IP
      const resolvedIp = typeof rec.ip === 'string' && rec.ip.trim() ? rec.ip.trim() : undefined;
      if (resolvedIp && isInternalOrSsrfTarget(resolvedIp)) {
        // Resolved IP points to loopback, RFC-1918, or cloud metadata -> DROP observation!
        continue;
      }

      const host = typeof rec.host === 'string' && rec.host.trim()
        ? rec.host.trim().toLowerCase().replace(/\.$/, '')
        : targetHost;

      if (isInternalOrSsrfTarget(host)) {
        continue;
      }

      const port = typeof rec.port === 'number'
        ? rec.port
        : typeof rec.port === 'string'
        ? parseInt(rec.port, 10) || 443
        : 443;

      const certResp = rec.certificate_response && typeof rec.certificate_response === 'object'
        ? (rec.certificate_response as Record<string, unknown>)
        : undefined;

      // Extract SANs
      const rawSans: unknown = certResp?.subject_an ?? rec.subject_an ?? rec.san;
      const subjectAlternativeNames: string[] = Array.isArray(rawSans)
        ? rawSans.map((s) => (typeof s === 'string' ? s.trim() : '')).filter(Boolean)
        : [];

      // Extract Issuer
      const rawIssuer = certResp?.issuer_dn ?? rec.issuer_dn;
      const issuer = typeof rawIssuer === 'string' && rawIssuer.trim() ? rawIssuer.trim() : undefined;

      // Extract validity dates
      const rawNotBefore = certResp?.not_before ?? rec.not_before;
      const notBefore = typeof rawNotBefore === 'string' && rawNotBefore.trim() ? rawNotBefore.trim() : undefined;

      const rawNotAfter = certResp?.not_after ?? rec.not_after;
      const notAfter = typeof rawNotAfter === 'string' && rawNotAfter.trim() ? rawNotAfter.trim() : undefined;

      // Extract certificate boolean flags
      const expired = typeof certResp?.expired === 'boolean' ? certResp.expired : undefined;
      const selfSigned = typeof certResp?.self_signed === 'boolean' ? certResp.self_signed : undefined;

      // Extract supported protocols & cipher suites
      const protocolsSet = new Set<string>();
      const ciphersSet = new Set<string>();

      if (typeof rec.tls_version === 'string' && rec.tls_version.trim()) {
        protocolsSet.add(rec.tls_version.trim().toLowerCase());
      }
      if (typeof rec.cipher === 'string' && rec.cipher.trim()) {
        ciphersSet.add(rec.cipher.trim());
      }

      if (Array.isArray(rec.version_enum)) {
        for (const item of rec.version_enum) {
          if (item && typeof item === 'object') {
            const vi = item as Record<string, unknown>;
            if (typeof vi.version === 'string' && vi.version.trim()) {
              protocolsSet.add(vi.version.trim().toLowerCase());
            }
            if (typeof vi.cipher === 'string' && vi.cipher.trim()) {
              ciphersSet.add(vi.cipher.trim());
            }
          }
        }
      }

      const supportedProtocols = Array.from(protocolsSet).sort();
      const cipherSuites = Array.from(ciphersSet).sort();

      const dedupKey = `${host}:${port}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      const collectedAt = new Date().toISOString();
      observations.push({
        host,
        port,
        ...(resolvedIp ? { ip: resolvedIp } : {}),
        ...(issuer ? { issuer } : {}),
        subjectAlternativeNames,
        supportedProtocols,
        cipherSuites,
        ...(notBefore ? { notBefore } : {}),
        ...(notAfter ? { notAfter } : {}),
        ...(expired !== undefined ? { expired } : {}),
        ...(selfSigned !== undefined ? { selfSigned } : {}),
        discoveredAt: collectedAt,
        collectedAt,
        freshness: 'live',
        sourceReliability: 'direct_observation',
      });
    }

    return {
      status: 'success',
      contractVersion: TLS_INSPECTION_CONTRACT_VERSION,
      targetHost,
      observations,
      explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
      lineage: request.lineage,
      durationMs: output.durationMs,
    };
  }
}
