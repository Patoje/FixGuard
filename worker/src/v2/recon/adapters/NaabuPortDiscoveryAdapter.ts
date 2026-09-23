import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  runAdapterPreflight,
  type PreSpawnDnsResolver,
} from './AdapterPreflightPipeline.js';
import {
  PORT_DISCOVERY_CONTRACT_VERSION,
  PORT_DISCOVERY_NON_CLAIMS,
  type DiscoveredPortObservation,
  type PortDiscoveryRequest,
  type PortDiscoveryResult,
  type PortDiscoveryTool,
} from './PortDiscoveryContracts.js';

function isValidIpv4(value: string): boolean {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return false;
  const parts = value.split('.').map((p) => parseInt(p, 10));
  return parts.every((p) => !isNaN(p) && p >= 0 && p <= 255);
}

export class NaabuPortDiscoveryAdapter implements PortDiscoveryTool {
  constructor(
    private readonly processRunner: ProcessRunner,
    private readonly dnsResolver?: PreSpawnDnsResolver
  ) {}

  async discoverPorts(request: PortDiscoveryRequest): Promise<PortDiscoveryResult> {
    const preflight = await runAdapterPreflight({
      target: request.targetHostOrIp,
      targetKind: 'ipv4_or_fqdn',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.authorizedScopeGrant,
      lineage: request.lineage,
      permissionCheck: (ps) => {
        let hasPermission = Boolean(
          ps.endpointDiscovery ||
          ps.activeValidation ||
          ps.lightValidation
        );
        if (!hasPermission && 'portScanning' in ps) {
          const extendedPs = ps as typeof ps & { portScanning?: boolean };
          if (extendedPs.portScanning) hasPermission = true;
        }
        if (!hasPermission && 'activeRecon' in ps) {
          const extendedPs = ps as typeof ps & { activeRecon?: boolean };
          if (extendedPs.activeRecon) hasPermission = true;
        }
        return hasPermission;
      },
      missingPermissionReason: 'Scope grant does not permit port scanning or active reconnaissance',
      targetOutOfScopeReason: 'Target is outside authorized scope boundaries',
      dnsResolver: this.dnsResolver,
    });

    if (!preflight.ok) {
      return {
        status: 'preflight_denied',
        contractVersion: PORT_DISCOVERY_CONTRACT_VERSION,
        targetHostOrIp: request.targetHostOrIp,
        reasonCode: preflight.reasonCode,
        reason: preflight.reason,
        explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    const target = preflight.targetHost;

    // Build argument array strictly without shell interpolation
    const rate = typeof request.rate === 'number' && request.rate > 0 ? request.rate : 1000;
    const args = ['-host', target, '-json', '-silent', '-rate', String(rate)];

    if (request.targetPorts && request.targetPorts.length > 0) {
      const sanitizedPorts = request.targetPorts
        .map((p) => String(p).trim())
        .filter((p) => /^[0-9,-]+$/.test(p) || /^top-\d+$/.test(p));
      if (sanitizedPorts.length > 0) {
        args.push('-p', sanitizedPorts.join(','));
      }
    }

    const timeoutMs = request.timeoutMs ?? 60_000;
    const execOutput = await this.processRunner.execute({
      binary: 'naabu',
      args,
      timeoutMs,
    });

    if (execOutput.timedOut) {
      return {
        status: 'execution_failed',
        contractVersion: PORT_DISCOVERY_CONTRACT_VERSION,
        targetHostOrIp: target,
        reasonCode: 'process_timeout',
        reason: `Naabu execution timed out after ${timeoutMs}ms`,
        explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: execOutput.exitCode,
        stderr: execOutput.stderr,
        durationMs: execOutput.durationMs,
      };
    }

    if (execOutput.exitCode !== 0) {
      return {
        status: 'execution_failed',
        contractVersion: PORT_DISCOVERY_CONTRACT_VERSION,
        targetHostOrIp: target,
        reasonCode: 'non_zero_exit_code',
        reason: `Naabu process failed with exit code ${execOutput.exitCode}`,
        explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: execOutput.exitCode,
        stderr: execOutput.stderr,
        durationMs: execOutput.durationMs,
      };
    }

    // Output parsing line-by-line with egress filtering and fail-closed resilience
    const lines = execOutput.stdout.split('\n');
    const observationsMap = new Map<string, DiscoveredPortObservation>();
    const nowIso = new Date().toISOString();

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      let rawObj: unknown;
      try {
        rawObj = JSON.parse(trimmed);
      } catch {
        // Fail closed on corrupted / non-JSON lines without crashing
        continue;
      }

      if (!rawObj || typeof rawObj !== 'object' || Array.isArray(rawObj)) {
        continue;
      }

      const rec = rawObj as Record<string, unknown>;
      const host = typeof rec.host === 'string' ? rec.host.trim().toLowerCase().replace(/\.$/, '') : '';
      const ip = typeof rec.ip === 'string' ? rec.ip.trim() : (isValidIpv4(host) ? host : '');
      const rawPort = typeof rec.port === 'number' ? rec.port : parseInt(String(rec.port), 10);

      if (isNaN(rawPort) || rawPort < 1 || rawPort > 65535) {
        continue;
      }

      // SSRF & Loopback containment: drop if IP or host is blocked internal/loopback/cloud metadata
      if ((ip && isInternalOrSsrfTarget(ip)) || (host && isInternalOrSsrfTarget(host))) {
        continue;
      }

      const effectiveHost = host || ip;
      const effectiveIp = ip || (isValidIpv4(host) ? host : '');
      const dedupeKey = `${effectiveHost}:${rawPort}`;

      if (!observationsMap.has(dedupeKey)) {
        observationsMap.set(dedupeKey, {
          host: effectiveHost,
          ip: effectiveIp,
          port: rawPort,
          protocol: 'tcp',
          state: 'open',
          discoveredAt: nowIso,
          collectedAt: nowIso,
          freshness: 'live',
          sourceReliability: 'direct_observation',
        });
      }
    }

    const observations: DiscoveredPortObservation[] = Array.from(observationsMap.values()).sort(
      (a, b) => a.port - b.port || a.host.localeCompare(b.host)
    );

    return {
      status: 'success',
      contractVersion: PORT_DISCOVERY_CONTRACT_VERSION,
      targetHostOrIp: target,
      observations,
      explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
      lineage: request.lineage,
      durationMs: execOutput.durationMs,
    };
  }
}
