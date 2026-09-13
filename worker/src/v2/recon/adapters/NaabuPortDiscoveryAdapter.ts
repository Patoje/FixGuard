import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { isRuntimeEstablishedVerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionService.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  PORT_DISCOVERY_CONTRACT_VERSION,
  PORT_DISCOVERY_NON_CLAIMS,
  type DiscoveredPortObservation,
  type PortDiscoveryRequest,
  type PortDiscoveryResult,
  type PortDiscoveryTool,
} from './PortDiscoveryContracts.js';

const FQDN_REGEX = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/;

function isValidIpv4(value: string): boolean {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return false;
  const parts = value.split('.').map((p) => parseInt(p, 10));
  return parts.every((p) => !isNaN(p) && p >= 0 && p <= 255);
}

export class NaabuPortDiscoveryAdapter implements PortDiscoveryTool {
  constructor(private readonly processRunner: ProcessRunner) {}

  async discoverPorts(request: PortDiscoveryRequest): Promise<PortDiscoveryResult> {
    const rawTarget = typeof request.targetHostOrIp === 'string' ? request.targetHostOrIp.trim().toLowerCase() : '';
    const target = rawTarget.replace(/\.$/, '');

    // 1. Atomic Preflight: Target format validation (FQDN or valid IPv4)
    const isTargetIpv4 = isValidIpv4(target);
    const isTargetFqdn = FQDN_REGEX.test(target);

    if (!target || (!isTargetIpv4 && !isTargetFqdn)) {
      return {
        status: 'preflight_denied',
        contractVersion: PORT_DISCOVERY_CONTRACT_VERSION,
        targetHostOrIp: request.targetHostOrIp,
        reasonCode: 'invalid_target_format',
        reason: 'Target is not a valid fully-qualified domain name or IPv4 address',
        explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 2. Atomic Preflight: Runtime-branded authorization verification
    if (
      !request.verifiedAuthorizationDecision ||
      !isRuntimeEstablishedVerifiedAuthorizationDecision(request.verifiedAuthorizationDecision)
    ) {
      return {
        status: 'preflight_denied',
        contractVersion: PORT_DISCOVERY_CONTRACT_VERSION,
        targetHostOrIp: target,
        reasonCode: 'authorization_unconfirmed',
        reason: 'Authorization decision is not runtime-established or lacks valid verification brand',
        explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    if (request.verifiedAuthorizationDecision.decision !== 'authorized') {
      return {
        status: 'preflight_denied',
        contractVersion: PORT_DISCOVERY_CONTRACT_VERSION,
        targetHostOrIp: target,
        reasonCode: 'authorization_denied',
        reason: 'Authorization decision is not in authorized state',
        explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
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
        contractVersion: PORT_DISCOVERY_CONTRACT_VERSION,
        targetHostOrIp: target,
        reasonCode: 'lineage_mismatch',
        reason: 'Execution lineage does not match authorization decision and scope grant',
        explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 4. Atomic Preflight: Scope permissions check (portScanning, activeRecon, endpointDiscovery, activeValidation)
    const ps = grant.permissionSet;
    let hasPermission = Boolean(
      ps.endpointDiscovery ||
      ps.activeValidation ||
      ps.lightValidation
    );
    if (!hasPermission && 'portScanning' in ps) {
      const extendedPs = ps as typeof ps & { portScanning?: boolean };
      if (extendedPs.portScanning) {
        hasPermission = true;
      }
    }
    if (!hasPermission && 'activeRecon' in ps) {
      const extendedPs = ps as typeof ps & { activeRecon?: boolean };
      if (extendedPs.activeRecon) {
        hasPermission = true;
      }
    }

    if (!hasPermission) {
      return {
        status: 'preflight_denied',
        contractVersion: PORT_DISCOVERY_CONTRACT_VERSION,
        targetHostOrIp: target,
        reasonCode: 'missing_permission',
        reason: 'Scope grant does not permit port scanning or active reconnaissance',
        explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 5. Atomic Preflight: Scope boundary check
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
        // ignore malformed origin strings in grant
      }
    }

    const allowedIps: string[] = [];
    if ('allowedIps' in grant.boundaries) {
      const extBoundaries = grant.boundaries as typeof grant.boundaries & { allowedIps?: unknown };
      if (Array.isArray(extBoundaries.allowedIps)) {
        for (const item of extBoundaries.allowedIps) {
          if (typeof item === 'string' && item.trim()) {
            allowedIps.push(item.trim());
          }
        }
      }
    }

    const isTargetInScope =
      allowedDomains.includes(target) ||
      allowedDomains.some((d) => target.endsWith('.' + d)) ||
      allowedHosts.includes(target) ||
      allowedIps.includes(target) ||
      subjectDomain === target ||
      subjectHost === target ||
      originHosts.includes(target) ||
      originHosts.some((h) => target.endsWith('.' + h));

    if (!isTargetInScope) {
      return {
        status: 'preflight_denied',
        contractVersion: PORT_DISCOVERY_CONTRACT_VERSION,
        targetHostOrIp: target,
        reasonCode: 'target_out_of_scope',
        reason: 'Target is outside authorized scope boundaries',
        explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 6. Atomic Preflight: SSRF containment pre-check on target itself
    if (isInternalOrSsrfTarget(target)) {
      return {
        status: 'preflight_denied',
        contractVersion: PORT_DISCOVERY_CONTRACT_VERSION,
        targetHostOrIp: target,
        reasonCode: 'ssrf_target_blocked',
        reason: 'Target host or IP resolves to prohibited loopback, RFC-1918, or metadata range',
        explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

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
