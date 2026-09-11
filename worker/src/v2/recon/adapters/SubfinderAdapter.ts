import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { isRuntimeEstablishedVerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionService.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
  SUBDOMAIN_DISCOVERY_NON_CLAIMS,
  type DiscoveredSubdomainObservation,
  type SubdomainDiscoveryRequest,
  type SubdomainDiscoveryResult,
  type SubdomainDiscoveryTool,
} from './SubdomainDiscoveryContracts.js';

const FQDN_REGEX = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/;

export class SubfinderAdapter implements SubdomainDiscoveryTool {
  constructor(private readonly processRunner: ProcessRunner) {}

  async discoverSubdomains(request: SubdomainDiscoveryRequest): Promise<SubdomainDiscoveryResult> {
    const rawTarget = typeof request.targetDomain === 'string' ? request.targetDomain.trim().toLowerCase() : '';
    const targetDomain = rawTarget.replace(/\.$/, '');

    // 1. Atomic Preflight: Validate target domain format
    if (!targetDomain || !FQDN_REGEX.test(targetDomain)) {
      return {
        status: 'preflight_denied',
        contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
        targetDomain: request.targetDomain,
        reasonCode: 'invalid_target_domain',
        reason: 'Target domain is not a valid fully-qualified domain name',
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 2. Atomic Preflight: Validate authorization decision runtime brand
    if (
      !request.verifiedAuthorizationDecision ||
      !isRuntimeEstablishedVerifiedAuthorizationDecision(request.verifiedAuthorizationDecision)
    ) {
      return {
        status: 'preflight_denied',
        contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'authorization_unconfirmed',
        reason: 'Authorization decision is not runtime-established or lacks valid verification brand',
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    if (request.verifiedAuthorizationDecision.decision !== 'authorized') {
      return {
        status: 'preflight_denied',
        contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'authorization_denied',
        reason: 'Authorization decision is not in authorized state',
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 3. Atomic Preflight: Lineage tuple consistency check
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
        contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'lineage_mismatch',
        reason: 'Execution lineage does not match authorization decision and scope grant',
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 4. Atomic Preflight: Scope permissions check
    const hasPermission = Boolean(
      grant.permissionSet.endpointDiscovery || grant.permissionSet.passiveRecon
    );
    if (!hasPermission) {
      return {
        status: 'preflight_denied',
        contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'missing_permission',
        reason: 'Scope grant does not permit endpointDiscovery or passiveRecon',
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 5. Atomic Preflight: Scope boundaries check
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

    const isDomainInScope =
      allowedDomains.includes(targetDomain) ||
      allowedDomains.some((d) => targetDomain.endsWith('.' + d)) ||
      allowedHosts.includes(targetDomain) ||
      subjectDomain === targetDomain ||
      subjectHost === targetDomain ||
      originHosts.includes(targetDomain) ||
      originHosts.some((h) => targetDomain.endsWith('.' + h));

    if (!isDomainInScope) {
      return {
        status: 'preflight_denied',
        contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'target_out_of_scope',
        reason: 'Target domain is outside authorized scope boundaries',
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 6. Atomic Preflight: SSRF target check on the targetDomain itself
    if (isInternalOrSsrfTarget(targetDomain)) {
      return {
        status: 'preflight_denied',
        contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'ssrf_target_blocked',
        reason: 'Target domain resolves or points to a blocked internal/loopback target',
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 7. Command Invocation: Strictly via ProcessRunner with shell: false and isolated argument array
    const timeoutMs = request.timeoutMs ?? 60_000;
    const execOutput = await this.processRunner.execute({
      binary: 'subfinder',
      args: ['-d', targetDomain, '-silent', '-json'],
      timeoutMs,
    });

    if (execOutput.timedOut) {
      return {
        status: 'execution_failed',
        contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'process_timeout',
        reason: `Subfinder execution timed out after ${timeoutMs}ms`,
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: execOutput.exitCode,
        stderr: execOutput.stderr,
        durationMs: execOutput.durationMs,
      };
    }

    if (execOutput.exitCode !== 0) {
      return {
        status: 'execution_failed',
        contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'non_zero_exit_code',
        reason: `Subfinder process failed with exit code ${execOutput.exitCode}`,
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: execOutput.exitCode,
        stderr: execOutput.stderr,
        durationMs: execOutput.durationMs,
      };
    }

    // 8. Stream/Line Parsing with Closed-World DTOs, Scope Gate, and SSRF Boundary
    const lines = execOutput.stdout.split('\n');
    const observationsMap = new Map<
      string,
      {
        subdomain: string;
        parentDomain: string;
        ips: Set<string>;
        sources: Set<string>;
        discoveredAt: string;
        confidence: number;
      }
    >();

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

      const record = rawObj as Record<string, unknown>;
      if (typeof record.host !== 'string' || !record.host.trim()) {
        continue;
      }

      const rawHost = record.host.trim().toLowerCase().replace(/\.$/, '');
      if (!FQDN_REGEX.test(rawHost)) {
        continue;
      }

      // Scope Gate: Returned subdomain must match targetDomain or be a subdomain of targetDomain
      const isSubdomain = rawHost === targetDomain || rawHost.endsWith('.' + targetDomain);
      if (!isSubdomain) {
        continue;
      }

      // SSRF Gate: Hostname itself must not be loopback or internal
      if (isInternalOrSsrfTarget(rawHost)) {
        continue;
      }

      // Extract IP addresses if provided
      const rawIps: string[] = [];
      if (typeof record.ip === 'string' && record.ip.trim()) {
        rawIps.push(record.ip.trim());
      } else if (Array.isArray(record.ip)) {
        for (const item of record.ip) {
          if (typeof item === 'string' && item.trim()) {
            rawIps.push(item.trim());
          }
        }
      }

      // SSRF & Scope Gate (M30): Enforce that returned records do not resolve to prohibited
      // RFC-1918 / loopback / cloud metadata IP addresses. If prohibited IP is present, drop record.
      const hasBlockedIp = rawIps.some((ip) => isInternalOrSsrfTarget(ip));
      if (hasBlockedIp) {
        continue;
      }

      // Extract sources
      const rawSources: string[] = [];
      if (Array.isArray(record.sources)) {
        for (const s of record.sources) {
          if (typeof s === 'string' && s.trim()) {
            rawSources.push(s.trim());
          }
        }
      }

      const existing = observationsMap.get(rawHost);
      if (existing) {
        for (const ip of rawIps) existing.ips.add(ip);
        for (const src of rawSources) existing.sources.add(src);
      } else {
        observationsMap.set(rawHost, {
          subdomain: rawHost,
          parentDomain: targetDomain,
          ips: new Set(rawIps),
          sources: new Set(rawSources),
          discoveredAt: nowIso,
          confidence: 1.0,
        });
      }
    }

    const observations: DiscoveredSubdomainObservation[] = Array.from(observationsMap.values())
      .sort((a, b) => a.subdomain.localeCompare(b.subdomain))
      .map((obs) => ({
        subdomain: obs.subdomain,
        parentDomain: obs.parentDomain,
        ipAddresses: obs.ips.size > 0 ? Array.from(obs.ips).sort() : undefined,
        sources: obs.sources.size > 0 ? Array.from(obs.sources).sort() : undefined,
        discoveredAt: obs.discoveredAt,
        confidence: obs.confidence,
      }));

    return {
      status: 'success',
      contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
      targetDomain,
      observations,
      explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
      lineage: request.lineage,
      durationMs: execOutput.durationMs,
    };
  }
}
