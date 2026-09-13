import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { isRuntimeEstablishedVerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionService.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  DNS_RESOLUTION_CONTRACT_VERSION,
  DNS_RESOLUTION_NON_CLAIMS,
  type DiscoveredDnsObservation,
  type DnsRecordType,
  type DnsResolutionRequest,
  type DnsResolutionResult,
  type DnsResolutionTool,
} from './DnsResolutionContracts.js';

const FQDN_REGEX = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/;

export class DnsxAdapter implements DnsResolutionTool {
  constructor(private readonly processRunner: ProcessRunner) {}

  async resolveDns(request: DnsResolutionRequest): Promise<DnsResolutionResult> {
    const rawTarget = typeof request.targetDomain === 'string' ? request.targetDomain.trim().toLowerCase() : '';
    const targetDomain = rawTarget.replace(/\.$/, '');

    // 1. Atomic Preflight: Target domain format validation
    if (!targetDomain || !FQDN_REGEX.test(targetDomain)) {
      return {
        status: 'preflight_denied',
        contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
        targetDomain: request.targetDomain,
        reasonCode: 'invalid_target_domain',
        reason: 'Target domain is not a valid fully-qualified domain name',
        explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 2. Atomic Preflight: Target domain SSRF pre-check
    if (isInternalOrSsrfTarget(targetDomain)) {
      return {
        status: 'preflight_denied',
        contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'ssrf_target_blocked',
        reason: 'Target domain points to prohibited internal, loopback, or metadata address',
        explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 3. Atomic Preflight: Runtime-branded authorization verification
    if (
      !request.verifiedAuthorizationDecision ||
      !isRuntimeEstablishedVerifiedAuthorizationDecision(request.verifiedAuthorizationDecision)
    ) {
      return {
        status: 'preflight_denied',
        contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'authorization_unconfirmed',
        reason: 'Authorization decision is not runtime-established or lacks valid verification brand',
        explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    if (request.verifiedAuthorizationDecision.decision !== 'authorized') {
      return {
        status: 'preflight_denied',
        contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'authorization_denied',
        reason: 'Authorization decision is not in authorized state',
        explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 4. Atomic Preflight: Continuous Lineage tuple integrity verification
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
        contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'lineage_mismatch',
        reason: 'Execution lineage does not match authorization decision and scope grant',
        explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 5. Atomic Preflight: Scope permissions check
    const ps = grant.permissionSet;
    let hasPermission = Boolean(
      ps.endpointDiscovery ||
      ps.passiveRecon ||
      ps.activeValidation ||
      ps.lightValidation ||
      ps.technologyFingerprinting ||
      ps.activeCrawling
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
        contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'missing_permission',
        reason: 'Scope grant does not permit DNS resolution or reconnaissance',
        explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 6. Atomic Preflight: Scope boundaries check
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
        // ignore malformed origin strings
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
        contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'target_out_of_scope',
        reason: 'Target domain is outside authorized scope boundaries',
        explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // Execution Phase: Assemble isolated dnsx CLI arguments
    const args = [
      '-d', targetDomain,
      '-json',
    ];

    const recordTypes = request.recordTypes && request.recordTypes.length > 0
      ? request.recordTypes
      : (['A', 'AAAA', 'CNAME', 'TXT', 'MX'] as const);

    if (recordTypes.includes('A')) args.push('-a');
    if (recordTypes.includes('AAAA')) args.push('-aaaa');
    if (recordTypes.includes('CNAME')) args.push('-cname');
    if (recordTypes.includes('TXT')) args.push('-txt');
    if (recordTypes.includes('MX')) args.push('-mx');

    // Wildcard Filtering (-wd <targetDomain>)
    if (request.wildcardFiltering !== false) {
      args.push('-wd', targetDomain);
    }

    // Resolver Containment (-r 1.1.1.1,8.8.8.8) to prevent system DNS rebinding SSRF
    const resolvers = request.resolvers && request.resolvers.length > 0
      ? request.resolvers.join(',')
      : '1.1.1.1,8.8.8.8';
    args.push('-r', resolvers);

    const timeoutMs = request.timeoutMs ?? 60_000;

    let output;
    try {
      output = await this.processRunner.execute({
        binary: 'dnsx',
        args,
        timeoutMs,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        status: 'execution_failed',
        contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'process_launch_failed',
        reason: msg,
        explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    if (output.timedOut) {
      return {
        status: 'execution_failed',
        contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'execution_timed_out',
        reason: `dnsx execution timed out after ${timeoutMs}ms`,
        explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: output.exitCode,
        stderr: output.stderr,
        durationMs: output.durationMs,
      };
    }

    if (output.exitCode !== 0) {
      return {
        status: 'execution_failed',
        contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'process_execution_failed',
        reason: output.stderr.trim() || `dnsx exited with non-zero exit code: ${output.exitCode}`,
        explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: output.exitCode,
        stderr: output.stderr,
        durationMs: output.durationMs,
      };
    }

    // Parsing & Deep SSRF Egress Gate Phase
    const observations: DiscoveredDnsObservation[] = [];
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

      const host = typeof rec.host === 'string' && rec.host.trim()
        ? rec.host.trim().toLowerCase().replace(/\.$/, '')
        : targetDomain;

      const addObservation = (type: DnsRecordType, rawValues: unknown) => {
        if (!Array.isArray(rawValues) || rawValues.length === 0) return;

        const stringValues = rawValues
          .map((v) => (typeof v === 'string' ? v.trim() : ''))
          .filter(Boolean);

        if (stringValues.length === 0) return;

        // Deep SSRF Egress Gate for A and AAAA records
        if (type === 'A' || type === 'AAAA') {
          for (const ip of stringValues) {
            if (isInternalOrSsrfTarget(ip)) {
              // Any resolved IP pointing to loopback, RFC-1918, or metadata causes observation drop
              return;
            }
          }
        }

        const dedupKey = `${host}|${type}|${stringValues.sort().join(',')}`;
        if (seen.has(dedupKey)) return;
        seen.add(dedupKey);

        observations.push({
          domain: host,
          recordType: type,
          values: stringValues,
          discoveredAt: new Date().toISOString(),
        });
      };

      if (rec.a) addObservation('A', rec.a);
      if (rec.aaaa) addObservation('AAAA', rec.aaaa);
      if (rec.cname) addObservation('CNAME', rec.cname);
      if (rec.txt) addObservation('TXT', rec.txt);
      if (rec.mx) addObservation('MX', rec.mx);
    }

    return {
      status: 'success',
      contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
      targetDomain,
      observations,
      explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
      lineage: request.lineage,
      durationMs: output.durationMs,
    };
  }
}
