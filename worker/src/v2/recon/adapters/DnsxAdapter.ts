import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  runAdapterPreflight,
  type PreSpawnDnsResolver,
} from './AdapterPreflightPipeline.js';
import {
  DNS_RESOLUTION_CONTRACT_VERSION,
  DNS_RESOLUTION_NON_CLAIMS,
  type DiscoveredDnsObservation,
  type DnsRecordType,
  type DnsResolutionRequest,
  type DnsResolutionResult,
  type DnsResolutionTool,
} from './DnsResolutionContracts.js';

export class DnsxAdapter implements DnsResolutionTool {
  constructor(
    private readonly processRunner: ProcessRunner,
    private readonly dnsResolver?: PreSpawnDnsResolver
  ) {}

  async resolveDns(request: DnsResolutionRequest): Promise<DnsResolutionResult> {
    const rawTarget = typeof request.targetDomain === 'string' ? request.targetDomain.trim().toLowerCase() : '';
    const targetDomain = rawTarget.replace(/\.$/, '');

    // Unified Atomic Preflight Gate
    const preflight = await runAdapterPreflight({
      target: targetDomain,
      targetKind: 'fqdn',
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
          ps.activeCrawling ||
          ('activeRecon' in ps && (ps as { activeRecon?: boolean }).activeRecon)
        ),
      missingPermissionReason: 'Scope grant does not permit DNS resolution or reconnaissance',
      targetOutOfScopeReason: 'Target domain is outside authorized scope boundaries',
      dnsResolver: this.dnsResolver,
    });

    if (!preflight.ok) {
      return {
        status: 'preflight_denied',
        contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
        targetDomain: request.targetDomain,
        reasonCode: preflight.reasonCode,
        reason: preflight.reason,
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
