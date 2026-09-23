import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  runAdapterPreflight,
  type PreSpawnDnsResolver,
} from './AdapterPreflightPipeline.js';
import {
  PARAMETER_DISCOVERY_CONTRACT_VERSION,
  PARAMETER_DISCOVERY_NON_CLAIMS,
  type DiscoveredParameterObservation,
  type HttpParameterMethod,
  type ParameterDiscoveryRequest,
  type ParameterDiscoveryResult,
  type ParameterDiscoveryTool,
} from './ParameterDiscoveryContracts.js';

export class ArjunAdapter implements ParameterDiscoveryTool {
  constructor(
    private readonly processRunner: ProcessRunner,
    private readonly dnsResolver?: PreSpawnDnsResolver
  ) {}

  async discoverParameters(request: ParameterDiscoveryRequest): Promise<ParameterDiscoveryResult> {
    const rawTarget = typeof request.targetUrl === 'string' ? request.targetUrl.trim() : '';

    // Unified Atomic Preflight Gate
    const preflight = await runAdapterPreflight({
      target: rawTarget,
      targetKind: 'url',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.authorizedScopeGrant,
      lineage: request.lineage,
      permissionCheck: (ps) =>
        Boolean(
          ps.endpointDiscovery ||
          ps.activeValidation ||
          ps.lightValidation ||
          ps.activeCrawling ||
          ps.passiveRecon ||
          ps.technologyFingerprinting ||
          ('activeRecon' in ps && (ps as { activeRecon?: boolean }).activeRecon)
        ),
      missingPermissionReason: 'Scope grant does not permit parameter discovery or active reconnaissance',
      targetOutOfScopeReason: 'Target URL host is outside authorized scope boundaries',
      dnsResolver: this.dnsResolver,
    });

    if (!preflight.ok) {
      return {
        status: 'preflight_denied',
        contractVersion: PARAMETER_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: preflight.reasonCode,
        reason: preflight.reason,
        explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // Execution Phase: Setup isolated CLI arguments and secure temp output file
    const tempFilePath = path.join(
      os.tmpdir(),
      `arjun-${Date.now()}-${Math.random().toString(36).slice(2)}.json`
    );

    const effectiveMethod: HttpParameterMethod = request.httpMethod ?? 'GET';

    const args = ['-u', rawTarget];

    if (request.httpMethod) {
      args.push('-m', request.httpMethod);
    }

    // Only append -c and -d if explicitly provided in the DTO
    if (typeof request.chunkSize === 'number' && request.chunkSize > 0) {
      args.push('-c', String(request.chunkSize));
    }

    if (typeof request.delaySeconds === 'number' && request.delaySeconds > 0) {
      args.push('-d', String(request.delaySeconds));
    }

    args.push('-oJ', tempFilePath);

    const timeoutMs = request.timeoutMs ?? 60_000;

    let output;
    let rawJsonContent = '';

    try {
      output = await this.processRunner.execute({
        binary: 'arjun',
        args,
        timeoutMs,
      });

      // Retrieve JSON from temp file if written, falling back to output.stdout
      try {
        const fileContent = await fs.readFile(tempFilePath, 'utf-8');
        if (fileContent.trim()) {
          rawJsonContent = fileContent.trim();
        }
      } catch {
        // Temp file not written or running in unit test mock -> use stdout
        rawJsonContent = output.stdout.trim();
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        status: 'execution_failed',
        contractVersion: PARAMETER_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: 'process_launch_failed',
        reason: msg,
        explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    } finally {
      // Guarantee deletion of temporary file in finally block to prevent storage exhaustion
      try {
        await fs.unlink(tempFilePath);
      } catch {
        // Safe ignore
      }
    }

    if (output.timedOut) {
      return {
        status: 'execution_failed',
        contractVersion: PARAMETER_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: 'execution_timed_out',
        reason: `arjun execution timed out after ${timeoutMs}ms`,
        explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: output.exitCode,
        stderr: output.stderr,
        durationMs: output.durationMs,
      };
    }

    if (output.exitCode !== 0) {
      return {
        status: 'execution_failed',
        contractVersion: PARAMETER_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: 'process_execution_failed',
        reason: output.stderr.trim() || `arjun exited with non-zero exit code: ${output.exitCode}`,
        explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: output.exitCode,
        stderr: output.stderr,
        durationMs: output.durationMs,
      };
    }

    // Parsing & Deep SSRF Egress Gate Phase
    const observations: DiscoveredParameterObservation[] = [];
    const seen = new Set<string>();

    if (rawJsonContent) {
      const parsedObjects: unknown[] = [];

      try {
        const fullParsed = JSON.parse(rawJsonContent);
        parsedObjects.push(fullParsed);
      } catch {
        // Fall back to line-by-line JSON parsing for mixed/banner output
        const lines = rawJsonContent.split('\n');
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          try {
            const lineParsed = JSON.parse(trimmed);
            parsedObjects.push(lineParsed);
          } catch {
            // Non-JSON or malformed lines fail closed safely
          }
        }
      }

      const grant = request.authorizedScopeGrant;
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

      const isHostInScope = (host: string): boolean =>
        allowedDomains.includes(host) ||
        allowedDomains.some((d) => host.endsWith('.' + d)) ||
        allowedHosts.includes(host) ||
        subjectDomain === host ||
        subjectHost === host ||
        originHosts.includes(host) ||
        originHosts.some((h) => host.endsWith('.' + h));

      const processEntry = (entryUrl: string, params: unknown) => {
        if (!entryUrl || typeof entryUrl !== 'string' || !Array.isArray(params)) return;

        let entryHost = '';
        try {
          const u = new URL(entryUrl);
          entryHost = u.hostname.toLowerCase().replace(/\.$/, '');
        } catch {
          return;
        }

        // Deep SSRF Egress Gate: Re-evaluate URL host against SSRF restrictions
        if (isInternalOrSsrfTarget(entryHost)) {
          return; // Drop entire observation
        }

        // Deep Scope Boundary Gate: Re-evaluate URL host against scope boundaries
        if (!isHostInScope(entryHost)) {
          return; // Drop entire observation
        }

        for (const param of params) {
          if (typeof param !== 'string') continue;
          const cleanParam = param.trim();
          if (!cleanParam) continue;

          const dedupKey = `${entryUrl}|${effectiveMethod}|${cleanParam}`;
          if (seen.has(dedupKey)) continue;
          seen.add(dedupKey);

          observations.push({
            url: entryUrl,
            method: effectiveMethod,
            parameterName: cleanParam,
            discoveredAt: new Date().toISOString(),
            collectedAt: new Date().toISOString(),
            freshness: 'live',
            sourceReliability: 'direct_observation',
          });
        }
      };

      for (const parsed of parsedObjects) {
        if (Array.isArray(parsed)) {
          for (const item of parsed) {
            if (item && typeof item === 'object') {
              const obj = item as Record<string, unknown>;
              if (typeof obj.url === 'string' && Array.isArray(obj.params)) {
                processEntry(obj.url, obj.params);
              } else {
                for (const [key, value] of Object.entries(obj)) {
                  processEntry(key, value);
                }
              }
            }
          }
        } else if (parsed && typeof parsed === 'object') {
          const obj = parsed as Record<string, unknown>;
          if (typeof obj.url === 'string' && Array.isArray(obj.params)) {
            processEntry(obj.url, obj.params);
          } else {
            for (const [key, value] of Object.entries(obj)) {
              processEntry(key, value);
            }
          }
        }
      }
    }

    return {
      status: 'success',
      contractVersion: PARAMETER_DISCOVERY_CONTRACT_VERSION,
      targetUrl: rawTarget,
      observations,
      explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
      lineage: request.lineage,
      durationMs: output.durationMs,
    };
  }
}
