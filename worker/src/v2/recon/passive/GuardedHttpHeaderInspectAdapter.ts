import type { PassiveCapabilityExecutor } from './PassiveCapabilityExecutor';
import type { CapabilityRequest } from '../../core/ExecutionContracts';
import type { EvidenceCollection } from '../../core/Evidence';
import type { HttpHeaderInspectTransport } from './HttpHeaderInspectTransport';
import { evaluateEgressPolicy } from '../policy/PassiveEgressPolicy';
import type { AuthorizedScope } from '../policy/EgressPolicyContracts';
import { normalizeTargetUrl } from '../policy/TargetUrlNormalizer';

export class GuardedHttpHeaderInspectAdapter implements PassiveCapabilityExecutor {
  constructor(
    private readonly transport: HttpHeaderInspectTransport,
    private readonly authorizedScope: AuthorizedScope
  ) {}

  async execute(request: CapabilityRequest): Promise<EvidenceCollection> {
    if (request.capability !== 'http.header.inspect') {
      throw new Error(`Unsupported capability: ${request.capability}`);
    }

    const decision = evaluateEgressPolicy({
      targetUrl: request.target.uri,
      authorizedScope: this.authorizedScope,
      capabilityId: request.capability
    });

    if (decision.decision !== 'allow') {
      throw new Error(`Policy enforcement failed: target is ${decision.decision}`);
    }

    const urlToFetch = decision.normalizedTarget?.normalizedUrl || request.target.uri;

    let response;
    try {
      response = await this.transport.execute(urlToFetch, 3000);
    } catch (err: any) {
      throw new Error(`Transport failed: ${err.message}`);
    }
      
    const sanitizedHeaders = this.sanitizeHeaders(response.headers);
    
    return {
      findings: [],
      metadata: {
        capabilityId: 'http.header.inspect',
        evidenceKind: 'observation',
        observationSource: 'real_http_header_inspect',
        requestedUrl: decision.safeDisplayUrl,
        observedAt: Date.now(),
        statusCode: response.statusCode,
        statusText: response.statusText,
        headers: sanitizedHeaders,
        policyDecision: decision.decision
      }
    };
  }

  private sanitizeHeaders(rawHeaders: Record<string, string | string[] | undefined>): Record<string, string> {
    const safe: Record<string, string> = {};
    const sensitive = [
      'secret', 'secrets', 'password', 'passwd', 'session', 'auth', 'authorization',
      'token', 'bearer', 'api-key', 'x-api-key', 'access-token', 'refresh-token',
      'jwt', 'cookie', 'set-cookie'
    ];
    
    let headerCount = 0;
    let totalSize = 0;

    for (const [key, value] of Object.entries(rawHeaders)) {
      if (value === undefined) continue;
      
      headerCount++;
      if (headerCount > 50) break; // Bound header count

      const lowerKey = key.toLowerCase();
      let safeValue = Array.isArray(value) ? value.join(', ') : String(value);

      if (sensitive.some(s => lowerKey.includes(s))) {
        safeValue = '[REDACTED]';
      } else if (lowerKey === 'location') {
        const norm = normalizeTargetUrl(safeValue);
        safeValue = norm.safeDisplayUrl || '[untrusted-url]';
        // additional length bound to be safe
        if (safeValue.length > 256) safeValue = safeValue.substring(0, 256) + '...';
      }
      
      totalSize += key.length + safeValue.length;
      if (totalSize > 4096) break; // Bound total size

      safe[key] = safeValue;
    }
    return safe;
  }
}
