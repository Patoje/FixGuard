import * as http from 'node:http';
import * as https from 'node:https';
import * as dns from 'node:dns';
import type { HttpHeaderInspectTransport, RawTransportResponse } from './HttpHeaderInspectTransport';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy';

export class RealHttpHeaderInspectTransport implements HttpHeaderInspectTransport {
  constructor(
    private readonly testLookupOverride?: typeof dns.lookup
  ) {}

  async execute(targetUrl: string, timeoutMs: number): Promise<RawTransportResponse> {
    const parsed = new URL(targetUrl);
    
    return new Promise((resolve, reject) => {
      const isHttps = parsed.protocol === 'https:';
      const client = isHttps ? https : http;

      const lookupFn = this.testLookupOverride || dns.lookup;

      const customLookup = (
        hostname: string,
        opts: dns.LookupOptions,
        callback: (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void
      ) => {
        lookupFn(hostname, opts, (err, address, family) => {
          if (err) return callback(err, address, family);

          if (Array.isArray(address)) {
            for (const addr of address) {
              if (isInternalOrSsrfTarget(addr.address)) {
                return callback(new Error(`DNS resolved to blocked IP during connection: ${addr.address}`), address, family);
              }
            }
          } else {
            if (isInternalOrSsrfTarget(address)) {
              return callback(new Error(`DNS resolved to blocked IP during connection: ${address}`), address, family);
            }
          }

          callback(null, address, family);
        });
      };

      const options: http.RequestOptions | https.RequestOptions = {
        method: 'HEAD',
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        timeout: timeoutMs,
        lookup: customLookup as any, // custom lookup
        headers: {
          'User-Agent': 'FixGuard-Recon/2.0 (Security Audit Platform)'
        }
      };

      const req = client.request(options, (res) => {
        // No body read required for HEAD, but let's consume it to avoid leaks
        res.resume();
        
        // Bounded headers
        const headers = res.headers;
        
        resolve({
          statusCode: res.statusCode || 0,
          statusText: res.statusMessage || '',
          headers: headers as Record<string, string | string[] | undefined>
        });
      });

      req.on('timeout', () => {
        req.destroy(new Error('Request timed out'));
      });

      req.on('error', (err) => {
        reject(err);
      });

      req.end();
    });
  }
}
