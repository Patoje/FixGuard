import * as http from 'node:http';
import * as https from 'node:https';
import * as dns from 'node:dns';
import type { ActiveReconAdapter } from './ActiveReconAdapter.js';
import type { ActiveReconProbeRequest, SafeActiveReconObservation } from './ActiveReconContracts.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import { sanitizeSecurityTxtMetadata } from './ActiveReconDocumentSanitizers.js';

const SECURITY_TXT_PATH = '/.well-known/security.txt';

export class RealActiveReconSecurityTxtProbeAdapter implements ActiveReconAdapter {
  constructor(
    private readonly testLookupOverride?: typeof dns.lookup
  ) {}

  async probe(request: ActiveReconProbeRequest): Promise<SafeActiveReconObservation[]> {
    if (request.capabilityId !== 'http.security_txt.inspect') {
      throw new Error(`M37 security.txt adapter supports only http.security_txt.inspect. Received: ${request.capabilityId}`);
    }

    const parsed = new URL(request.targetUrl);

    // Explicit pre-request safety check: exact path, no query, no fragment
    if (
      (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
      parsed.pathname !== SECURITY_TXT_PATH ||
      parsed.search !== '' ||
      parsed.hash !== ''
    ) {
      throw new Error(
        `Policy enforcement failed: target must be exactly ${SECURITY_TXT_PATH} with no query or fragment. Received: ${request.targetUrl}`
      );
    }

    // Explicit pre-request safety check for literal IPs (before any socket code)
    if (isInternalOrSsrfTarget(parsed.hostname)) {
      throw new Error(
        `Policy enforcement failed: target is a blocked internal or SSRF literal IP: ${parsed.hostname}`
      );
    }

    const isHttps = parsed.protocol === 'https:';
    const client = isHttps ? https : http;

    return new Promise((resolve, reject) => {
      const lookupFn = this.testLookupOverride || dns.lookup;

      // Request-bound DNS/IP guard — blocks unsafe resolved IPs before socket connect
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
        method: 'GET',
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        // Fixed path — never derived from parsed.pathname + parsed.search
        path: SECURITY_TXT_PATH,
        timeout: 3000,
        lookup: customLookup as any,
        headers: {
          'User-Agent': 'FixGuard-Recon/2.0 (Security Audit Platform)'
        }
      };

      const req = client.request(options, (res) => {
        // Redirection limit: 0 — do not follow; do not emit Location header
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400) {
          res.destroy();
          return resolve([{
            kind: 'security_txt_metadata',
            safeSummary: 'security.txt returned a redirect; no redirects followed.',
            confidence: 'high',
            metadata: sanitizeSecurityTxtMetadata('', {
              reachable: false,
              contentTypeLookedTextLike: false,
              bodyTruncated: false
            })
          }]);
        }

        let body = '';
        let truncated = false;

        res.on('data', (chunk: Buffer) => {
          const maxBytes = 16384; // 16 KiB limit
          if (body.length + chunk.length > maxBytes) {
            body += chunk.toString('utf8', 0, maxBytes - body.length);
            truncated = true;
            res.destroy();
          } else {
            body += chunk.toString('utf8');
          }
        });

        res.on('end', () => {
          processResponse();
        });

        res.on('close', () => {
          if (truncated) {
            processResponse();
          }
        });

        let isResolved = false;

        const processResponse = () => {
          if (isResolved) return;
          isResolved = true;

          // content-type check — reading only boolean; raw header value never emitted
          const isTextLike = res.headers['content-type']?.includes('text/plain') || false;

          // Only parse body on 200 + text/plain; otherwise emit empty metadata
          const bodyToParse = (res.statusCode === 200 && isTextLike) ? body : '';

          const metadata = sanitizeSecurityTxtMetadata(bodyToParse, {
            reachable: res.statusCode === 200,
            contentTypeLookedTextLike: isTextLike,
            bodyTruncated: truncated
          });

          resolve([{
            kind: 'security_txt_metadata',
            safeSummary: 'security.txt was reachable; recognized field metadata was summarized without storing raw field values',
            confidence: 'high',
            metadata
          }]);
        };
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
