import * as http from 'node:http';
import * as https from 'node:https';
import * as dns from 'node:dns';
import type { ActiveReconAdapter } from './ActiveReconAdapter.js';
import type { ActiveReconProbeRequest, SafeActiveReconObservation } from './ActiveReconContracts.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';

export class RealActiveReconHttpProbeAdapter implements ActiveReconAdapter {
  constructor(
    private readonly testLookupOverride?: typeof dns.lookup
  ) {}

  async probe(request: ActiveReconProbeRequest): Promise<SafeActiveReconObservation[]> {
    if (request.capabilityId !== 'http.robots.inspect') {
      throw new Error(`Real adapter currently supports only http.robots.inspect. Received: ${request.capabilityId}`);
    }

    const parsed = new URL(request.targetUrl);
    
    // Explicit pre-request safety check for exact robots target
    if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || 
        parsed.pathname !== '/robots.txt' || 
        parsed.search !== '' || 
        parsed.hash !== '') {
      throw new Error(`Policy enforcement failed: target must be exactly /robots.txt with no query or fragment. Received: ${request.targetUrl}`);
    }

    // Explicit pre-request safety check for literal IPs
    if (isInternalOrSsrfTarget(parsed.hostname)) {
      throw new Error(`Policy enforcement failed: target is a blocked internal or SSRF literal IP: ${parsed.hostname}`);
    }

    const isHttps = parsed.protocol === 'https:';
    const client = isHttps ? https : http;

    return new Promise((resolve, reject) => {
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
        method: 'GET',
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: '/robots.txt',
        timeout: 3000,
        lookup: customLookup as any,
        headers: {
          'User-Agent': 'FixGuard-Recon/2.0 (Security Audit Platform)'
        }
      };

      const req = client.request(options, (res) => {
        // Redirection limit: 0
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400) {
          res.destroy();
          return resolve([{
            kind: 'robots_metadata',
            safeSummary: 'robots.txt returned a redirect; no redirects followed.',
            confidence: 'high',
            metadata: {
              reachable: false,
              contentTypeLookedTextLike: false,
              recognizedDirectiveLineCount: 0,
              hasUserAgentDirective: false,
              hasDisallowDirective: false,
              hasAllowDirective: false,
              hasSitemapDirective: false,
              bodyTruncated: false
            }
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

          const isTextLike = res.headers['content-type']?.includes('text/plain') || false;
          
          let userAgentCount = 0;
          let disallowCount = 0;
          let allowCount = 0;
          let sitemapCount = 0;

          if (res.statusCode === 200 && isTextLike) {
            const lines = body.split('\n').map(l => l.trim().toLowerCase());
            for (const line of lines) {
              if (line.startsWith('user-agent:')) userAgentCount++;
              else if (line.startsWith('disallow:')) disallowCount++;
              else if (line.startsWith('allow:')) allowCount++;
              else if (line.startsWith('sitemap:')) sitemapCount++;
            }
          }

          resolve([{
            kind: 'robots_metadata',
            safeSummary: 'robots.txt was reachable; recognized directive metadata was summarized without storing raw paths',
            confidence: 'high',
            metadata: {
              reachable: res.statusCode === 200,
              contentTypeLookedTextLike: isTextLike,
              recognizedDirectiveLineCount: userAgentCount + disallowCount + allowCount + sitemapCount,
              hasUserAgentDirective: userAgentCount > 0,
              hasDisallowDirective: disallowCount > 0,
              hasAllowDirective: allowCount > 0,
              hasSitemapDirective: sitemapCount > 0,
              bodyTruncated: truncated
            }
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
