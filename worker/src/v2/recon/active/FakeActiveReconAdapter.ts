import type { ActiveReconAdapter } from './ActiveReconAdapter.js';
import type { ActiveReconProbeRequest, SafeActiveReconObservation } from './ActiveReconContracts.js';
import { sanitizeRobotsTxtMetadata, sanitizeSecurityTxtMetadata } from './ActiveReconDocumentSanitizers.js';

export class FakeActiveReconAdapter implements ActiveReconAdapter {
  public executionCount = 0;

  async probe(request: ActiveReconProbeRequest): Promise<SafeActiveReconObservation[]> {
    this.executionCount++;

    if (request.capabilityId === 'http.robots.inspect') {
      const fakeRobotsBody = `
User-agent: *
Disallow: /admin
Allow: /public
Sitemap: https://example.com/sitemap.xml
      `;
      const metadata = sanitizeRobotsTxtMetadata(fakeRobotsBody, {
        reachable: true,
        contentTypeLookedTextLike: true,
        bodyTruncated: false
      });

      return [{
        kind: 'robots_metadata',
        safeSummary: 'robots metadata probe modeled by fake adapter',
        confidence: 'medium',
        metadata
      }];
    }

    if (request.capabilityId === 'http.security_txt.inspect') {
      const fakeSecurityTxtBody = `
Contact: mailto:security@example.com
Expires: 2030-12-31T23:59:59Z
Encryption: https://example.com/pgp-key.txt
Acknowledgments: https://example.com/hall-of-fame
Preferred-Languages: en, es
Canonical: https://example.com/.well-known/security.txt
Policy: https://example.com/security-policy
      `;
      const metadata = sanitizeSecurityTxtMetadata(fakeSecurityTxtBody, {
        reachable: true,
        contentTypeLookedTextLike: true,
        bodyTruncated: false
      });

      return [{
        kind: 'security_txt_metadata',
        safeSummary: 'security.txt metadata probe modeled by fake adapter',
        confidence: 'medium',
        metadata
      }];
    }

    return [];
  }
}
