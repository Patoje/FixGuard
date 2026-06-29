import type { ActiveReconAdapter } from './ActiveReconAdapter.js';
import type { ActiveReconProbeRequest, SafeActiveReconObservation } from './ActiveReconContracts.js';

export class FakeActiveReconAdapter implements ActiveReconAdapter {
  public executionCount = 0;

  async probe(request: ActiveReconProbeRequest): Promise<SafeActiveReconObservation[]> {
    this.executionCount++;

    if (request.capabilityId === 'http.robots.inspect') {
      return [{
        kind: 'robots_metadata',
        safeSummary: 'robots metadata probe modeled by fake adapter',
        confidence: 'medium'
      }];
    }

    if (request.capabilityId === 'http.security_txt.inspect') {
      return [{
        kind: 'security_txt_metadata',
        safeSummary: 'security.txt metadata probe modeled by fake adapter',
        confidence: 'medium'
      }];
    }

    return [];
  }
}
