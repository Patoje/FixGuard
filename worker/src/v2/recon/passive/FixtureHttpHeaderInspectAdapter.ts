import type { CapabilityRequest } from '../../core/ExecutionContracts';
import type { EvidenceCollection } from '../../core/Evidence';
import type { PassiveCapabilityExecutor } from './PassiveCapabilityExecutor';

export class FixtureHttpHeaderInspectAdapter implements PassiveCapabilityExecutor {
  async execute(request: CapabilityRequest): Promise<EvidenceCollection> {
    if (request.capability !== 'http.header.inspect') {
      throw new Error(`Unsupported capability: ${request.capability}`);
    }

    // Produce deterministic safe fixture evidence.
    return {
      findings: [], // Explicitly empty as per M29 rules: no vulnerability claims.
      metadata: {
        capabilityId: 'http.header.inspect',
        evidenceKind: 'observation',
        observationSource: 'deterministic_fixture',
        requestedUrl: request.target.uri,
        observedFacts: {
          statusCode: 200,
          headers: {
            'content-type': 'text/html; charset=utf-8',
            'server': 'nginx/1.24.0',
            'x-powered-by': 'Express',
            'strict-transport-security': 'max-age=31536000; includeSubDomains'
          }
        },
        inferredSignals: [
          {
            kind: 'possible_technology_hint',
            confidence: 'low',
            inferred: true,
            value: 'Express'
          },
          {
            kind: 'possible_technology_hint',
            confidence: 'medium',
            inferred: true,
            value: 'nginx'
          }
        ],
        observedAt: Date.now()
      }
    };
  }
}
