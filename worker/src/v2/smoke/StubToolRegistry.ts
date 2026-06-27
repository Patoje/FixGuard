/**
 * StubToolRegistry — smoke-test-only deterministic stub.
 *
 * Returns fixed EvidenceCollections for subdomain_discovery and http_probe
 * without spawning any external processes. Exports createStubOrchestrator()
 * for smoke tests to wire into V2AssessmentRuntime via constructor injection.
 *
 * Finding types deliberately mirror the real parsers so the real Intelligence
 * Layer rules fire correctly:
 *   subdomain_discovery -> type "subdomain_discovery"  (SubdomainProfilerRule)
 *   http_probe          -> type "http_live_host"        (HttpProbeProfilerRule)
 *
 * Not for production use. Must not be imported outside of src/v2/smoke/.
 */
import { MinimalOrchestrator } from '../core/MinimalOrchestrator';
import type { ProcessRunner } from '../core/ProcessRunner';
import type { ToolRegistry } from '../core/ToolRegistry';
import type { ToolDefinition } from '../core/ToolDefinition';
import type { CapabilityRequest, ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts';
import type { ToolAdapter, ValidationResult } from '../adapters/ToolAdapter';
import type { Parser } from '../parsers/Parser';
import type { EvidenceCollection } from '../core/Evidence';

// ---------------------------------------------------------------------------
// Stub ProcessRunner — never spawns; returns a harmless dummy RawExecutionOutput
// ---------------------------------------------------------------------------
class StubProcessRunner implements ProcessRunner {
  async execute(_request: ExecutionRequest): Promise<RawExecutionOutput> {
    return { stdout: '', stderr: '', exitCode: 0, durationMs: 0, timedOut: false };
  }
}

// ---------------------------------------------------------------------------
// Stub Adapter — validate always passes; prepare returns a harmless placeholder
// ---------------------------------------------------------------------------
class StubAdapter implements ToolAdapter {
  constructor(readonly capability: string) {}

  validate(_config: Record<string, unknown>, _targetUri: string): ValidationResult {
    return { isValid: true, errors: [] };
  }

  prepare(_request: CapabilityRequest): ExecutionRequest {
    // Never actually executed — StubProcessRunner returns before the binary matters
    return { binary: 'stub', args: [], timeoutMs: 1000 };
  }
}

// ---------------------------------------------------------------------------
// Fixed deterministic evidence — types match real parser output so Intelligence
// Layer profiler rules (SubdomainProfilerRule, HttpProbeProfilerRule) fire.
// ---------------------------------------------------------------------------
const STUB_SUBDOMAIN_EVIDENCE: EvidenceCollection = {
  findings: [
    {
      id: 'stub_subdomain_1',
      type: 'subdomain_discovery',    // matches SubdomainProfilerRule
      severity: 'info',
      title: 'Discovered Subdomain',
      description: 'Stub subdomain found for smoke testing',
      target: 'api.example.com',
      evidence: 'api.example.com',
      confidence: 1.0,
      metadata: { subdomain: 'api.example.com', host: 'api.example.com' }
    }
  ],
  metadata: { source: 'stub', runtimeMs: 0 }
};

const STUB_HTTP_EVIDENCE: EvidenceCollection = {
  findings: [
    {
      id: 'stub_http_1',
      type: 'http_live_host',         // matches HttpProbeProfilerRule
      severity: 'info',
      title: 'Live HTTP Host: https://api.example.com',
      description: 'Stub HTTP probe result for smoke testing',
      target: 'https://api.example.com',
      evidence: '{"url":"https://api.example.com","status-code":200}',
      confidence: 0.95,
      metadata: {
        url: 'https://api.example.com',
        host: 'api.example.com',
        statusCode: 200,
        title: 'Example API',
        webserver: 'nginx',
        technologies: ['nginx'],
        scheme: 'https',
        finalUrl: 'https://api.example.com'
      }
    }
  ],
  metadata: { source: 'stub', runtimeMs: 0 }
};

class StubSubdomainParser implements Parser {
  parse(_output: RawExecutionOutput): EvidenceCollection {
    return STUB_SUBDOMAIN_EVIDENCE;
  }
}

class StubHttpParser implements Parser {
  parse(_output: RawExecutionOutput): EvidenceCollection {
    return STUB_HTTP_EVIDENCE;
  }
}

// ---------------------------------------------------------------------------
// StubToolRegistry — implements ToolRegistry; always resolves to stub stubs
// ---------------------------------------------------------------------------
const STUB_DEFINITIONS: ToolDefinition[] = [
  {
    capability: 'subdomain_discovery',
    adapter: new StubAdapter('subdomain_discovery'),
    parser: new StubSubdomainParser(),
    requirements: { binary: 'stub' },
    metadata: { name: 'stub-subfinder', version: 'smoke', description: 'Deterministic stub' },
    priority: 100
  },
  {
    capability: 'http_probe',
    adapter: new StubAdapter('http_probe'),
    parser: new StubHttpParser(),
    requirements: { binary: 'stub' },
    metadata: { name: 'stub-httpx', version: 'smoke', description: 'Deterministic stub' },
    priority: 100
  }
];

class StubToolRegistry implements ToolRegistry {
  register(_definition: ToolDefinition): void {
    // no-op: stubs are fixed at construction time
  }

  resolve(request: CapabilityRequest): ToolDefinition | undefined {
    return STUB_DEFINITIONS.find(d => d.capability === request.capability);
  }
}

// ---------------------------------------------------------------------------
// Factory — exported for use by smoke tests only
// ---------------------------------------------------------------------------
export function createStubOrchestrator(): MinimalOrchestrator {
  return new MinimalOrchestrator(new StubToolRegistry(), new StubProcessRunner());
}
