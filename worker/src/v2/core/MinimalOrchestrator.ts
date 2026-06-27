import type { CapabilityRequest } from './ExecutionContracts';
import type { EvidenceCollection } from './Evidence';
import type { ToolRegistry } from './ToolRegistry';
import type { ProcessRunner } from './ProcessRunner';

export class MinimalOrchestrator {
  constructor(
    private registry: ToolRegistry,
    private runner: ProcessRunner
  ) {}

  async run(request: CapabilityRequest): Promise<EvidenceCollection> {
    const definition = this.registry.resolve(request);
    if (!definition) {
      throw new Error(`No tool definition resolved for capability: ${request.capability}`);
    }

    const validation = definition.adapter.validate(request.config, request.target.uri);
    if (!validation.isValid) {
      throw new Error(`Validation failed: ${validation.errors.join(', ')}`);
    }

    const executionRequest = definition.adapter.prepare(request);
    
    // Execute strictly using the safe ProcessRunner
    const rawOutput = await this.runner.execute(executionRequest);

    // Return the structured evidence collection via the definition's parser
    return definition.parser.parse(rawOutput);
  }
}
