import type { ToolDefinition } from './ToolDefinition';
import type { CapabilityRequest } from './ExecutionContracts';

export interface ToolRegistry {
  register(definition: ToolDefinition): void;
  resolve(request: CapabilityRequest): ToolDefinition | undefined;
}

export class LocalToolRegistry implements ToolRegistry {
  private definitions = new Map<string, ToolDefinition[]>();

  register(definition: ToolDefinition): void {
    const existing = this.definitions.get(definition.capability) || [];
    existing.push(definition);
    
    // Sort by priority descending (highest priority first)
    existing.sort((a, b) => b.priority - a.priority);
    this.definitions.set(definition.capability, existing);
  }

  resolve(request: CapabilityRequest): ToolDefinition | undefined {
    const candidates = this.definitions.get(request.capability);
    if (!candidates || candidates.length === 0) {
      return undefined;
    }

    // Return the highest priority definition that meets static requirements
    for (const candidate of candidates) {
      if (this.meetsStaticRequirements(candidate)) {
        return candidate;
      }
    }
    
    return undefined;
  }

  private meetsStaticRequirements(definition: ToolDefinition): boolean {
    if (definition.requirements.supportedPlatforms) {
      return definition.requirements.supportedPlatforms.includes(process.platform);
    }
    return true; // No constraint means it runs everywhere
  }
}
