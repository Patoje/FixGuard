import type { CapabilityDefinition } from './CapabilityDefinition';
import { FORBIDDEN_CAPABILITY_KEYS, validateSafeCapabilityInput } from './SafeCapabilityInput';

export class CapabilityRegistry {
  private readonly capabilities: Map<string, CapabilityDefinition> = new Map();

  public register(definition: CapabilityDefinition): void {
    if (this.capabilities.has(definition.id)) {
      throw new Error(`Capability registration failed: Duplicate capability ID '${definition.id}'`);
    }

    this.validateSafeDefinition(definition);
    
    // Store a deep clone to prevent external mutation
    this.capabilities.set(definition.id, JSON.parse(JSON.stringify(definition)));
  }

  public getDefinition(id: string): CapabilityDefinition | undefined {
    const definition = this.capabilities.get(id);
    return definition ? JSON.parse(JSON.stringify(definition)) : undefined;
  }

  public listDefinitions(): CapabilityDefinition[] {
    return Array.from(this.capabilities.values()).map(def => JSON.parse(JSON.stringify(def)));
  }

  public validateInput(id: string, input: any): void {
    const definition = this.capabilities.get(id);
    if (!definition) {
      throw new Error(`Cannot validate input for unknown capability '${id}'`);
    }
    
    validateSafeCapabilityInput(input);
  }

  private validateSafeDefinition(definition: any, currentDepth = 0): void {
    if (currentDepth > 10) {
      throw new Error('Capability registration failed: Definition exceeds maximum depth');
    }

    if (definition === null || typeof definition !== 'object') {
      return;
    }

    if (Array.isArray(definition)) {
      for (const item of definition) {
        this.validateSafeDefinition(item, currentDepth + 1);
      }
      return;
    }

    for (const key of Object.keys(definition)) {
      if (FORBIDDEN_CAPABILITY_KEYS.includes(key)) {
        throw new Error(`Capability registration failed: Forbidden executable key '${key}' found in definition`);
      }
      this.validateSafeDefinition(definition[key], currentDepth + 1);
    }
  }
}
