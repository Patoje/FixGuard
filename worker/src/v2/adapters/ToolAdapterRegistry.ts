import type { ToolAdapter } from './ToolAdapter';

/**
 * @deprecated Use ToolRegistry from ../core/ToolRegistry instead.
 * This class will be removed once V1 proofOfConcepts are deleted.
 */
export class ToolAdapterRegistry {
  private adapters = new Map<string, ToolAdapter>();

  register(adapter: ToolAdapter): void {
    this.adapters.set(adapter.capability, adapter);
  }

  get(capability: string): ToolAdapter | undefined {
    return this.adapters.get(capability);
  }

  getAll(): ToolAdapter[] {
    return Array.from(this.adapters.values());
  }
}
