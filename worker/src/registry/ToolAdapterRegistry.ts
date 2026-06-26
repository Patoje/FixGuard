/**
 * ToolAdapterRegistry - Registry for managing different tool adapters
 * Implements the registry pattern for ToolAdapters
 */

import type { ToolAdapter } from '../types/ToolAdapter';

export class ToolAdapterRegistry {
  private adapters: Map<string, ToolAdapter> = new Map();

  /**
   * Register a tool adapter
   */
  register(adapter: ToolAdapter): void {
    this.adapters.set(adapter.toolId, adapter);
  }

  /**
   * Get a registered tool adapter by ID
   */
  get(toolId: string): ToolAdapter | undefined {
    return this.adapters.get(toolId);
  }

  /**
   * Get all registered adapters
   */
  getAll(): ToolAdapter[] {
    return Array.from(this.adapters.values());
  }

  /**
   * Check if a tool adapter is registered
   */
  has(toolId: string): boolean {
    return this.adapters.has(toolId);
  }

  /**
   * Get all registered tool IDs
   */
  getToolIds(): string[] {
    return Array.from(this.adapters.keys());
  }

  /**
   * Unregister a tool adapter
   */
  unregister(toolId: string): boolean {
    return this.adapters.delete(toolId);
  }
}