/**
 * ToolAdapter - Converts structured execution step into executable command
 * Validates configuration and prepares execution
 */

import type { ExecutionStep } from './ExecutionPlan';
import type { TargetContext } from './TargetContext';

export type { ExecutionStep, TargetContext };

export interface ToolAdapter {
  readonly toolId: string;
  readonly capabilities: string[];
  
  prepare(step: ExecutionStep, targetContext: TargetContext): ExecutableCommand;
  validate(config: Record<string, any>): ValidationResult;
  getMetadata(): ToolMetadata;
  isAvailable(): Promise<boolean>;
}

export interface ExecutableCommand {
  binary: string;
  args: string[];
  env?: Record<string, string>;
  timeout?: number;
  stdin?: string;
  metadata: Record<string, any>;
}

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings?: string[];
}

export interface ToolMetadata {
  name: string;
  version: string;
  description: string;
  author: string;
  homepage: string;
  capabilities: string[];
  supportedTargets: string[];
  requirements: ToolRequirements;
  metadata: Record<string, any>;
}

export interface ToolRequirements {
  os: string[];
  arch: string[];
  dependencies: string[];
  minimumResources: ResourceRequirements;
  networkAccess: boolean;
  fileSystemAccess: boolean;
  metadata: Record<string, any>;
}

export interface ResourceRequirements {
  cpu: string; // e.g., "1 core"
  memory: string; // e.g., "512MB"
  disk: string; // e.g., "1GB"
  networkBandwidth?: string; // e.g., "10Mbps"
  metadata: Record<string, any>;
}

// Base class for implementing ToolAdapters
export abstract class BaseToolAdapter implements ToolAdapter {
  abstract readonly toolId: string;
  abstract readonly capabilities: string[];
  
  abstract prepare(step: ExecutionStep, targetContext: TargetContext): ExecutableCommand;
  abstract getMetadata(): ToolMetadata;
  
  validate(config: Record<string, any>): ValidationResult {
    // Default validation implementation - can be overridden
    const errors: string[] = [];
    const warnings: string[] = [];
    
    // Basic validation
    if (typeof config !== 'object') {
      errors.push('Configuration must be an object');
      return { isValid: false, errors, warnings };
    }
    
    // Check for required properties based on common patterns
    if (config.target && typeof config.target !== 'string') {
      errors.push('Target must be a string');
    }
    
    // Check for common configuration patterns
    if (config.timeout && typeof config.timeout !== 'number') {
      errors.push('Timeout must be a number');
    }
    
    if (config.args && !Array.isArray(config.args)) {
      errors.push('Args must be an array');
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }
  
  async isAvailable(): Promise<boolean> {
    // Default implementation checks if binary exists
    try {
      const metadata = this.getMetadata();
      // In a real implementation, this would check if the tool binary exists
      // For now, we'll return true as this is a type definition exercise
      return true;
    } catch (error) {
      return false;
    }
  }
}

// Tool adapter registry interface
export interface ToolAdapterRegistry {
  register(adapter: ToolAdapter): void;
  unregister(toolId: string): void;
  getAdapter(capability: string): ToolAdapter | null;
  getAvailableCapabilities(): string[];
  getAllAdapters(): ToolAdapter[];
  isCapabilityAvailable(capability: string): boolean;
}

// Default implementation of the registry
export class DefaultToolAdapterRegistry implements ToolAdapterRegistry {
  private adapters: Map<string, ToolAdapter> = new Map();
  private capabilityMap: Map<string, string> = new Map(); // capability -> toolId
  
  register(adapter: ToolAdapter): void {
    this.adapters.set(adapter.toolId, adapter);
    
    // Map each capability to this adapter
    // Note: In a real implementation, we'd handle multiple adapters per capability
    for (const capability of adapter.capabilities) {
      this.capabilityMap.set(capability, adapter.toolId);
    }
  }
  
  unregister(toolId: string): void {
    const adapter = this.adapters.get(toolId);
    if (adapter) {
      // Remove capability mappings
      for (const capability of adapter.capabilities) {
        if (this.capabilityMap.get(capability) === toolId) {
          this.capabilityMap.delete(capability);
        }
      }
      this.adapters.delete(toolId);
    }
  }
  
  getAdapter(capability: string): ToolAdapter | null {
    const toolId = this.capabilityMap.get(capability);
    if (toolId) {
      return this.adapters.get(toolId) || null;
    }
    return null;
  }
  
  getAvailableCapabilities(): string[] {
    return Array.from(this.capabilityMap.keys());
  }
  
  getAllAdapters(): ToolAdapter[] {
    return Array.from(this.adapters.values());
  }
  
  isCapabilityAvailable(capability: string): boolean {
    return this.capabilityMap.has(capability);
  }
}