import type { ToolAdapter, ExecutionStep, TargetContext, ExecutableCommand, ValidationResult, ToolMetadata } from '../types/ToolAdapter';

/**
 * Base class for implementing ToolAdapters
 */
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