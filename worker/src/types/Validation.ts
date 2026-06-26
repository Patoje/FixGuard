/**
 * Validation.ts
 * 
 * Contract for validation utilities used across the ToolAdapter architecture.
 * Provides standardized validation mechanisms for all the new type definitions.
 */

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
}

export interface Validator<T> {
  validate(input: T): ValidationResult;
}

/**
 * Validation utilities for the ToolAdapter architecture
 */
export class Validation {
  /**
   * Validate that a string is not empty
   */
  static requiredString(value: string | undefined | null, fieldName: string): ValidationResult {
    if (!value) {
      return {
        isValid: false,
        errors: [`Field '${fieldName}' is required`],
        warnings: []
      };
    }
    
    if (typeof value !== 'string' || value.trim().length === 0) {
      return {
        isValid: false,
        errors: [`Field '${fieldName}' must be a non-empty string`],
        warnings: []
      };
    }
    
    return { isValid: true, errors: [], warnings: [] };
  }

  /**
   * Validate that a value is within allowed options
   */
  static enumValue<T>(value: T, allowedValues: T[], fieldName: string): ValidationResult {
    if (!allowedValues.includes(value)) {
      return {
        isValid: false,
        errors: [`Field '${fieldName}' has invalid value. Allowed values: ${allowedValues.join(', ')}`],
        warnings: []
      };
    }
    
    return { isValid: true, errors: [], warnings: [] };
  }

  /**
   * Validate URL format
   */
  static url(value: string, fieldName: string): ValidationResult {
    const result = this.requiredString(value, fieldName);
    if (!result.isValid) return result;

    try {
      new URL(value);
      return { isValid: true, errors: [], warnings: [] };
    } catch (error) {
      return {
        isValid: false,
        errors: [`Field '${fieldName}' must be a valid URL`],
        warnings: []
      };
    }
  }

  /**
   * Validate UUID format
   */
  static uuid(value: string, fieldName: string): ValidationResult {
    const result = this.requiredString(value, fieldName);
    if (!result.isValid) return result;

    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(value)) {
      return {
        isValid: false,
        errors: [`Field '${fieldName}' must be a valid UUID`],
        warnings: []
      };
    }

    return { isValid: true, errors: [], warnings: [] };
  }

  /**
   * Validate that a number is positive
   */
  static positiveNumber(value: number, fieldName: string): ValidationResult {
    if (typeof value !== 'number' || isNaN(value)) {
      return {
        isValid: false,
        errors: [`Field '${fieldName}' must be a valid number`],
        warnings: []
      };
    }

    if (value <= 0) {
      return {
        isValid: false,
        errors: [`Field '${fieldName}' must be a positive number`],
        warnings: []
      };
    }

    return { isValid: true, errors: [], warnings: [] };
  }

  /**
   * Validate an array has minimum length
   */
  static minLength<T>(array: T[], minLength: number, fieldName: string): ValidationResult {
    if (!Array.isArray(array)) {
      return {
        isValid: false,
        errors: [`Field '${fieldName}' must be an array`],
        warnings: []
      };
    }

    if (array.length < minLength) {
      return {
        isValid: false,
        errors: [`Field '${fieldName}' must have at least ${minLength} elements`],
        warnings: []
      };
    }

    return { isValid: true, errors: [], warnings: [] };
  }

  /**
   * Combine multiple validation results
   */
  static combine(results: ValidationResult[]): ValidationResult {
    const allErrors = results.flatMap(r => r.errors);
    const allWarnings = results.flatMap(r => r.warnings || []);
    
    return {
      isValid: allErrors.length === 0,
      errors: allErrors,
      warnings: allWarnings
    };
  }
}

/**
 * Validation implementations for our core types
 */
export class TargetContextValidator implements Validator<import('./TargetContext').TargetContext> {
  validate(context: import('./TargetContext').TargetContext): ValidationResult {
    const results: ValidationResult[] = [];

    // Validate required fields
    results.push(Validation.requiredString(context.targetId, 'targetId'));
    results.push(Validation.url(context.targetUrl, 'targetUrl'));

    // Validate technologies array
    if (context.technologies) {
      for (let i = 0; i < context.technologies.length; i++) {
        const tech = context.technologies[i];
        if (tech) {
          results.push(Validation.requiredString(tech.name, `technologies[${i}].name`));
        }
      }
    }

    return Validation.combine(results);
  }
}

export class AssessmentProfileValidator implements Validator<import('./AssessmentProfile').AssessmentProfile> {
  validate(profile: import('./AssessmentProfile').AssessmentProfile): ValidationResult {
    const results: ValidationResult[] = [];

    results.push(Validation.requiredString(profile.id, 'profile.id'));
    results.push(Validation.requiredString(profile.name, 'profile.name'));
    results.push(Validation.requiredString(profile.description, 'profile.description'));

    // Validate risk level
    results.push(Validation.enumValue(profile.riskLevel, ['low', 'medium', 'high', 'critical'], 'riskLevel'));

    // Validate assessment intent if present
    if (profile.assessmentIntent) {
      results.push(Validation.requiredString(profile.assessmentIntent.purpose?.toString(), 'assessmentIntent.purpose'));
      results.push(Validation.requiredString(profile.assessmentIntent.scope?.toString(), 'assessmentIntent.scope'));
      results.push(Validation.requiredString(profile.assessmentIntent.depth?.toString(), 'assessmentIntent.depth'));
    }

    return Validation.combine(results);
  }
}

export class ExecutionPlanValidator implements Validator<import('./ExecutionPlan').ExecutionPlan> {
  validate(plan: import('./ExecutionPlan').ExecutionPlan): ValidationResult {
    const results: ValidationResult[] = [];

    results.push(Validation.requiredString(plan.planId, 'planId'));
    results.push(Validation.positiveNumber(plan.timeout, 'timeout'));

    // Validate steps
    if (plan.steps && plan.steps.length > 0) {
      for (let i = 0; i < plan.steps.length; i++) {
        const step = plan.steps[i];
        if (step) {
          results.push(Validation.requiredString(step.stepId, `steps[${i}].stepId`));
        }
      }
    }

    return Validation.combine(results);
  }
}

export class EvidenceValidator implements Validator<import('./Evidence').Evidence> {
  validate(evidence: import('./Evidence').Evidence): ValidationResult {
    const results: ValidationResult[] = [];

    results.push(Validation.requiredString(evidence.evidenceId, 'evidenceId'));
    results.push(Validation.requiredString(evidence.sourceTool, 'sourceTool'));
    results.push(Validation.requiredString(evidence.type, 'type'));
    
    if (typeof evidence.quality !== 'number' || evidence.quality < 0 || evidence.quality > 1) {
      results.push({
        isValid: false,
        errors: ['Evidence quality must be a number between 0 and 1'],
        warnings: []
      });
    }

    return Validation.combine(results);
  }
}

export class RawExecutionOutputValidator implements Validator<import('./RawExecutionOutput').RawExecutionOutput> {
  validate(output: import('./RawExecutionOutput').RawExecutionOutput): ValidationResult {
    const results: ValidationResult[] = [];

    results.push(Validation.requiredString(output.executionId, 'executionId'));
    results.push(Validation.requiredString(output.toolId, 'toolId'));
    results.push(Validation.requiredString(output.command, 'command'));

    if (!(output.startTime instanceof Date)) {
      results.push({
        isValid: false,
        errors: ['startTime must be a Date object'],
        warnings: []
      });
    }

    if (!(output.endTime instanceof Date)) {
      results.push({
        isValid: false,
        errors: ['endTime must be a Date object'],
        warnings: []
      });
    }

    if (output.endTime.getTime() < output.startTime.getTime()) {
      results.push({
        isValid: false,
        errors: ['endTime must be after startTime'],
        warnings: []
      });
    }

    return Validation.combine(results);
  }
}