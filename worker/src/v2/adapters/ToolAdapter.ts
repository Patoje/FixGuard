import type { CapabilityRequest, ExecutionRequest } from '../core/ExecutionContracts';

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
}

export interface ToolAdapter {
  readonly capability: string;
  prepare(request: CapabilityRequest): ExecutionRequest;
  validate(config: Record<string, unknown>, targetUri: string): ValidationResult;
}
