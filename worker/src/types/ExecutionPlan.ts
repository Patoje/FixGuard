/**
 * ExecutionPlan - Ordered, dependency-aware sequence of execution steps
 * Represents "what to execute and when"
 */

import type { AssessmentIntent } from './AssessmentProfile';
import type { TargetContext } from './TargetContext';

export type { TargetContext };

export interface ExecutionPlan {
  planId: string;
  targetContext: TargetContext;
  steps: ExecutionStep[];
  parallelGroups: string[][]; // groups of steps that can run in parallel
  dependencies: Record<string, string[]>; // stepId → [dependencyStepIds]
  retryPolicy: RetryPolicy;
  timeout: number;
  metadata: Record<string, any>;
}

export interface ExecutionStep {
  stepId: string;
  profileId: string; // references AssessmentProfile
  assessmentIntent: AssessmentIntent; // from AssessmentProfile
  toolCapability: string; // capability to request
  config: Record<string, any>; // mutated by PipelineSelector (but intent-preserving)
  targetContext: TargetContext; // reference, not duplication
  timeout?: number;
  dependencies: string[];
  metadata: Record<string, any>;
}

export interface RetryPolicy {
  maxRetries: number;
  backoffStrategy: 'linear' | 'exponential' | 'fixed';
  backoffInterval: number; // in seconds
  retryConditions: RetryCondition[];
  metadata: Record<string, any>;
}

export interface RetryCondition {
  statusCode: number[];
  errorPatterns: string[];
  shouldRetry(error: Error, attempt: number): boolean;
  metadata: Record<string, any>;
}

// Supporting types for execution planning
export interface ExecutionConstraint {
  resourceLimits: ResourceLimit;
  timeConstraints: TimeConstraint;
  dependencyConstraints: DependencyConstraint;
  metadata: Record<string, any>;
}

export interface ResourceLimit {
  cpuMax: number; // percentage
  memoryMax: string; // e.g., "512MB"
  networkMax: string; // e.g., "10Mbps"
  concurrencyMax: number;
  metadata: Record<string, any>;
}

export interface TimeConstraint {
  startTime?: Date;
  deadline?: Date;
  maxDuration: number; // in seconds
  gracePeriod: number; // in seconds
  metadata: Record<string, any>;
}

export interface DependencyConstraint {
  requires: string[]; // step IDs that must complete first
  blocks: string[]; // step IDs that must wait for this step
  condition: DependencyCondition; // when dependency is satisfied
  metadata: Record<string, any>;
}

export interface DependencyCondition {
  type: 'completion' | 'success' | 'specific_output' | 'evidence_available';
  outputRequirement?: string; // required output for 'specific_output'
  evidenceRequirement?: string; // required evidence for 'evidence_available'
  metadata: Record<string, any>;
}

// Execution plan builders and utilities
export class ExecutionPlanBuilder {
  private plan: Partial<ExecutionPlan>;
  
  constructor(targetContext: TargetContext) {
    this.plan = {
      planId: this.generateId(),
      targetContext,
      steps: [],
      parallelGroups: [],
      dependencies: {},
      retryPolicy: {
        maxRetries: 3,
        backoffStrategy: 'exponential',
        backoffInterval: 1,
        retryConditions: [],
        metadata: {}
      },
      timeout: 3600, // 1 hour default
      metadata: {}
    };
  }
  
  addStep(step: ExecutionStep): ExecutionPlanBuilder {
    if (!this.plan.steps) this.plan.steps = [];
    this.plan.steps.push(step);
    
    // Initialize dependencies record if needed
    if (!this.plan.dependencies) this.plan.dependencies = {};
    
    return this;
  }
  
  addDependency(stepId: string, dependencyId: string): ExecutionPlanBuilder {
    if (!this.plan.dependencies) this.plan.dependencies = {};
    if (!this.plan.dependencies[stepId]) {
      this.plan.dependencies[stepId] = [];
    }
    this.plan.dependencies[stepId].push(dependencyId);
    return this;
  }
  
  setRetryPolicy(policy: RetryPolicy): ExecutionPlanBuilder {
    this.plan.retryPolicy = policy;
    return this;
  }
  
  setTimeout(timeout: number): ExecutionPlanBuilder {
    this.plan.timeout = timeout;
    return this;
  }
  
  build(): ExecutionPlan {
    if (!this.plan.planId) this.plan.planId = this.generateId();
    if (!this.plan.parallelGroups) this.plan.parallelGroups = [];
    if (!this.plan.dependencies) this.plan.dependencies = {};
    if (!this.plan.metadata) this.plan.metadata = {};
    
    return this.plan as ExecutionPlan;
  }
  
  private generateId(): string {
    return `plan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Utility functions
export function validateExecutionPlan(plan: ExecutionPlan): ValidationResult {
  const errors: string[] = [];
  
  // Validate that all dependency references exist
  for (const [stepId, dependencies] of Object.entries(plan.dependencies || {})) {
    if (!plan.steps.some(step => step.stepId === stepId)) {
      errors.push(`Step with ID ${stepId} referenced in dependencies does not exist in plan`);
    }
    
    for (const depId of dependencies) {
      if (!plan.steps.some(step => step.stepId === depId)) {
        errors.push(`Dependency with ID ${depId} referenced by step ${stepId} does not exist in plan`);
      }
    }
  }
  
  // Validate that all steps have valid profile references
  for (const step of plan.steps) {
    if (!step.profileId) {
      errors.push(`Step ${step.stepId} missing profileId`);
    }
    if (!step.toolCapability) {
      errors.push(`Step ${step.stepId} missing toolCapability`);
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
}