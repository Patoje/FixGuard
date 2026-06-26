/**
 * RawExecutionOutput - Standardized output capture from tool execution
 * Contains execution metadata and results
 */

import type { Finding } from './Evidence';

export interface RawExecutionOutput {
  executionId: string;
  toolId: string;
  command: string; // The actual command that was executed
  executableCommand?: ExecutableCommand; // Structured command if available
  startTime: Date;
  endTime: Date;
  durationMs: number;
  exitCode: number;
  stdout: string;
  stderr: string;
  pid?: number;
  resourcesUsed?: ResourceUsage;
  metadata: Record<string, any>;
}

export interface ExecutableCommand {
  binary: string;
  args: string[];
  env?: Record<string, string>;
  timeout?: number;
  stdin?: string;
  metadata: Record<string, any>;
}

export interface ResourceUsage {
  cpuPercent: number;
  memoryUsed: string; // e.g., "128MB"
  memoryPeak: string;
  diskRead: string;
  diskWrite: string;
  networkIn: string;
  networkOut: string;
  timestamp: Date;
  metadata: Record<string, any>;
}

// Execution result status
export type ExecutionStatus = 'success' | 'failed' | 'timeout' | 'interrupted' | 'partial';

// Execution result with status and parsed data
export interface ExecutionResult {
  executionId: string;
  status: ExecutionStatus;
  output: RawExecutionOutput;
  parsedData?: any; // Tool-specific parsed output
  findings?: Finding[]; // Extracted findings if applicable
  errors: string[];
  warnings: string[];
  metadata: Record<string, any>;
}

// Utility functions for working with execution output
export function isSuccess(output: RawExecutionOutput): boolean {
  return output.exitCode === 0;
}

export function isTimeout(output: RawExecutionOutput): boolean {
  // This would typically be determined by the execution framework
  // For now, we'll use a simple check based on duration vs timeout
  return output.metadata?.timeoutExceeded === true;
}

export function getExecutionStatus(output: RawExecutionOutput): ExecutionStatus {
  if (isTimeout(output)) {
    return 'timeout';
  }
  
  if (output.exitCode === 0) {
    return 'success';
  }
  
  // Different exit codes might indicate different failure types
  // This is a simplified implementation
  return 'failed';
}

export function calculateEfficiency(output: RawExecutionOutput): number {
  // Calculate efficiency as a ratio of useful output to resource consumption
  if (!output.resourcesUsed) {
    // If no resource data, return neutral efficiency
    return 0.5;
  }
  
  const durationSec = output.durationMs / 1000;
  const cpuTime = (output.resourcesUsed.cpuPercent / 100) * durationSec;
  const outputLength = output.stdout.length + output.stderr.length;
  
  // Higher output with lower resource usage = higher efficiency
  if (cpuTime === 0) {
    return outputLength > 0 ? 1.0 : 0.0;
  }
  
  // Normalize to 0-1 range
  const efficiency = Math.min(1.0, outputLength / (cpuTime * 1000));
  return Math.max(0, efficiency);
}

// Execution output builder for consistent creation
export class RawExecutionOutputBuilder {
  private output: Partial<RawExecutionOutput>;
  
  constructor() {
    this.output = {
      metadata: {}
    };
  }
  
  setExecutionId(id: string): RawExecutionOutputBuilder {
    this.output.executionId = id;
    return this;
  }
  
  setToolId(id: string): RawExecutionOutputBuilder {
    this.output.toolId = id;
    return this;
  }
  
  setCommand(command: string): RawExecutionOutputBuilder {
    this.output.command = command;
    return this;
  }
  
  setExecutableCommand(cmd: ExecutableCommand): RawExecutionOutputBuilder {
    this.output.executableCommand = cmd;
    return this;
  }
  
  setStartTime(time: Date): RawExecutionOutputBuilder {
    this.output.startTime = time;
    return this;
  }
  
  setEndTime(time: Date): RawExecutionOutputBuilder {
    this.output.endTime = time;
    return this;
  }
  
  setExitCode(code: number): RawExecutionOutputBuilder {
    this.output.exitCode = code;
    return this;
  }
  
  setStdout(stdout: string): RawExecutionOutputBuilder {
    this.output.stdout = stdout;
    return this;
  }
  
  setStderr(stderr: string): RawExecutionOutputBuilder {
    this.output.stderr = stderr;
    return this;
  }
  
  setResources(resources: ResourceUsage): RawExecutionOutputBuilder {
    this.output.resourcesUsed = resources;
    return this;
  }
  
  setPid(pid: number): RawExecutionOutputBuilder {
    this.output.pid = pid;
    return this;
  }
  
  setMetadata(metadata: Record<string, any>): RawExecutionOutputBuilder {
    this.output.metadata = { ...this.output.metadata, ...metadata };
    return this;
  }
  
  build(): RawExecutionOutput {
    if (!this.output.executionId) {
      this.output.executionId = generateId();
    }
    
    if (!this.output.startTime) {
      this.output.startTime = new Date();
    }
    
    if (!this.output.endTime) {
      this.output.endTime = new Date();
    }
    
    if (!this.output.durationMs) {
      this.output.durationMs = this.output.endTime.getTime() - this.output.startTime.getTime();
    }
    
    if (!this.output.metadata) {
      this.output.metadata = {};
    }
    
    // Calculate duration if not set
    if (this.output.durationMs === undefined && this.output.startTime && this.output.endTime) {
      this.output.durationMs = this.output.endTime.getTime() - this.output.startTime.getTime();
    }
    
    return this.output as RawExecutionOutput;
  }
}

function generateId(): string {
  return `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}