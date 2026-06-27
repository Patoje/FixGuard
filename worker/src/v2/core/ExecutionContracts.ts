export interface TargetContext {
  uri: string;
  headers?: Record<string, string>;
  env?: string;
}

export interface CapabilityRequest {
  capability: string;
  target: TargetContext;
  config: Record<string, unknown>;
}

export interface ExecutionRequest {
  binary: string;
  args: string[];
  env?: Record<string, string>;
  timeoutMs: number;
}

export interface RawExecutionOutput {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  timedOut: boolean;
}
