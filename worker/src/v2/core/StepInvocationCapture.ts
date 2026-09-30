/**
 * Records the invocation a step actually performed.
 * Process receipts are copied from the ExecutionRequest ProcessRunner received.
 * HTTP receipts are the method and URL of a probe dispatched after preflight.
 */

import { AsyncLocalStorage } from 'node:async_hooks';

import type { ExecutionRequest } from './ExecutionContracts.js';

export type CapturedStepInvocation =
  | {
      readonly kind: 'process';
      readonly binary: string;
      readonly args: readonly string[];
    }
  | {
      readonly kind: 'http';
      readonly method: string;
      readonly url: string;
    }
  | {
      readonly kind: 'not_invoked';
    };

interface CaptureState {
  process: { binary: string; args: readonly string[] } | null;
  http: { method: string; url: string } | null;
}

const storage = new AsyncLocalStorage<CaptureState>();

function current(): CaptureState | undefined {
  return storage.getStore();
}

/**
 * Copy binary and args from the request a ProcessRunner implementation received.
 * Does not compose flags.
 */
export function noteProcessRunnerReceipt(
  request: Pick<ExecutionRequest, 'binary' | 'args'>
): void {
  const state = current();
  if (!state || state.process) return;
  if (typeof request.binary !== 'string' || request.binary.length === 0) return;
  if (!Array.isArray(request.args)) return;
  const args: string[] = [];
  for (const arg of request.args) {
    if (typeof arg !== 'string') return;
    args.push(arg);
  }
  state.process = {
    binary: request.binary,
    args: Object.freeze(args),
  };
}

/** Method and URL of an HTTP probe dispatched after its preflight passed. */
export function noteHttpProbeReceipt(method: string, url: string): void {
  const state = current();
  if (!state || state.http) return;
  if (typeof method !== 'string' || method.length === 0) return;
  if (typeof url !== 'string' || url.length === 0) return;
  state.http = { method, url };
}

export async function captureStepInvocation<T>(
  fn: () => Promise<T>
): Promise<{ readonly result: T; readonly invocation: CapturedStepInvocation }> {
  const state: CaptureState = { process: null, http: null };
  const result = await storage.run(state, fn);
  if (state.process) {
    return {
      result,
      invocation: {
        kind: 'process',
        binary: state.process.binary,
        args: state.process.args,
      },
    };
  }
  if (state.http) {
    return {
      result,
      invocation: {
        kind: 'http',
        method: state.http.method,
        url: state.http.url,
      },
    };
  }
  return { result, invocation: { kind: 'not_invoked' } };
}
