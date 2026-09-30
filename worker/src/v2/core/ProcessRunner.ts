import { spawn } from 'child_process';

import type { ExecutionRequest, RawExecutionOutput } from './ExecutionContracts';
import { noteProcessRunnerReceipt } from './StepInvocationCapture.js';

export interface ProcessRunner {
  execute(request: ExecutionRequest): Promise<RawExecutionOutput>;
}

/**
 * Local process runner — shell:false spawn with an explicit timeout kill.
 *
 * Node's spawn `timeout` option is unreliable across versions / for tools that
 * ignore SIGTERM (e.g. hung gau). We enforce timeoutMs ourselves: SIGTERM then
 * SIGKILL after a short grace period, and always resolve (never hang forever).
 */
export class LocalProcessRunner implements ProcessRunner {
  async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    noteProcessRunnerReceipt(request);
    const startTime = Date.now();

    const env = {
      ...process.env,
      ...request.env,
    };

    return new Promise((resolve, reject) => {
      if (!request.binary) {
        return reject(new Error('Missing binary in ExecutionRequest'));
      }

      const timeoutMs =
        typeof request.timeoutMs === 'number' &&
        Number.isFinite(request.timeoutMs) &&
        request.timeoutMs > 0
          ? request.timeoutMs
          : undefined;

      // Explicitly spawn without shell to avoid interpolation/injection.
      // Do not rely on spawn's timeout option — enforce below.
      const child = spawn(request.binary, request.args, {
        shell: false,
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';
      let timedOut = false;
      let settled = false;
      let killTimer: ReturnType<typeof setTimeout> | undefined;
      let graceTimer: ReturnType<typeof setTimeout> | undefined;

      const clearTimers = (): void => {
        if (killTimer !== undefined) clearTimeout(killTimer);
        if (graceTimer !== undefined) clearTimeout(graceTimer);
      };

      const settle = (code: number | null): void => {
        if (settled) return;
        settled = true;
        clearTimers();
        resolve({
          stdout,
          stderr,
          exitCode: code ?? (timedOut ? 124 : 1),
          durationMs: Date.now() - startTime,
          timedOut,
        });
      };

      child.stdout.on('data', (chunk: Buffer) => {
        stdout += chunk.toString();
      });

      child.stderr.on('data', (chunk: Buffer) => {
        stderr += chunk.toString();
      });

      child.on('error', (err: Error & { code?: string }) => {
        if (settled) return;
        settled = true;
        clearTimers();
        if (err.code === 'ENOENT') {
          reject(
            new Error(
              `Command not found: ${request.binary}. Ensure it is installed and in PATH.`
            )
          );
        } else {
          reject(err);
        }
      });

      child.on('close', (code) => {
        settle(code);
      });

      if (timeoutMs !== undefined) {
        killTimer = setTimeout(() => {
          if (settled) return;
          timedOut = true;
          try {
            child.kill('SIGTERM');
          } catch {
            // process may already be gone
          }
          graceTimer = setTimeout(() => {
            if (settled) return;
            try {
              child.kill('SIGKILL');
            } catch {
              // process may already be gone
            }
            // If close never fires (zombie / uninterruptible), force settle.
            settle(124);
          }, 2_000);
        }, timeoutMs);
      }
    });
  }
}
