import { spawn } from 'child_process';

import type { ExecutionRequest, RawExecutionOutput } from './ExecutionContracts';

export interface ProcessRunner {
  execute(request: ExecutionRequest): Promise<RawExecutionOutput>;
}

export class LocalProcessRunner implements ProcessRunner {
  async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    const startTime = Date.now();
    
    const env = { 
      ...process.env, 
      ...request.env 
    };

    return new Promise((resolve, reject) => {
      if (!request.binary) {
        return reject(new Error('Missing binary in ExecutionRequest'));
      }

      // Explicitly spawn without shell to avoid interpolation/injection
      const child = spawn(request.binary, request.args, {
        shell: false,
        timeout: request.timeoutMs,
        env,
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let stdout = '';
      let stderr = '';
      let timedOut = false;

      child.stdout.on('data', (chunk: Buffer) => {
        stdout += chunk.toString();
      });

      child.stderr.on('data', (chunk: Buffer) => {
        stderr += chunk.toString();
      });

      child.on('error', (err: Error & { code?: string }) => {
        if (err.code === 'ENOENT') {
          reject(new Error(`Command not found: ${request.binary}. Ensure it is installed and in PATH.`));
        } else {
          reject(err);
        }
      });

      child.on('timeout', () => {
        timedOut = true;
        child.kill('SIGTERM');
      });

      child.on('close', (code) => {
        const endTime = Date.now();
        resolve({
          stdout,
          stderr,
          exitCode: code ?? (timedOut ? 124 : 1),
          durationMs: endTime - startTime,
          timedOut
        });
      });
    });
  }
}
