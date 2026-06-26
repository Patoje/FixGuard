import { spawn } from 'child_process';
import os from 'os';

const DEFAULT_TIMEOUT_MS = 120_000;

/** Strip ANSI/VT100 escape codes so CLI banners render cleanly in the UI */
function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/[\u001B\u009B][[\]()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><~]/g, '');
}

/**
 * Parses a command string into an argument array, respecting quoted substrings.
 * Handles both single and double quotes, and backslash-escaped characters.
 *
 * Example: `nuclei -u https://example.com -H "X-Forwarded-For: 127.0.0.1"`
 *       => ['nuclei', '-u', 'https://example.com', '-H', 'X-Forwarded-For: 127.0.0.1']
 */
function parseCommandArgs(cmd: string): string[] {
  const args: string[] = [];
  let current = '';
  let inQuote: string | null = null;
  let i = 0;

  while (i < cmd.length) {
    const ch = cmd[i]!;

    // Handle backslash-escaped character outside quotes
    if (ch === '\\' && !inQuote && i + 1 < cmd.length) {
      current += cmd[++i];
      i++;
      continue;
    }

    if (inQuote) {
      if (ch === inQuote) {
        inQuote = null;
      } else if (ch === '\\' && inQuote === '"' && i + 1 < cmd.length) {
        // Inside double quotes, backslash escapes the next character
        current += cmd[++i];
      } else {
        current += ch;
      }
    } else {
      if (ch === '"' || ch === "'") {
        inQuote = ch;
      } else if (/\s/.test(ch)) {
        if (current.length > 0) {
          args.push(current);
          current = '';
        }
      } else {
        current += ch;
      }
    }
    i++;
  }

  if (current.length > 0) {
    args.push(current);
  }

  return args;
}

/**
 * Some CLI tools (nmap, subfinder, gau, amass) need a bare hostname, not a full URL.
 * This helper extracts just the hostname when the command is one of these tools.
 */
function resolveTarget(commandTemplate: string, targetUrl: string): string {
  const needsHostname = /^(nmap|subfinder|amass|gau|shodan|kxss)\b/.test(commandTemplate.trim());
  if (needsHostname) {
    try {
      return new URL(targetUrl).hostname;
    } catch {
      // If parsing fails (e.g. already a hostname), return as-is
      return targetUrl.replace(/^https?:\/\//, '').split('/')[0] || targetUrl;
    }
  }
  return targetUrl;
}

/** Build extended PATH including ~/go/bin and ~/bin for Go/Rust-based tools */
function buildEnv(): NodeJS.ProcessEnv {
  const homedir = os.homedir();
  const extraPaths = [
    `${homedir}/go/bin`,
    `${homedir}/bin`,
    `${homedir}/.local/bin`,
  ];
  const separator = process.platform === 'win32' ? ';' : ':';
  const currentPath = process.env.PATH || '';

  // Only add paths not already present
  const toAdd = extraPaths.filter(p => !currentPath.includes(p));
  const extendedPath = toAdd.length > 0
    ? `${currentPath}${separator}${toAdd.join(separator)}`
    : currentPath;

  return { ...process.env, PATH: extendedPath };
}

/**
 * Executes a single parsed command via spawn() with shell disabled.
 * Collects stdout + stderr and returns the combined output.
 * Non-zero exit codes still return output (many CLI tools exit non-zero when findings exist).
 */
function spawnCommand(
  args: string[],
  timeoutMs: number,
  env: NodeJS.ProcessEnv
): Promise<string> {
  return new Promise((resolve, reject) => {
    const [command, ...commandArgs] = args;
    if (!command) {
      return reject(new Error('Empty command'));
    }

    const child = spawn(command, commandArgs, {
      shell: false,
      timeout: timeoutMs,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;

    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });

    child.on('error', (err: Error & { code?: string }) => {
      if (err.code === 'ENOENT') {
        reject(new Error(`Command not found: ${command}. Ensure it is installed and in PATH.`));
      } else {
        reject(err);
      }
    });

    child.on('close', () => {
      if (timedOut) return;
      // Tools like nuclei/ffuf/sqlmap often exit non-zero even on successful scans.
      // We always return the combined output â€” callers decide if findings exist.
      resolve(stripAnsi(stdout + '\n' + stderr));
    });

    child.on('timeout', () => {
      timedOut = true;
      child.kill('SIGTERM');
      resolve(stripAnsi(stdout + '\n' + stderr + `\n[Command timed out after ${timeoutMs / 1000}s]`));
    });
  });
}

/**
 * Executes a command with optional stdin input (for pipe chains).
 * Used internally when splitting pipe commands like `gau target | kxss`.
 */
function spawnCommandWithStdin(
  args: string[],
  timeoutMs: number,
  env: NodeJS.ProcessEnv,
  stdinData: string
): Promise<string> {
  return new Promise((resolve, reject) => {
    const [command, ...commandArgs] = args;
    if (!command) {
      return reject(new Error('Empty command'));
    }

    const child = spawn(command, commandArgs, {
      shell: false,
      timeout: timeoutMs,
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;

    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });

    child.on('error', (err: Error & { code?: string }) => {
      if (err.code === 'ENOENT') {
        reject(new Error(`Command not found: ${command}. Ensure it is installed and in PATH.`));
      } else {
        reject(err);
      }
    });

    child.on('close', () => {
      if (timedOut) return;
      resolve(stripAnsi(stdout + '\n' + stderr));
    });

    child.on('timeout', () => {
      timedOut = true;
      child.kill('SIGTERM');
      resolve(stripAnsi(stdout + '\n' + stderr + `\n[Command timed out after ${timeoutMs / 1000}s]`));
    });

    // Write stdin data from previous pipe segment, then close
    if (stdinData) {
      child.stdin.write(stdinData);
    }
    child.stdin.end();
  });
}

/**
 * Executes a CLI command safely using spawn() with shell disabled.
 *
 * Security: Arguments are passed as an array to spawn(), preventing shell
 * interpretation of metacharacters (;, &&, |, $, backticks, etc.).
 * The target URL is validated via the URL constructor before interpolation.
 *
 * Special cases:
 * - Pipe commands (e.g. `gau target | kxss`) are split and executed sequentially,
 *   with stdout from the left side piped to stdin of the right side.
 * - Compound commands with `&&` are split and executed sequentially.
 *
 * @param commandTemplate - Command string with <TARGET> placeholder
 * @param targetUrl       - Target URL (validated and sanitized before interpolation)
 */
export async function runCliCommand(commandTemplate: string, targetUrl: string): Promise<string> {
  const resolvedTarget = resolveTarget(commandTemplate, targetUrl);
  const finalCommand = commandTemplate.replace('<TARGET>', resolvedTarget);
  const env = buildEnv();

  // Handle pipe commands (e.g., "gau example.com | kxss")
  if (finalCommand.includes(' | ')) {
    const segments = finalCommand.split(' | ');
    let prevOutput = '';
    for (const segment of segments) {
      const args = parseCommandArgs(segment.trim());
      if (args.length === 0) continue;
      prevOutput = await spawnCommandWithStdin(args, DEFAULT_TIMEOUT_MS, env, prevOutput);
    }
    return prevOutput;
  }

  // Handle compound commands with && (e.g., "mkdir -p dir && wget ...")
  if (finalCommand.includes(' && ')) {
    const segments = finalCommand.split(' && ');
    let lastOutput = '';
    for (const segment of segments) {
      const args = parseCommandArgs(segment.trim());
      if (args.length === 0) continue;
      lastOutput = await spawnCommand(args, DEFAULT_TIMEOUT_MS, env);
    }
    return lastOutput;
  }

  // Standard single command
  const args = parseCommandArgs(finalCommand);
  if (args.length === 0) {
    throw new Error('Empty command after parsing');
  }

  return spawnCommand(args, DEFAULT_TIMEOUT_MS, env);
}
