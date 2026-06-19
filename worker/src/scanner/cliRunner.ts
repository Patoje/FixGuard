import { exec } from 'child_process';
import util from 'util';

const execPromise = util.promisify(exec);

/** Strip ANSI/VT100 escape codes so CLI banners render cleanly in the UI */
function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/[\u001B\u009B][[\]()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><~]/g, '');
}

/**
 * Some CLI tools (nmap, subfinder, gau, amass) need a bare hostname, not a full URL.
 * This helper extracts just the hostname when the command is one of those tools.
 */
function resolveTarget(commandTemplate: string, targetUrl: string): string {
  const needsHostname = /^(nmap|subfinder|amass|gau|shodan|kxss)\b/.test(commandTemplate.trim());
  if (needsHostname) {
    try {
      return new URL(targetUrl).hostname;
    } catch {
      // If parsing fails (e.g. already a hostname), return as-is
      return targetUrl.replace(/^https?:\/\//, '').split('/')[0];
    }
  }
  return targetUrl;
}

export async function runCliCommand(commandTemplate: string, targetUrl: string): Promise<string> {
  const resolvedTarget = resolveTarget(commandTemplate, targetUrl);
  const finalCommand = commandTemplate.replace('<TARGET>', resolvedTarget);
  
  try {
    // Run the command with a timeout of 2 minutes (120000ms) to prevent hanging
    // Inject $HOME/go/bin and $HOME/bin into PATH so binaries work even without terminal restart
    const { stdout, stderr } = await execPromise(finalCommand, { 
      timeout: 120000,
      env: { ...process.env, PATH: `${process.env.PATH}:${process.env.HOME}/go/bin:${process.env.HOME}/bin` }
    });
    // Some tools print findings to stdout, others to stderr, we combine them
    return stripAnsi(stdout + '\n' + stderr);
  } catch (error: any) {
    // execPromise throws if exit code is not 0 (very common for nuclei/ffuf even when they find something)
    // The output is still in error.stdout and error.stderr
    if (error.stdout || error.stderr) {
      return stripAnsi((error.stdout || '') + '\n' + (error.stderr || ''));
    }
    throw new Error(`Command failed: ${error.message}`);
  }
}
