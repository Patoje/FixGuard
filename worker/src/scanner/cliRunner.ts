import { exec } from 'child_process';
import util from 'util';

const execPromise = util.promisify(exec);

export async function runCliCommand(commandTemplate: string, targetUrl: string): Promise<string> {
  const finalCommand = commandTemplate.replace('<TARGET>', targetUrl);
  
  try {
    // Run the command with a timeout of 2 minutes (120000ms) to prevent hanging
    const { stdout, stderr } = await execPromise(finalCommand, { timeout: 120000 });
    // Some tools print findings to stdout, others to stderr, we combine them or just use stdout
    return stdout + '\n' + stderr;
  } catch (error: any) {
    // execPromise throws if exit code is not 0 (which is very common for nuclei/ffuf if they fail or even if they find something sometimes)
    // The output is still in error.stdout and error.stderr
    if (error.stdout || error.stderr) {
      return (error.stdout || '') + '\n' + (error.stderr || '');
    }
    throw new Error(`Command failed: ${error.message}`);
  }
}
