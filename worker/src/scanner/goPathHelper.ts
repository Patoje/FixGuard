import { exec } from 'child_process';
import util from 'util';
import path from 'path';
import os from 'os';

const execPromise = util.promisify(exec);

let cachedGoPath: string | null = null;

export async function getGoPath(): Promise<string> {
  if (cachedGoPath) return cachedGoPath;

  if (process.env.GOPATH) {
    cachedGoPath = path.join(process.env.GOPATH, 'bin');
    return cachedGoPath;
  }

  try {
    const { stdout } = await execPromise('go env GOPATH');
    const goPath = stdout.trim();
    if (goPath) {
      cachedGoPath = path.join(goPath, 'bin');
      return cachedGoPath;
    }
  } catch (e) {
    // Fallback if `go` is not in PATH
  }

  // Fallback to default macOS/Linux path
  cachedGoPath = path.join(os.homedir(), 'go', 'bin');
  return cachedGoPath;
}
