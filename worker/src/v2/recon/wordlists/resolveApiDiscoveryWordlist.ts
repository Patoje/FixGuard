/**
 * Gated API discovery wordlist resolver (discovery-only, in-scope).
 *
 * Defaults to the merged SecLists-backed list under wordlists/modern/.
 * Deep fuzz (~10k tokens) is opt-in via FIXGUARD_API_WORDLIST_DEEP=1.
 * Explicit FIXGUARD_API_WORDLIST_PATH always wins.
 */

import { existsSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
/** worker/ — two levels up from src/v2/recon/wordlists */
const WORKER_ROOT = resolve(MODULE_DIR, '../../../..');

export const GATED_API_DISCOVERY_WORDLIST_RELATIVE =
  'wordlists/modern/api-discovery-gated.txt';
export const DEEP_API_DISCOVERY_WORDLIST_RELATIVE =
  'wordlists/modern/seclists-api-endpoints-res.txt';

function resolveUnderWorker(relativePath: string): string {
  return join(WORKER_ROOT, relativePath);
}

function firstExisting(paths: readonly string[]): string | null {
  for (const p of paths) {
    if (typeof p === 'string' && p.length > 0 && existsSync(p)) {
      return p;
    }
  }
  return null;
}

/**
 * Resolve the wordlist path for ffuf/content discovery API fuzzing.
 * Fail-open to relative gated path when files are absent (caller/preflight still validates).
 */
export function resolveApiDiscoveryWordlistPath(options?: {
  readonly preferDeep?: boolean;
  readonly explicitPath?: string;
}): string {
  const envExplicit =
    typeof process.env.FIXGUARD_API_WORDLIST_PATH === 'string'
      ? process.env.FIXGUARD_API_WORDLIST_PATH.trim()
      : '';
  const explicit = (options?.explicitPath ?? envExplicit).trim();
  if (explicit.length > 0) {
    return isAbsolute(explicit) ? explicit : resolve(explicit);
  }

  const deep =
    options?.preferDeep === true ||
    process.env.FIXGUARD_API_WORDLIST_DEEP === '1' ||
    process.env.FIXGUARD_API_WORDLIST_DEEP === 'true';

  if (deep) {
    const deepPath = firstExisting([
      resolveUnderWorker(DEEP_API_DISCOVERY_WORDLIST_RELATIVE),
      resolve(DEEP_API_DISCOVERY_WORDLIST_RELATIVE),
    ]);
    if (deepPath) return deepPath;
  }

  const gated = firstExisting([
    resolveUnderWorker(GATED_API_DISCOVERY_WORDLIST_RELATIVE),
    resolve(GATED_API_DISCOVERY_WORDLIST_RELATIVE),
    resolveUnderWorker('wordlists/core/api-endpoints.txt'),
    resolve('wordlists/core/api-endpoints.txt'),
  ]);

  return gated ?? GATED_API_DISCOVERY_WORDLIST_RELATIVE;
}
