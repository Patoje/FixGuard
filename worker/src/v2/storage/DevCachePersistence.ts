import fs from 'node:fs';
import path from 'node:path';

/**
 * Shared dev-cache persistence gate and array read/write helpers for the
 * in-memory repositories that opt into local-dev-server persistence
 * (ADR-011: DB-free first). Never active under a smoke/test script run —
 * see the 2026-10-25 fix in InMemoryAttackPlanRepository.ts /
 * InMemoryOrchestratedAssessmentRepository.ts: a smoke test run directly
 * (not through the aggregated `smoke:v2` wrapper) used to load a prior
 * run's stale on-disk state into a "fresh" repository.
 */

const DEV_CACHE_DIR = path.join(process.cwd(), '.dev_cache');

function isRunningFromSmokeOrTestScript(): boolean {
  return process.argv.some(
    (arg) => typeof arg === 'string' && (arg.includes('smoke') || arg.includes('test') || arg.includes('spec'))
  );
}

export function isDevPersistenceEnabled(): boolean {
  return (
    process.env.NODE_ENV !== 'test' &&
    process.env.FIXGUARD_V2_HERMETIC_RECON !== '1' &&
    process.env.FIXGUARD_DISABLE_DEV_CACHE !== '1' &&
    !isRunningFromSmokeOrTestScript()
  );
}

/** Loads a JSON array dev-cache file; returns [] on any absence/corruption/disabled-persistence. */
export function loadDevCacheArray<T>(fileName: string): T[] {
  if (!isDevPersistenceEnabled()) return [];
  try {
    const file = path.join(DEV_CACHE_DIR, fileName);
    if (!fs.existsSync(file)) return [];
    const raw = fs.readFileSync(file, 'utf-8');
    const data = JSON.parse(raw);
    return Array.isArray(data) ? (data as T[]) : [];
  } catch {
    return [];
  }
}

/** Writes a JSON array dev-cache file; a no-op (never throws) when persistence is disabled or the write fails. */
export function saveDevCacheArray<T>(fileName: string, data: readonly T[]): void {
  if (!isDevPersistenceEnabled()) return;
  try {
    if (!fs.existsSync(DEV_CACHE_DIR)) {
      fs.mkdirSync(DEV_CACHE_DIR, { recursive: true });
    }
    fs.writeFileSync(path.join(DEV_CACHE_DIR, fileName), JSON.stringify(data, null, 2), 'utf-8');
  } catch {
    // non-blocking
  }
}
