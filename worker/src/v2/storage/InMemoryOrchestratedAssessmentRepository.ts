/**
 * FixGuard V2 — In-Memory Orchestrated Assessment Repository
 *
 * Provides isolated, thread-safe in-memory persistence for orchestrated assessment records
 * ensuring mutation safety via deep cloning.
 * In local dev, snapshots to .dev_cache/ so tsx watch restarts do not wipe active sessions.
 */

import fs from 'node:fs';
import path from 'node:path';
import type {
  OrchestratedAssessmentRecord,
  OrchestratedAssessmentRepository,
} from '../application/OrchestratedAssessmentContracts.js';

const DEV_CACHE_DIR = path.join(process.cwd(), '.dev_cache');
const ASSESSMENTS_CACHE_FILE = path.join(DEV_CACHE_DIR, 'orchestrated_assessments.json');

function isDevPersistenceEnabled(): boolean {
  return (
    process.env.NODE_ENV !== 'test' &&
    process.env.FIXGUARD_V2_HERMETIC_RECON !== '1' &&
    process.env.FIXGUARD_DISABLE_DEV_CACHE !== '1'
  );
}

export class InMemoryOrchestratedAssessmentRepository
  implements OrchestratedAssessmentRepository
{
  private readonly records = new Map<string, OrchestratedAssessmentRecord>();

  constructor() {
    if (isDevPersistenceEnabled()) {
      try {
        if (fs.existsSync(ASSESSMENTS_CACHE_FILE)) {
          const raw = fs.readFileSync(ASSESSMENTS_CACHE_FILE, 'utf-8');
          const data = JSON.parse(raw);
          if (Array.isArray(data)) {
            for (const item of data) {
              if (item && typeof item.assessmentId === 'string') {
                this.records.set(item.assessmentId, item);
              }
            }
          }
        }
      } catch {
        // fail-safe recovery
      }
    }
  }

  private persistDevCache(): void {
    if (!isDevPersistenceEnabled()) return;
    try {
      if (!fs.existsSync(DEV_CACHE_DIR)) {
        fs.mkdirSync(DEV_CACHE_DIR, { recursive: true });
      }
      const data = Array.from(this.records.values());
      fs.writeFileSync(ASSESSMENTS_CACHE_FILE, JSON.stringify(data, null, 2), 'utf-8');
    } catch {
      // non-blocking
    }
  }

  private clone<T>(value: T): T {
    return JSON.parse(JSON.stringify(value));
  }

  public async save(record: OrchestratedAssessmentRecord): Promise<void> {
    this.records.set(record.assessmentId, this.clone(record));
    this.persistDevCache();
  }

  public async findById(assessmentId: string): Promise<OrchestratedAssessmentRecord | null> {
    const record = this.records.get(assessmentId);
    if (!record) {
      return null;
    }
    return this.clone(record);
  }

  public async list(): Promise<readonly OrchestratedAssessmentRecord[]> {
    return Array.from(this.records.values()).map((r) => this.clone(r));
  }

  public async update(
    assessmentId: string,
    updater: (prev: OrchestratedAssessmentRecord) => OrchestratedAssessmentRecord
  ): Promise<OrchestratedAssessmentRecord> {
    const existing = this.records.get(assessmentId);
    if (!existing) {
      throw new Error(`Orchestrated assessment '${assessmentId}' not found`);
    }

    const updated = updater(this.clone(existing));
    this.records.set(assessmentId, this.clone(updated));
    this.persistDevCache();
    return this.clone(updated);
  }
}

