import type { AuditEntry } from './ApprovalContracts';

export interface AuditLog {
  record(entry: AuditEntry): void;
  getAll(): AuditEntry[];
  getByRecommendation(id: string): AuditEntry[];
}

export class LocalAuditLog implements AuditLog {
  private entries: AuditEntry[] = [];

  record(entry: AuditEntry): void {
    // Deep copy to enforce immutability
    this.entries.push(JSON.parse(JSON.stringify(entry)));
  }

  getAll(): AuditEntry[] {
    return JSON.parse(JSON.stringify(this.entries));
  }

  getByRecommendation(id: string): AuditEntry[] {
    return this.getAll().filter(e => e.recommendationId === id);
  }
}
