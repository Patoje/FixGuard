import { db } from '../db/db';
import { findings } from '../db/schema';
import { eq } from 'drizzle-orm';
import crypto from 'crypto';

export interface FindingInput {
  scanId: number;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  endpoint?: string;
  method?: string;
  requestRaw?: string;
  responseRaw?: string;
  payloadUsed?: string;
  cweId?: string;
  owaspCategory?: string;
  toolSource: string;
}

export class IssueManager {
  /**
   * Generates a unique fingerprint for a finding to prevent duplicates.
   * Based on endpoint + type/title + parameter/payload
   */
  private static generateFingerprint(input: FindingInput): string {
    const rawString = `${input.endpoint || 'global'}|${input.method || 'any'}|${input.title}|${input.payloadUsed || 'none'}`;
    return crypto.createHash('sha256').update(rawString).digest('hex');
  }

  /**
   * Reports a finding. If a finding with the same fingerprint already exists
   * for this scan, it updates the updatedAt timestamp instead of duplicating it.
   */
  public static async reportFinding(input: FindingInput): Promise<void> {
    const fingerprint = this.generateFingerprint(input);

    try {
      // Check if finding already exists globally (or per scan depending on scope, here we use fingerprint as unique)
      const existing = await db.select().from(findings).where(eq(findings.fingerprint, fingerprint)).limit(1).then(res => res[0]);

      if (existing) {
        // Update last seen
        console.log(`[IssueManager] Duplicate finding suppressed. Updating last_seen for: ${input.title} at ${input.endpoint}`);
        await db.update(findings)
          .set({ updatedAt: new Date() })
          .where(eq(findings.id, existing.id));
      } else {
        // Insert new finding
        console.log(`[IssueManager] New finding registered: [${input.severity.toUpperCase()}] ${input.title}`);
        await db.insert(findings).values({
          scanId: input.scanId,
          fingerprint,
          title: input.title,
          severity: input.severity,
          status: 'open',
          endpoint: input.endpoint,
          method: input.method,
          requestRaw: input.requestRaw,
          responseRaw: input.responseRaw,
          payloadUsed: input.payloadUsed,
          cweId: input.cweId,
          owaspCategory: input.owaspCategory,
          toolSource: input.toolSource,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
      }
    } catch (error) {
      console.error(`[IssueManager] Error reporting finding:`, error);
    }
  }
}
