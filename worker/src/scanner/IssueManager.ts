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
        // Check if finding already exists globally (using fingerprint as unique)
        const existing = await db.select().from(findings).where(eq(findings.fingerprint, fingerprint)).limit(1).then(res => res[0]);

        if (existing) {
          console.log(`[IssueManager] Finding already exists globally: ${input.title} at ${input.endpoint}`);
          
          let updatedDetectedBy = existing.detectedBy || [existing.toolSource];
          if (!updatedDetectedBy.includes(input.toolSource)) {
            updatedDetectedBy.push(input.toolSource);
          }

          let updatedConfirmedInScans = existing.confirmedInScans || [existing.scanId];
          if (!updatedConfirmedInScans.includes(input.scanId)) {
            updatedConfirmedInScans.push(input.scanId);
          }

          let newConfidence = 50; // default for single tool
          if (updatedDetectedBy.length >= 2 || updatedConfirmedInScans.length >= 2) {
             newConfidence = 99; // Confirmed across multiple tools or scans
             console.log(`[IssueManager] Correlated! Confidence bumped to 99 for ${input.title}`);
          }

          await db.update(findings)
            .set({ 
              updatedAt: new Date(),
              detectedBy: updatedDetectedBy,
              confirmedInScans: updatedConfirmedInScans,
              confidence: newConfidence
            })
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
          detectedBy: [input.toolSource],
          confirmedInScans: [input.scanId],
          confidence: 50, // Initial confidence "needs_review"
          createdAt: new Date(),
          updatedAt: new Date(),
        });
      }
    } catch (error) {
      console.error(`[IssueManager] Error reporting finding:`, error);
    }
  }
}
