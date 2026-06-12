import { NextResponse } from 'next/server';
import { db } from '@/db/db';
import { scans, vulnerabilities, reconProfiles, findings } from '@/db/schema';
import { eq, or } from 'drizzle-orm';

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id: scanIdStr } = await params;
    const scanId = parseInt(scanIdStr, 10);
    
    if (isNaN(scanId)) {
      return NextResponse.json({ error: 'Invalid scan ID' }, { status: 400 });
    }

    const scanRecords = await db.select().from(scans).where(eq(scans.id, scanId));
    
    if (scanRecords.length === 0) {
      return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
    }

    const scanRecord = scanRecords[0];

    // Get child scan IDs (targeted attacks launched from the Arsenal)
    const childScans = await db.select({ id: scans.id }).from(scans).where(eq(scans.parentScanId, scanId));
    const childScanIds = childScans.map(s => s.id);

    // Fetch vulnerabilities from this scan (passive recon results)
    const vulnRecords = await db.select().from(vulnerabilities).where(eq(vulnerabilities.scanId, scanId));

    // Fetch findings from child targeted attack scans and convert to vulnerability format
    let childFindings: typeof vulnRecords = [];
    if (childScanIds.length > 0) {
      const rawFindings = await db.select().from(findings).where(
        or(...childScanIds.map(id => eq(findings.scanId, id)))
      );
      // Map findings → vulnerability shape so the frontend renders them uniformly
      childFindings = rawFindings.map(f => ({
        id: f.id + 100000, // offset to avoid ID collisions with vulnerabilities table
        scanId: f.scanId,
        type: f.title,
        severity: f.severity.toUpperCase(),
        description: `[Arsenal] ${f.endpoint || ''} — ${f.title}`,
        metadata: JSON.stringify({ endpoint: f.endpoint, method: f.method, payload: f.payloadUsed }),
        parentId: null,
        autoFixCode: null,
        createdAt: f.createdAt,
      }));
    }

    const reconRecords = await db.select().from(reconProfiles).where(eq(reconProfiles.scanId, scanId));

    const severityOrder: Record<string, number> = {
      'CRITICAL': 1,
      'HIGH': 2,
      'MEDIUM': 3,
      'LOW': 4
    };

    const allVulns = [...vulnRecords, ...childFindings];
    allVulns.sort((a, b) => {
      const orderA = severityOrder[a.severity.toUpperCase()] || 99;
      const orderB = severityOrder[b.severity.toUpperCase()] || 99;
      return orderA - orderB;
    });

    return NextResponse.json({
      scan: scanRecord,
      vulnerabilities: allVulns,
      reconProfile: reconRecords[0] || null
    });
  } catch (error) {
    console.error('Error fetching scan:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
