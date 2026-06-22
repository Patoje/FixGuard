import { db } from './src/db/db';
import { scans, vulnerabilities, reconProfiles } from './src/db/schema';
import { desc, eq } from 'drizzle-orm';

async function run() {
  console.log("=== LATEST SCANS ===");
  const latestScans = await db.select().from(scans).orderBy(desc(scans.id)).limit(3);
  for (const s of latestScans) {
    console.log(`Scan ${s.id}: [${s.mode}] ${s.status} - ${s.targetUrl}`);
    const vulns = await db.select().from(vulnerabilities).where(eq(vulnerabilities.scanId, s.id));
    console.log(`  Findings: ${vulns.length}`);
    for (const v of vulns) {
      console.log(`    - [${v.severity}] ${v.type} (${v.description.substring(0, 50)}...)`);
    }
  }
  process.exit(0);
}
run().catch(console.error);
