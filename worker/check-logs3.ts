import { db } from './src/db/db';
import { scans, vulnerabilities, reconProfiles } from './src/db/schema';
import { desc, not, eq } from 'drizzle-orm';

async function run() {
  const latestScans = await db.select().from(scans).where(not(eq(scans.mode, 'targeted'))).orderBy(desc(scans.id)).limit(3);
  for (const s of latestScans) {
    console.log(`Scan ${s.id}: [${s.mode}] ${s.status} - ${s.targetUrl} - ${s.createdAt}`);
  }
  process.exit(0);
}
run().catch(console.error);
