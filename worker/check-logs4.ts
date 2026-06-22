import { db } from './src/db/db';
import { scans, vulnerabilities, reconProfiles } from './src/db/schema';
import { eq } from 'drizzle-orm';

async function run() {
  const profile = await db.select().from(reconProfiles).where(eq(reconProfiles.scanId, 455)).limit(1).then(r => r[0]);
  if (profile) {
    console.log("Endpoints count:", profile.endpoints?.length);
    console.log("Attack Surface count:", (profile.attackSurface as any[])?.length);
  }
  process.exit(0);
}
run().catch(console.error);
