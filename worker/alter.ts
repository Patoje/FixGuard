import { neon } from '@neondatabase/serverless';
import * as dotenv from 'dotenv';
dotenv.config();

async function run() {
  try {
    console.log("Connecting to", process.env.DATABASE_URL);
    const sql = neon(process.env.DATABASE_URL!);
    await sql`ALTER TABLE "scans" ADD COLUMN IF NOT EXISTS "mode" varchar DEFAULT 'passive' NOT NULL`;
    console.log("Column added successfully!");
  } catch (err) {
    console.error("Error:", err);
  }
}

run();
