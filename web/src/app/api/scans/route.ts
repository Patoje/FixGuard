import { NextResponse } from 'next/server';
import { db } from '@/db/db';
import { scans, users } from '@/db/schema';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { targetUrl, mode } = body;

    if (!targetUrl || !mode) {
      return NextResponse.json({ error: 'Falta targetUrl o mode' }, { status: 400 });
    }

    // Ensure we have at least one user for the foreign key
    let defaultUser = await db.select().from(users).limit(1).then(res => res[0]);
    if (!defaultUser) {
      const insertedUsers = await db.insert(users).values({ email: `anonymous_${Date.now()}@test.com` }).returning();
      defaultUser = insertedUsers[0];
    }

    const insertedScans = await db.insert(scans).values({
      userId: defaultUser.id,
      targetUrl,
      mode,
      status: 'pending',
    }).returning({ id: scans.id });

    const scanId = insertedScans[0].id;

    return NextResponse.json({ scanId });
  } catch (error) {
    console.error('Error creating scan:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}

export async function GET(request: Request) {
  try {
    const allScans = await db.select().from(scans).orderBy(scans.createdAt);
    return NextResponse.json(allScans);
  } catch (error) {
    console.error('Error fetching scans:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
