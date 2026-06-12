import { NextResponse } from 'next/server';
import { db } from '@/db/db';
import { scans, users } from '@/db/schema';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { targetUrl, vectorId, parentScanId } = body;

    if (!targetUrl || !vectorId || !parentScanId) {
      return NextResponse.json({ error: 'Faltan parámetros requeridos (targetUrl, vectorId, parentScanId)' }, { status: 400 });
    }

    // Ensure we have at least one user for the foreign key
    let defaultUser = await db.select().from(users).limit(1).then(res => res[0]);
    if (!defaultUser) {
      const insertedUsers = await db.insert(users).values({ email: `anonymous_${Date.now()}@test.com` }).returning();
      defaultUser = insertedUsers[0];
    }

    // Insertar un nuevo scan de tipo 'targeted'
    const insertedScans = await db.insert(scans).values({
      userId: defaultUser.id,
      targetUrl,
      mode: 'targeted',
      status: 'pending',
      targetedVectorId: vectorId,
      parentScanId: parentScanId
    }).returning({ id: scans.id });

    const newScanId = insertedScans[0].id;

    // Disparar el ataque dirigido hacia el worker que ya tiene un endpoint listo
    fetch('http://localhost:3001/api/attack/targeted', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        targetUrl,
        scanId: newScanId,
        vectorId,
        parentId: parentScanId
      }),
    }).catch(err => console.error('Error invoking worker API for targeted attack:', err));

    return NextResponse.json({ success: true, targetedScanId: newScanId });
  } catch (error) {
    console.error('Error creating targeted attack:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
