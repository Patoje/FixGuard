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

    // Disparar el ataque y ESPERAR la respuesta del worker para devolverla al frontend
    try {
      const workerRes = await fetch('http://localhost:4000/api/attack/targeted', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetUrl,
          scanId: newScanId,
          vectorId,
          parentId: parentScanId
        }),
        // 30 segundos de timeout para herramientas pesadas
        signal: AbortSignal.timeout(30000),
      });
      const workerData = await workerRes.json();
      return NextResponse.json({ success: true, targetedScanId: newScanId, workerOutput: workerData });
    } catch (workerErr: any) {
      // Si el worker tarda demasiado o falla, igual respondemos OK
      return NextResponse.json({ success: true, targetedScanId: newScanId, workerOutput: { error: workerErr.message } });
    }

  } catch (error) {
    console.error('Error creating targeted attack:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
