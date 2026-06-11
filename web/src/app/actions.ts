'use server';

import { db } from '@/db/db';
import { scans, vulnerabilities, users } from '@/db/schema';
import { eq } from 'drizzle-orm';

export async function startScan(targetUrl: string, mode: 'passive' | 'active' | 'aggressive' = 'passive') {
  try {
    // 0. Como aún no tenemos Auth, creamos/buscamos un usuario dummy para evitar el error de llave foránea
    let user = await db.query.users.findFirst();
    if (!user) {
      const [newUser] = await db.insert(users).values({ email: 'test@fixguard.com' }).returning();
      user = newUser;
    }

    // 1. Insertar el scan en la base de datos local como "pending" con el userId
    const [newScan] = await db.insert(scans).values({
      targetUrl,
      userId: user.id,
      status: 'pending'
    }).returning();

    // 2. Hacer la llamada POST al worker local
    // (Asegúrate de que el worker esté corriendo en el puerto 4000)
    const workerRes = await fetch('http://127.0.0.1:4000/api/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        scanId: newScan.id,
        targetUrl: targetUrl,
        mode: mode
      })
    });

    if (!workerRes.ok) {
      throw new Error('El Worker respondió con error');
    }

    return { success: true, scanId: newScan.id };
  } catch (error: any) {
    console.error("Error al iniciar el escaneo:", error.message);
    return { success: false, error: 'No se pudo contactar al Worker. ¿Está corriendo en el puerto 4000?' };
  }
}

export async function startSastScan(targetDir: string) {
  try {
    let user = await db.query.users.findFirst();
    if (!user) {
      const [newUser] = await db.insert(users).values({ email: 'test@fixguard.com' }).returning();
      user = newUser;
    }

    const [newScan] = await db.insert(scans).values({
      targetUrl: targetDir, // Guardamos la ruta del dir como si fuera la URL para reciclar el modelo
      userId: user.id,
      status: 'pending'
    }).returning();

    const workerRes = await fetch('http://127.0.0.1:4000/api/sast', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        scanId: newScan.id,
        targetDir: targetDir
      })
    });

    if (!workerRes.ok) {
      throw new Error('El Worker respondió con error en SAST');
    }

    return { success: true, scanId: newScan.id };
  } catch (error: any) {
    console.error("Error al iniciar SAST:", error.message);
    return { success: false, error: 'No se pudo contactar al Worker. ¿Está corriendo en el puerto 4000?' };
  }
}

export async function checkScanStatus(scanId: number) {
  try {
    // Buscar el estado del scan
    const scanData = await db.query.scans.findFirst({
      where: eq(scans.id, scanId),
    });

    if (!scanData) return { status: 'failed' };

    // Si ya terminó, traer las vulnerabilidades
    if (scanData.status === 'completed' || scanData.status === 'failed') {
      const vulns = await db.query.vulnerabilities.findMany({
        where: eq(vulnerabilities.scanId, scanId)
      });
      return { status: scanData.status, vulnerabilities: vulns };
    }

    return { status: scanData.status };
  } catch (error) {
    console.error("Error consultando estado:", error);
    return { status: 'failed' };
  }
}
