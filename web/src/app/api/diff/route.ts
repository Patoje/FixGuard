import { NextResponse } from 'next/server';
import { db } from '@/db/db';
import { findings } from '@/db/schema';
import { eq } from 'drizzle-orm';

// Helper para generar una clave única de comparación (evita falsos positivos si el payload exacto cambia)
function getFindingKey(f: any) {
  return `${f.title}|${f.endpoint || 'global'}|${f.method || 'ANY'}`.toLowerCase();
}

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const scanA_id = searchParams.get('scanA');
    const scanB_id = searchParams.get('scanB');

    if (!scanA_id || !scanB_id) {
      return NextResponse.json({ error: 'Faltan parámetros scanA y scanB' }, { status: 400 });
    }

    const scanA = parseInt(scanA_id, 10);
    const scanB = parseInt(scanB_id, 10);

    // Obtener hallazgos de ambos escaneos
    const findingsA = await db.select().from(findings).where(eq(findings.scanId, scanA));
    const findingsB = await db.select().from(findings).where(eq(findings.scanId, scanB));

    // Mapear findings A por su clave para búsqueda rápida
    const mapA = new Map();
    for (const f of findingsA) {
      mapA.set(getFindingKey(f), f);
    }

    // Mapear findings B
    const mapB = new Map();
    for (const f of findingsB) {
      mapB.set(getFindingKey(f), f);
    }

    const result = {
      new: [] as any[],
      resolved: [] as any[],
      persisted: [] as any[]
    };

    // Calcular "Nuevas" y "Persistentes" (Iterando sobre B)
    for (const fB of findingsB) {
      const key = getFindingKey(fB);
      if (mapA.has(key)) {
        result.persisted.push({ current: fB, previous: mapA.get(key) });
      } else {
        result.new.push(fB);
      }
    }

    // Calcular "Resueltas" (Iterando sobre A)
    for (const fA of findingsA) {
      const key = getFindingKey(fA);
      if (!mapB.has(key)) {
        result.resolved.push(fA);
      }
    }

    return NextResponse.json(result);

  } catch (error) {
    console.error('Error calculando diff:', error);
    return NextResponse.json({ error: 'Error interno calculando el Diff' }, { status: 500 });
  }
}
