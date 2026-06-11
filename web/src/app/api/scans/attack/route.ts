import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { scanId, targetUrl, vectorId, parentId } = body;

    if (!scanId || !targetUrl || !vectorId) {
      return NextResponse.json({ error: 'Faltan parámetros requeridos.' }, { status: 400 });
    }

    // Forward request to Worker
    const workerUrl = process.env.WORKER_URL || 'http://localhost:4000';
    const response = await fetch(`${workerUrl}/api/attack/targeted`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ scanId, targetUrl, vectorId, parentId }),
    });

    if (!response.ok) {
      throw new Error(`Worker respondió con error: ${response.statusText}`);
    }

    const data = await response.json();
    return NextResponse.json(data);
  } catch (error: any) {
    console.error('Error al lanzar ataque dirigido:', error);
    return NextResponse.json(
      { error: 'Error al comunicarse con el worker.' },
      { status: 500 }
    );
  }
}
