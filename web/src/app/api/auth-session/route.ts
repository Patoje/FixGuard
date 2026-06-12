import { NextResponse } from 'next/server';
import { db } from '@/db/db';
import { sessions } from '@/db/schema';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { targetUrl, authType, tokenOrCookie } = body;

    if (!targetUrl || !authType || !tokenOrCookie) {
      return NextResponse.json({ error: 'Falta targetUrl, authType o tokenOrCookie' }, { status: 400 });
    }

    const origin = new URL(targetUrl).origin;

    // Desactivar sesiones anteriores globalmente (para simplificar MVP)
    await db.update(sessions).set({ isActive: '0' });

    // Insertar nueva sesión
    await db.insert(sessions).values({
      targetUrl: origin,
      authType,
      cookieHeader: authType === 'cookie' ? tokenOrCookie : null,
      jwtToken: authType === 'jwt' ? tokenOrCookie : null,
      isActive: '1',
    });

    return NextResponse.json({ success: true, message: 'Sesión autenticada guardada' });
  } catch (error) {
    console.error('Error saving session:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
