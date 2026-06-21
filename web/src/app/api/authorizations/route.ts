import { NextResponse } from 'next/server';
import { db } from '@/db/db';
import { authorizations, users } from '@/db/schema';
import { eq } from 'drizzle-orm';

/**
 * POST /api/authorizations
 * Body: { domain: string, userId?: number }
 * Registra un dominio como autorizado para ataques agresivos.
 */
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { domain, userId } = body;

    if (!domain || typeof domain !== 'string') {
      return NextResponse.json({ error: 'Se requiere un dominio válido.' }, { status: 400 });
    }

    // Normalizar el dominio: extraer hostname si viene como URL completa
    let targetDomain = domain.trim();
    try {
      if (targetDomain.startsWith('http://') || targetDomain.startsWith('https://')) {
        targetDomain = new URL(targetDomain).hostname;
      }
    } catch {
      // Si no parsea como URL, usar el string directamente (ej: "example.com")
    }

    // Resolver el usuario: usar el proporcionado o el primero disponible (anonymous)
    let resolvedUserId = userId;
    if (!resolvedUserId) {
      let defaultUser = await db.select().from(users).limit(1).then((res) => res[0]);
      if (!defaultUser) {
        const inserted = await db
          .insert(users)
          .values({ email: `anonymous_${Date.now()}@fixguard.local` })
          .returning();
        defaultUser = inserted[0];
      }
      resolvedUserId = defaultUser.id;
    }

    // Evitar duplicados: verificar si ya existe el dominio para este usuario
    const existing = await db
      .select()
      .from(authorizations)
      .where(eq(authorizations.userId, resolvedUserId));

    const alreadyExists = existing.some((r) => r.targetDomain === targetDomain);
    if (alreadyExists) {
      return NextResponse.json(
        { message: 'El dominio ya está autorizado.', domain: targetDomain },
        { status: 200 }
      );
    }

    // Generar una firma simple como registro de auditoría
    const signature = `fixguard-ui-consent-${Date.now()}`;

    const [inserted] = await db
      .insert(authorizations)
      .values({
        userId: resolvedUserId,
        targetDomain,
        signature,
      })
      .returning();

    return NextResponse.json(
      {
        message: 'Dominio autorizado exitosamente.',
        authorization: inserted,
      },
      { status: 201 }
    );
  } catch (error) {
    console.error('[API /authorizations POST]', error);
    return NextResponse.json({ error: 'Error interno del servidor.' }, { status: 500 });
  }
}

/**
 * GET /api/authorizations
 * Retorna todos los dominios autorizados, opcionalmente filtrado por userId
 * Query params: ?userId=<id>
 */
export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const userIdParam = searchParams.get('userId');

    let query = db.select().from(authorizations).$dynamic();

    if (userIdParam) {
      const uid = parseInt(userIdParam, 10);
      if (!isNaN(uid)) {
        query = query.where(eq(authorizations.userId, uid));
      }
    }

    const records = await query.orderBy(authorizations.authorizedAt);

    return NextResponse.json({ authorizations: records });
  } catch (error) {
    console.error('[API /authorizations GET]', error);
    return NextResponse.json({ error: 'Error interno del servidor.' }, { status: 500 });
  }
}
