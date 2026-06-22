import { db } from '../db/db';
import { sessions } from '../db/schema';
import { eq, and, like } from 'drizzle-orm';

export class SessionManager {
  /**
   * Obtiene la sesión activa para un objetivo dado.
   */
  public static async getActiveSession(targetUrl: string) {
    try {
      const url = new URL(targetUrl);
      const origin = url.origin;
      
      const allActive = await db.select().from(sessions).where(eq(sessions.isActive, '1'));
      
      // Buscar una sesión que coincida con el origen
      const session = allActive.find(s => origin.includes(s.targetUrl) || s.targetUrl.includes(origin));
        
      return session || null;
    } catch {
      return null;
    }
  }

  /**
   * Obtiene los headers de autenticación para inyectar en Axios/Fetch
   */
  public static async getAuthHeaders(targetUrl: string): Promise<Record<string, string>> {
    const session = await this.getActiveSession(targetUrl);
    if (!session) return {};

    const headers: Record<string, string> = {};
    if (session.authType === 'cookie' && session.cookieHeader) {
      headers['Cookie'] = session.cookieHeader;
    } else if (session.authType === 'jwt' && session.jwtToken) {
      headers['Authorization'] = `Bearer ${session.jwtToken}`;
    }
    
    return headers;
  }

  /**
   * Genera los flags CLI para inyectar autenticación en herramientas externas
   */
  public static async getCliAuthFlags(targetUrl: string, tool: string): Promise<string> {
    const session = await this.getActiveSession(targetUrl);
    if (!session) return '';

    let headerStr = '';
    if (session.authType === 'cookie' && session.cookieHeader) {
      headerStr = `Cookie: ${session.cookieHeader}`;
    } else if (session.authType === 'jwt' && session.jwtToken) {
      headerStr = `Authorization: Bearer ${session.jwtToken}`;
    }

    if (!headerStr) return '';

    // Allowlist estricta para inyección de auth headers en comandos CLI
    if (tool.includes('curl') || tool.includes('ffuf') || tool.includes('nuclei') || tool.includes('dalfox') || tool.includes('katana') || tool.includes('httpx')) {
      return `-H "${headerStr}"`;
    }
    if (tool.includes('wpscan')) {
      return `--header "${headerStr}"`;
    }
    if (tool.includes('sqlmap')) {
      return `--headers="${headerStr}"`;
    }
    if (tool.includes('xsstrike')) {
      return `--headers "${headerStr}"`;
    }
    
    // Si la herramienta no soporta inyección de headers (ej: nmap, trufflehog, subfinder, gau), retornamos vacío
    return '';
  }

  /**
   * Registra una nueva sesión (generalmente desde la UI)
   */
  public static async registerSession(targetUrl: string, authType: 'cookie' | 'jwt', tokenOrCookie: string) {
    try {
      const origin = new URL(targetUrl).origin;
      
      // Desactivar sesiones anteriores globalmente (para simplificar MVP)
      await db.update(sessions).set({ isActive: '0' });

      await db.insert(sessions).values({
        targetUrl: origin,
        authType,
        cookieHeader: authType === 'cookie' ? tokenOrCookie : null,
        jwtToken: authType === 'jwt' ? tokenOrCookie : null,
        isActive: '1'
      });
      
      console.log(`[SessionManager] Sesión ${authType.toUpperCase()} registrada para ${origin}`);
      return true;
    } catch (error) {
      console.error(`[SessionManager] Error registrando sesión:`, error);
      return false;
    }
  }
}
