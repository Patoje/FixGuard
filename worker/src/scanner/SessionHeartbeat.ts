import axios from 'axios';
import { SessionManager } from './SessionManager';

export class SessionHeartbeat {
  private static activeHeartbeats: Map<number, NodeJS.Timeout> = new Map();

  /**
   * Starts a heartbeat for a given scan if a session cookie is present.
   * Sends a GET request to the target URL every 4 minutes (240000 ms).
   */
  public static async start(scanId: number, targetUrl: string) {
    if (this.activeHeartbeats.has(scanId)) {
      return; // Ya hay un heartbeat corriendo
    }

    try {
      const authFlags = await SessionManager.getCliAuthFlags(targetUrl, 'curl');
      if (!authFlags || !authFlags.includes('Cookie:')) {
        console.log(`[Scan ${scanId}] 💓 Heartbeat cancelado: No hay cookies de sesión para mantener vivas.`);
        return;
      }

      // Extraer solo el string de la cookie para axios
      const cookieMatch = authFlags.match(/Cookie:\s*([^"']+)/i);
      const cookieHeader = cookieMatch ? cookieMatch[1] : '';

      if (!cookieHeader) return;

      console.log(`[Scan ${scanId}] 💓 Iniciando Heartbeat de sesión (Keep-Alive) cada 4 minutos...`);

      const intervalId = setInterval(async () => {
        try {
          console.log(`[Scan ${scanId}] 💓 Enviando latido (Heartbeat) a ${targetUrl}...`);
          await axios.get(targetUrl, {
            headers: { 'Cookie': cookieHeader },
            validateStatus: () => true, // Accept any status code, we just want to hit the server
            timeout: 5000
          });
        } catch (error) {
          // Si falla un latido por timeout, lo ignoramos para no ensuciar los logs
        }
      }, 4 * 60 * 1000); // 4 minutos

      this.activeHeartbeats.set(scanId, intervalId);
    } catch (error) {
      console.warn(`[Scan ${scanId}] Error al iniciar el Heartbeat:`, error);
    }
  }

  /**
   * Stops the heartbeat for a given scan.
   */
  public static stop(scanId: number) {
    const intervalId = this.activeHeartbeats.get(scanId);
    if (intervalId) {
      clearInterval(intervalId);
      this.activeHeartbeats.delete(scanId);
      console.log(`[Scan ${scanId}] 🛑 Heartbeat detenido.`);
    }
  }
}
