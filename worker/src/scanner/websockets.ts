import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';
import * as cheerio from 'cheerio';

export async function runWebSocketsScan(scanId: number, targetUrl: string) {
  try {
    const response = await axios.get(targetUrl, { timeout: 5000, validateStatus: () => true });
    if (typeof response.data !== 'string') return;

    // Buscar WebSockets en el HTML principal
    const wsRegex = /(ws:\/\/|wss:\/\/|socket\.io)/i;
    
    if (wsRegex.test(response.data)) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'WEBSOCKETS_DETECTED',
        severity: 'LOW',
        description: `Vulnerabilidad BAJA (Informativa). Se detectó el uso de WebSockets (ws://, wss:// o Socket.io) en el código fuente. Se recomienda verificar manualmente que los canales de comunicación en tiempo real requieren autenticación y no exponen datos sensibles de otros usuarios.`,
        autoFixCode: null,
      });
    }
  } catch (error: any) {
    console.error(`[Scan ${scanId}] WebSockets scan error:`, error?.message || String(error));
  }
}
