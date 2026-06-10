import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runRateLimitScan(scanId: number, targetUrl: string) {
  try {
    const REQUESTS_TO_SEND = 30;
    
    // Crear un array de promesas de peticiones concurrentes
    const requests = Array.from({ length: REQUESTS_TO_SEND }).map(() => 
      axios.get(targetUrl, {
        timeout: 8000,
        validateStatus: () => true
      }).catch(e => ({ status: 0 })) // Capturar timeouts para que Promise.all no explote
    );

    const startTime = Date.now();
    const results = await Promise.all(requests);
    const endTime = Date.now();

    let rateLimited = false;
    let allSucceeded = true;

    for (const res of results) {
      if (res.status === 429) {
        rateLimited = true;
        break;
      }
      // Si recibimos un 503, WAF block (403), etc. asumimos que hay protección
      if (res.status >= 500 || res.status === 403) {
        allSucceeded = false;
      }
    }

    // Si enviamos 30 peticiones casi instantáneas y TODAS devolvieron 200, no hay Rate Limit
    if (!rateLimited && allSucceeded && (endTime - startTime) < 5000) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'MISSING_RATE_LIMITING',
        severity: 'LOW',
        description: `Vulnerabilidad BAJA. No se detectó protección de 'Rate Limiting' en la ruta principal. El motor pudo enviar 30 peticiones concurrentes en menos de 5 segundos sin ser bloqueado. Esto expone la aplicación a ataques de denegación de servicio (DDoS) a nivel de aplicación o scraping masivo de datos.`,
        autoFixCode: null,
      });
    }

  } catch (error) {
    console.error(`[Scan ${scanId}] Rate Limit scan error:`, error);
  }
}
