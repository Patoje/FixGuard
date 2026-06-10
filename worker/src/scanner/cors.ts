import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runCorsScan(scanId: number, targetUrl: string) {
  try {
    const evilOrigin = 'https://evil.com';
    
    const response = await axios.options(targetUrl, {
      headers: {
        'Origin': evilOrigin,
        'Access-Control-Request-Method': 'GET'
      },
      timeout: 5000,
      validateStatus: () => true
    });

    const acao = response.headers['access-control-allow-origin'];
    
    if (acao === evilOrigin || acao === '*') {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'CORS_MISCONFIGURATION',
        severity: 'HIGH',
        description: `Vulnerabilidad ALTA de CORS. El servidor acepta el origen '${evilOrigin}' y devolvió 'Access-Control-Allow-Origin: ${acao}'. Esto permite que sitios de terceros maliciosos realicen peticiones a tu API en nombre del usuario, exponiendo datos sensibles.`,
        autoFixCode: null,
      });
    }
  } catch (error: any) {
    console.error(`[Scan ${scanId}] CORS scan error:`, error?.message || String(error));
  }
}
