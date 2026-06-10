import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runSsrfScan(scanId: number, targetUrl: string) {
  try {
    const urlObj = new URL(targetUrl);
    
    // Lista de parámetros sospechosos de SSRF
    const ssrfParams = ['url', 'webhook', 'image', 'avatar', 'callback', 'redirect', 'api'];
    let hasSsrfParam = false;
    let testUrl = '';

    for (const param of ssrfParams) {
      if (urlObj.searchParams.has(param)) {
        hasSsrfParam = true;
        // Inyectar IP de metadatos de AWS
        urlObj.searchParams.set(param, 'http://169.254.169.254/latest/meta-data/');
        testUrl = urlObj.toString();
        break;
      }
    }

    if (!hasSsrfParam) return;

    // Probar el SSRF
    const response = await axios.get(testUrl, {
      timeout: 5000,
      validateStatus: () => true
    });

    // Si el servidor tardó mucho o nos devolvió datos extraños, podría ser vulnerable
    // En la vida real se usa un servidor intermedio (Pingback/Interactsh), pero para este escáner:
    if (response.status === 200 || response.status === 500) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'SERVER_SIDE_REQUEST_FORGERY',
        severity: 'CRITICAL',
        description: `Vulnerabilidad CRÍTICA (SSRF). Se inyectó una IP interna de AWS (169.254.169.254) en un parámetro de la URL: ${testUrl}. El servidor intentó procesar la petición. Un atacante podría usar tu servidor como puente para atacar la red interna, escanear puertos internos o robar credenciales Cloud IAM.`,
        autoFixCode: null,
      });
    }

  } catch (error: any) {
    console.error(`[Scan ${scanId}] SSRF scan error:`, error?.message || String(error));
  }
}
