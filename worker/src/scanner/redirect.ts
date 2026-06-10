import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runRedirectScan(scanId: number, targetUrl: string) {
  try {
    const urlObj = new URL(targetUrl);
    
    // Lista de parámetros sospechosos de redirección
    const redirectParams = ['next', 'returnUrl', 'return_url', 'redirect', 'callback', 'continue', 'url', 'dest'];
    let hasRedirectParam = false;
    let testUrl = '';

    for (const param of redirectParams) {
      if (urlObj.searchParams.has(param)) {
        hasRedirectParam = true;
        // Inyectar URL maliciosa
        urlObj.searchParams.set(param, 'https://evil.com');
        testUrl = urlObj.toString();
        break;
      }
    }

    if (!hasRedirectParam) return;

    // Evitar que Axios siga la redirección automáticamente para poder leer el código HTTP 301/302
    const response = await axios.get(testUrl, {
      timeout: 5000,
      maxRedirects: 0,
      validateStatus: () => true
    });

    // Si el servidor responde con una redirección hacia nuestra URL inyectada
    if ([301, 302, 307, 308].includes(response.status) && response.headers.location === 'https://evil.com') {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'OPEN_REDIRECT',
        severity: 'MEDIUM',
        description: `Vulnerabilidad MEDIA (Open Redirect). El parámetro de la URL fue modificado a: ${testUrl}. El servidor confió ciegamente en la entrada y generó una redirección HTTP (${response.status}) hacia 'https://evil.com'. Los atacantes pueden usar esto para crear campañas de Phishing muy convincentes (robando tokens OAuth si se usa en un flujo SSO).`,
        autoFixCode: null,
      });
    }

  } catch (error: any) {
    console.error(`[Scan ${scanId}] Open Redirect scan error:`, error?.message || String(error));
  }
}
