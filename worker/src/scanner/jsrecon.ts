import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';
import * as cheerio from 'cheerio';

export async function runJsReconScan(scanId: number, targetUrl: string) {
  try {
    const baseUrl = new URL(targetUrl).origin;
    
    // 1. Obtener HTML
    const response = await axios.get(targetUrl, {
      timeout: 5000,
      validateStatus: () => true
    });

    if (typeof response.data !== 'string') return;

    // 2. Extraer scripts
    const $ = cheerio.load(response.data);
    const jsFiles: string[] = [];
    
    $('script').each((_, el) => {
      let src = $(el).attr('src');
      if (src) {
        if (!src.startsWith('http')) {
          src = src.startsWith('/') ? `${baseUrl}${src}` : `${baseUrl}/${src}`;
        }
        if (src.startsWith(baseUrl)) { // Solo analizar scripts propios
          jsFiles.push(src);
        }
      }
    });

    let foundEndpoints = new Set<string>();
    let foundFlags = new Set<string>();

    // 3. Analizar cada script
    for (const jsUrl of jsFiles.slice(0, 5)) { // Limitar a 5 scripts para rendimiento
      try {
        const jsResponse = await axios.get(jsUrl, { timeout: 3000 });
        const jsContent = jsResponse.data;

        if (typeof jsContent !== 'string') continue;

        // Buscar endpoints ocultos (/api/admin, /internal, /dev)
        const endpointRegex = /["'](\/(?:api\/)?(?:admin|internal|debug|dev|staff|v2|private)[^"']*)["']/g;
        for (const match of jsContent.matchAll(endpointRegex)) {
          foundEndpoints.add(match[1]);
        }

        // Buscar Feature Flags
        const flagRegex = /\b(isAdmin|isInternal|isBeta|isStaff|debugMode|bypassAuth)\b/g;
        for (const match of jsContent.matchAll(flagRegex)) {
          foundFlags.add(match[1]);
        }
      } catch (e) {
        // Timeout del script
      }
    }

    // 4. Reportar hallazgos
    if (foundEndpoints.size > 0) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'HIDDEN_ENDPOINTS_EXPOSURE',
        severity: 'MEDIUM',
        description: `Vulnerabilidad MEDIA (JS Recon). Se encontraron endpoints internos/ocultos hardcodeados en el código JavaScript del cliente: ${Array.from(foundEndpoints).join(', ')}. Esto expone la arquitectura interna.`,
        autoFixCode: null,
      });
    }

    if (foundFlags.size > 0) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'FEATURE_FLAGS_EXPOSURE',
        severity: 'LOW',
        description: `Vulnerabilidad BAJA (JS Recon). Se detectaron banderas de estado (Feature Flags) en el lado del cliente: ${Array.from(foundFlags).join(', ')}. Un atacante podría manipular estas variables en el navegador para escalar privilegios en la UI.`,
        autoFixCode: null,
      });
    }

  } catch (error: any) {
    console.error(`[Scan ${scanId}] JS Recon error:`, error?.message || String(error));
  }
}
