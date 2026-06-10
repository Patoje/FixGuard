import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runNextJsScan(scanId: number, targetUrl: string) {
  try {
    const response = await axios.get(targetUrl, { timeout: 5000, validateStatus: () => true });
    if (typeof response.data !== 'string') return;

    const html = response.data;
    const baseUrl = new URL(targetUrl).origin;

    // 1. Detectar Build ID Clásico (Pages Router)
    const buildIdMatch = html.match(/\/_next\/static\/([^/]+)\/_buildManifest\.js/);
    if (buildIdMatch) {
      const buildId = buildIdMatch[1];
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'NEXTJS_BUILD_ID_LEAK',
        severity: 'LOW',
        description: `Vulnerabilidad BAJA (Informativa). Se extrajo el Build ID de Next.js ('${buildId}'). Un atacante puede iterar sobre la ruta oculta /_next/data/${buildId}/... y descargar archivos JSON con propiedades del servidor.`,
        autoFixCode: null,
      });
    }

    // 2. The Vercel Hack: Analizar React Server Components (RSC) Payload en Next.js App Router
    // Next.js 13/14 App Router inyecta la hidratación serializada en etiquetas <script>self.__next_f=...
    const rscMatches = html.matchAll(/self\.__next_f\.push\((.*?)\)/g);
    let foundRscLeak = false;

    for (const match of rscMatches) {
      const payload = match[1].toLowerCase();
      // Buscamos palabras clave peligrosas dentro de la data serializada que el servidor le manda al cliente
      if (
        payload.includes('password') || 
        payload.includes('secret') || 
        payload.includes('token') || 
        payload.includes('hash') || 
        payload.includes('private_key')
      ) {
         await db.insert(vulnerabilities).values({
          scanId,
          type: 'REACT_SERVER_COMPONENT_DATA_LEAK',
          severity: 'CRITICAL',
          description: `Vulnerabilidad CRÍTICA (Fuga de RSC). Next.js App Router está enviando datos altamente sensibles (passwords, secrets, tokens) al cliente dentro del Payload de React Server Components (self.__next_f). Esto ocurre cuando pasas un objeto entero de la base de datos a un Client Component sin filtrar los campos sensibles.`,
          autoFixCode: null,
        });
        foundRscLeak = true;
        break; // Solo reportar una vez por página para no saturar
      }
    }

    // 3. Fuga del X-Powered-By clásica
    if (response.headers['x-powered-by']?.toLowerCase().includes('next')) {
       await db.insert(vulnerabilities).values({
        scanId,
        type: 'X_POWERED_BY_LEAK',
        severity: 'LOW',
        description: `El servidor expone la tecnología base mediante 'X-Powered-By': Next.js.`,
        autoFixCode: null,
      });
    }

  } catch (error: any) {
    console.error(`[Scan ${scanId}] Next.js scan error:`, error?.message || String(error));
  }
}
