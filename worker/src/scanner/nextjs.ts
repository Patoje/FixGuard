import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runNextJsScan(scanId: number, targetUrl: string) {
  try {
    const response = await axios.get(targetUrl, { timeout: 5000, validateStatus: () => true });
    if (typeof response.data !== 'string') return;

    const html = response.data;
    const baseUrl = new URL(targetUrl).origin;

    // Detectar Build ID (ej: /_next/static/xyz123/_buildManifest.js)
    const buildIdMatch = html.match(/\/_next\/static\/([^/]+)\/_buildManifest\.js/);
    if (buildIdMatch) {
      const buildId = buildIdMatch[1];
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'NEXTJS_BUILD_ID_LEAK',
        severity: 'LOW',
        description: `Vulnerabilidad BAJA (Informativa). Se extrajo el Build ID de Next.js ('${buildId}'). Un atacante puede usar esto para iterar sobre la ruta oculta /_next/data/${buildId}/... y descargar archivos JSON con propiedades del servidor o datos serializados.`,
        autoFixCode: null,
      });

      // Intentar acceder a un json común de la página de inicio
      try {
        const dataUrl = `${baseUrl}/_next/data/${buildId}/index.json`;
        const dataResponse = await axios.get(dataUrl, { timeout: 3000 });
        if (dataResponse.status === 200) {
           await db.insert(vulnerabilities).values({
            scanId,
            type: 'NEXTJS_DATA_EXPOSURE',
            severity: 'MEDIUM',
            description: `Vulnerabilidad MEDIA. El escáner logró descargar el archivo JSON de datos serializados de Next.js en '${dataUrl}'. Revisa que las funciones getServerSideProps o getStaticProps no estén filtrando información confidencial a la UI.`,
            autoFixCode: null,
          });
        }
      } catch (e) {
        // Ignorar si no existe
      }
    }
  } catch (error: any) {
    console.error(`[Scan ${scanId}] Next.js scan error:`, error?.message || String(error));
  }
}
