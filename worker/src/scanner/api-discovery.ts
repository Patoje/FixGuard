import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

const API_PATHS = [
  '/swagger.json',
  '/openapi.json',
  '/api-docs',
  '/v1/api-docs',
  '/docs',
  '/swagger-ui.html',
  '/api/swagger'
];

export async function runApiDiscoveryScan(scanId: number, targetUrl: string) {
  try {
    const baseUrl = new URL(targetUrl).origin;
    let foundVulnerability = false;

    for (const path of API_PATHS) {
      if (foundVulnerability) break;

      const endpoint = `${baseUrl}${path}`;
      try {
        const response = await axios.head(endpoint, {
          timeout: 3000,
          validateStatus: () => true
        });

        // Verificamos si devuelve 200 OK y que sea contenido JSON o HTML
        if (response.status === 200) {
           const contentType = response.headers['content-type'] || '';
           if (contentType.includes('json') || contentType.includes('html')) {
             await db.insert(vulnerabilities).values({
               scanId,
               type: 'API_DOCUMENTATION_EXPOSURE',
               severity: 'MEDIUM',
               description: `Vulnerabilidad MEDIA por exposición de documentación de API. Se encontró una interfaz o archivo de especificación en '${endpoint}'. Si bien esto es útil para desarrolladores, en producción facilita enormemente a un atacante entender todos los endpoints y parámetros ocultos de tu aplicación para atacarlos.`,
               autoFixCode: null,
             });
             foundVulnerability = true;
             break;
           }
        }
      } catch (e) {
        // Ignorar timeouts
      }
    }
  } catch (error) {
    console.error(`[Scan ${scanId}] API Discovery scan error:`, error);
  }
}
