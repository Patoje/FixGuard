import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

const SECRET_PATHS = [
  '/.env',
  '/.env.local',
  '/.env.production',
  '/.git/config'
];

export async function runSecretsScan(scanId: number, targetUrl: string) {
  try {
    const baseUrl = new URL(targetUrl).origin;
    let foundVulnerability = false;

    for (const path of SECRET_PATHS) {
      if (foundVulnerability) break;

      const endpoint = `${baseUrl}${path}`;
      try {
        const response = await axios.get(endpoint, {
          timeout: 4000,
          validateStatus: () => true
        });

        // Verificamos si devuelve texto y no es una página de error 404 de HTML
        if (response.status === 200 && typeof response.data === 'string') {
           const data = response.data.toLowerCase();
           if (data.includes('database_url') || data.includes('api_key') || data.includes('secret') || data.includes('core]')) {
             await db.insert(vulnerabilities).values({
               scanId,
               type: 'SECRET_FILE_EXPOSURE',
               severity: 'CRITICAL',
               description: `Vulnerabilidad CRÍTICA. Se encontró un archivo de configuración expuesto en '${endpoint}'. Esto probablemente filtra credenciales de base de datos o claves de API que permiten tomar control total del servidor.`,
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
    console.error(`[Scan ${scanId}] Secrets scan error:`, error);
  }
}
