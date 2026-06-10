import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

const TRAVERSAL_PAYLOADS = [
  '../../../../etc/passwd',
  '..\\..\\..\\..\\windows\\win.ini',
  '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
];

export async function runTraversalScan(scanId: number, targetUrl: string) {
  try {
    let foundVulnerability = false;

    for (const payload of TRAVERSAL_PAYLOADS) {
      if (foundVulnerability) break;

      // Intentamos inyectar el payload como si fuera un archivo solicitado
      const endpoint = targetUrl.endsWith('/') ? `${targetUrl}${payload}` : `${targetUrl}/${payload}`;
      
      try {
        const response = await axios.get(endpoint, {
          timeout: 4000,
          validateStatus: () => true
        });

        const data = typeof response.data === 'string' ? response.data : '';

        // Comprobamos si nos devolvió el archivo de contraseñas de linux o configuración de windows
        if (data.includes('root:x:0:0:') || data.includes('[extensions]')) {
          await db.insert(vulnerabilities).values({
            scanId,
            type: 'PATH_TRAVERSAL_LFI',
            severity: 'CRITICAL',
            description: `Vulnerabilidad CRÍTICA de Path Traversal (LFI). Se logró acceder a archivos internos del sistema operativo enviando el payload '${payload}'. Esto significa que un atacante puede leer cualquier archivo confidencial del servidor, incluyendo código fuente y configuraciones.`,
            autoFixCode: null,
          });
          foundVulnerability = true;
          break;
        }
      } catch (e) {
        // Ignorar timeouts
      }
    }
  } catch (error) {
    console.error(`[Scan ${scanId}] Path Traversal scan error:`, error);
  }
}
