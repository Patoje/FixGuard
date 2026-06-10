import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

// Archivos críticos que nunca deberían estar expuestos
const SENSITIVE_PATHS = [
  { path: '/.env', type: 'EXPOSED_ENV_FILE', severity: 'CRITICAL', desc: 'Archivo .env expuesto. Contiene secretos críticos, contraseñas y claves de API.' },
  { path: '/.git/config', type: 'EXPOSED_GIT_CONFIG', severity: 'HIGH', desc: 'Directorio .git expuesto. Permite a los atacantes descargar todo el código fuente.' },
  { path: '/phpinfo.php', type: 'EXPOSED_PHPINFO', severity: 'HIGH', desc: 'Archivo phpinfo() expuesto. Revela toda la configuración interna del servidor.' },
  { path: '/backup.sql', type: 'EXPOSED_SQL_BACKUP', severity: 'CRITICAL', desc: 'Backup de base de datos expuesto. Permite robar todos los datos de los usuarios.' },
  { path: '/.DS_Store', type: 'EXPOSED_DS_STORE', severity: 'MEDIUM', desc: 'Archivo .DS_Store expuesto. Revela la estructura de directorios del servidor Mac.' }
];

export async function runDirectoryScan(scanId: number, targetUrl: string) {
  try {
    const baseUrl = new URL(targetUrl).origin;

    const checks = SENSITIVE_PATHS.map(async (item) => {
      try {
        const urlToTest = `${baseUrl}${item.path}`;
        const response = await axios.get(urlToTest, { 
          timeout: 3000,
          validateStatus: () => true // No lanzar error en 404
        });

        // Si responde 200 OK y no es una página HTML genérica de "Not Found"
        if (response.status === 200 && typeof response.data === 'string' && !response.data.toLowerCase().includes('<html')) {
          await db.insert(vulnerabilities).values({
            scanId,
            type: item.type,
            severity: item.severity as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            description: item.desc,
            autoFixCode: null,
          });
        }
      } catch (e) {
        // Ignorar timeouts o errores de red individuales
      }
    });

    await Promise.all(checks);
  } catch (error) {
    console.error(`[Scan ${scanId}] Directory scan error:`, error);
  }
}
