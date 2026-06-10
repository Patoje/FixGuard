import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

// Payloads clásicos para provocar errores de sintaxis en bases de datos vulnerables
const SQLI_PAYLOADS = [
  "'",
  "\"",
  "\\",
  "' OR 1=1--",
  "\" OR 1=1--"
];

// Firmas comunes de error de base de datos en el HTML devuelto
const SQL_ERROR_SIGNATURES = [
  "you have an error in your sql syntax",
  "warning: mysql_query()",
  "unclosed quotation mark after the character string",
  "quoted string not properly terminated",
  "pg_query(): query failed",
  "ora-01756",
  "sqlite3::query():"
];

export async function runSqliScan(scanId: number, targetUrl: string) {
  try {
    const urlObj = new URL(targetUrl);
    
    // Si la URL no tiene parámetros, le inventamos uno común para probar
    if (Array.from(urlObj.searchParams.keys()).length === 0) {
      urlObj.searchParams.set('id', '1');
    }

    const originalParams = new URLSearchParams(urlObj.search);
    let foundVulnerability = false;

    // Fuzzing: Probar cada parámetro con cada payload
    for (const [key, value] of originalParams.entries()) {
      if (foundVulnerability) break;

      for (const payload of SQLI_PAYLOADS) {
        try {
          // Construir URL maliciosa
          const attackUrl = new URL(urlObj.toString());
          attackUrl.searchParams.set(key, value + payload);

          // Enviar ataque
          const response = await axios.get(attackUrl.toString(), {
            timeout: 5000,
            validateStatus: () => true // Aceptar cualquier código HTTP (a menudo devuelven 500 en SQLi)
          });

          const html = typeof response.data === 'string' ? response.data.toLowerCase() : '';

          // Analizar si el servidor "vomitó" un error de SQL
          for (const signature of SQL_ERROR_SIGNATURES) {
            if (html.includes(signature)) {
              await db.insert(vulnerabilities).values({
                scanId,
                type: 'SQL_INJECTION_VULNERABILITY',
                severity: 'CRITICAL',
                description: `Vulnerabilidad CRÍTICA de Inyección SQL detectada en el parámetro '${key}'. El payload '${payload}' provocó un error visible en la base de datos (${signature}). Esto podría permitir a un atacante leer, modificar o eliminar todos los datos de la aplicación.`,
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
    }
  } catch (error) {
    console.error(`[Scan ${scanId}] SQLi scan error:`, error);
  }
}
