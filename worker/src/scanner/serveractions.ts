import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runServerActionsScan(scanId: number, targetUrl: string) {
  try {
    const htmlResponse = await axios.get(targetUrl, { timeout: 5000, validateStatus: () => true });
    if (typeof htmlResponse.data !== 'string') return;

    // Buscar "Action IDs" que genera Next.js internamente, usualmente son hashes alfanuméricos en los scripts
    // Ejemplo de payload: action={$$id:"7f5a8b9c"...}
    const actionIdMatches = htmlResponse.data.matchAll(/\$\$id\s*:\s*["']([a-f0-9]+)["']/g);
    const discoveredActions = new Set<string>();

    for (const match of actionIdMatches) {
      discoveredActions.add(match[1]);
    }

    if (discoveredActions.size > 0) {
       await db.insert(vulnerabilities).values({
        scanId,
        type: 'SERVER_ACTIONS_EXPOSED',
        severity: 'LOW',
        description: `Vulnerabilidad BAJA (Informativa). Se detectaron ${discoveredActions.size} Next.js Server Actions expuestos en el código fuente del cliente. Un atacante podría interceptar estos IDs (${Array.from(discoveredActions).slice(0, 3).join(', ')}...) e intentar forzar peticiones POST directas saltándose la interfaz de usuario.`,
        autoFixCode: null,
      });

      // Fuzzing Activo de los Server Actions descubiertos
      for (const actionId of discoveredActions) {
        try {
           const postResponse = await axios.post(targetUrl, [null], { // Array vacío simulando payload serializado
             headers: {
               'Next-Action': actionId,
               'Content-Type': 'text/plain;charset=UTF-8',
               'Accept': 'text/x-component'
             },
             timeout: 3000,
             validateStatus: () => true
           });

           // Si el servidor responde 200 y nos devuelve RSC (React Server Component), significa que la acción
           // se ejecutó exitosamente SIN autenticación o validación de CSRF.
           if (postResponse.status === 200 && typeof postResponse.data === 'string' && postResponse.data.includes('__next_f')) {
              await db.insert(vulnerabilities).values({
                scanId,
                type: 'SERVER_ACTION_BOLA',
                severity: 'HIGH',
                description: `Vulnerabilidad ALTA. El escáner logró ejecutar exitosamente el Server Action oculto '${actionId}' enviando un payload vacío directamente por POST. Esto indica que la función no tiene validación de sesión (BOLA/IDOR) o falta protección CSRF en el endpoint de mutación.`,
                autoFixCode: null,
              });
              break; // Con reportar uno es suficiente para alertar del patrón
           }
        } catch (e) {
          // Ignorar si falla la petición falsa
        }
      }
    }

  } catch (error: any) {
    console.error(`[Scan ${scanId}] Server Actions scan error:`, error?.message || String(error));
  }
}
