import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runBolaScan(scanId: number, targetUrl: string) {
  try {
    // Buscar si hay algún número en la URL que parezca un ID (ej: /users/123 o ?id=123)
    const urlObj = new URL(targetUrl);
    const pathMatch = urlObj.pathname.match(/\/(\d+)(\/|$)/);
    const queryMatch = urlObj.search.match(/id=(\d+)/);

    let testUrl = '';
    let originalId = '';
    let newId = '';

    if (pathMatch) {
      originalId = pathMatch[1];
      newId = (parseInt(originalId) + 1).toString();
      testUrl = targetUrl.replace(`/${originalId}`, `/${newId}`);
    } else if (queryMatch) {
      originalId = queryMatch[1];
      newId = (parseInt(originalId) + 1).toString();
      testUrl = targetUrl.replace(`id=${originalId}`, `id=${newId}`);
    } else {
      return; // No hay IDs obvios para probar
    }

    // Probar el nuevo ID
    const response = await axios.get(testUrl, {
      timeout: 5000,
      validateStatus: () => true
    });

    // Si el servidor responde 200 OK a un recurso que no deberíamos tener acceso (teóricamente)
    if (response.status === 200) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
        severity: 'HIGH',
        description: `Vulnerabilidad ALTA (BOLA / IDOR). El escáner detectó un ID numérico en la ruta (${originalId}) y logró acceder exitosamente a otro recurso simplemente incrementando el valor a (${newId}) a través de la URL: ${testUrl}. Esto sugiere que no hay validación de propiedad (Authorization) a nivel de objeto.`,
        autoFixCode: null,
      });
    }

  } catch (error: any) {
    console.error(`[Scan ${scanId}] BOLA scan error:`, error?.message || String(error));
  }
}
