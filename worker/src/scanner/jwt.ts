import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

// Un token JWT válido estándar convertido a alg:none
const ALG_NONE_TOKEN = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.';

export async function runJwtScan(scanId: number, targetUrl: string) {
  try {
    const response = await axios.get(targetUrl, {
      headers: {
        'Authorization': `Bearer ${ALG_NONE_TOKEN}`
      },
      timeout: 4000,
      validateStatus: () => true
    });

    // Si el servidor crashea (500) en lugar de darnos un 401 Unauthorized, es vulnerable
    if (response.status === 500) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'JWT_ALG_NONE_VULNERABILITY',
        severity: 'HIGH',
        description: `Vulnerabilidad ALTA de Autenticación. El servidor respondió con un Error 500 al recibir un token JWT con el algoritmo 'none' manipulado. Esto sugiere que el servidor está intentando procesar tokens inválidos sin verificar su firma criptográfica correctamente, lo que podría permitir falsificación de sesiones.`,
        autoFixCode: null,
      });
    }
  } catch (error) {
    console.error(`[Scan ${scanId}] JWT scan error:`, error);
  }
}
