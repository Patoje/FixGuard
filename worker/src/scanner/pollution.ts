import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runPollutionScan(scanId: number, targetUrl: string) {
  try {
    const url = new URL(targetUrl);
    
    // Inyectamos parámetros repetidos y de asignación masiva típicos de BOLA
    url.searchParams.append('id', '1');
    url.searchParams.append('id', '2');
    url.searchParams.append('isAdmin', 'true');
    url.searchParams.append('role', 'admin');

    const response = await axios.get(url.toString(), {
      timeout: 4000,
      validateStatus: () => true
    });

    // Si la contaminación causa una caída del servidor no controlada (500)
    if (response.status >= 500) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'HTTP_PARAMETER_POLLUTION',
        severity: 'MEDIUM',
        description: `Vulnerabilidad MEDIA (HTTP Parameter Pollution / Tampering). El servidor aceptó y procesó parámetros contaminados (?id=1&id=2 o ?isAdmin=true). Esto indica que no hay validación estricta de parámetros o que un arreglo fue interpretado como string. Puede llevar a desvío de lógica de negocio o escalada de privilegios menores.`,
        autoFixCode: null,
      });
    }
  } catch (error: any) {
    console.error(`[Scan ${scanId}] Parameter Pollution scan error:`, error?.message || String(error));
  }
}
