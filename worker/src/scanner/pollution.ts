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
        description: `Vulnerabilidad MEDIA de HTTP Parameter Pollution (HPP). El servidor generó un error 500 al recibir parámetros duplicados y cargas de asignación masiva (isAdmin=true). Esto indica que el backend no está validando correctamente las entradas de datos en la URL, lo que podría derivar en escalada de privilegios o Bypass de lógicas de negocio (BOLA).`,
        autoFixCode: null,
      });
    }
  } catch (error) {
    console.error(`[Scan ${scanId}] Parameter Pollution scan error:`, error);
  }
}
