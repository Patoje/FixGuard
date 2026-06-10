import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities, scans } from '../db/schema';
import { eq } from 'drizzle-orm';

const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'permissions-policy',
  'referrer-policy'
];

export async function runHeaderScan(scanId: number, targetUrl: string) {
  try {
    console.log(`Iniciando escaneo ${scanId} para ${targetUrl}...`);
    


    // Desactivamos la validación de certificados SSL y permitimos redirecciones para el scanner
    const response = await axios.get(targetUrl, { 
      timeout: 10000,
      validateStatus: () => true 
    });
    
    const headers = response.headers;
    const missingHeaders: string[] = [];

    for (const header of SECURITY_HEADERS) {
      if (!headers[header]) {
        missingHeaders.push(header);
      }
    }

    if (missingHeaders.length > 0) {
      console.log(`[Scan ${scanId}] Cabeceras faltantes encontradas:`, missingHeaders);
      
      // Insertamos cada fallo en la DB
      for (const header of missingHeaders) {
        await db.insert(vulnerabilities).values({
          scanId,
          type: `MISSING_HEADER_${header.toUpperCase().replace(/-/g, '_')}`,
          severity: header === 'strict-transport-security' ? 'HIGH' : 'MEDIUM',
          description: `La cabecera de seguridad '${header}' no está configurada en la respuesta HTTP del servidor.`,
          autoFixCode: null, 
        });
      }
    }

    // Comprobar fugas de información
    if (headers['server']) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'SERVER_HEADER_LEAK',
        severity: 'LOW',
        description: `El servidor está exponiendo su versión exacta en la cabecera 'Server': ${headers['server']}. Esto facilita a los atacantes buscar vulnerabilidades conocidas.`,
        autoFixCode: null,
      });
    }

    if (headers['x-powered-by']) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'X_POWERED_BY_LEAK',
        severity: 'LOW',
        description: `El servidor expone la tecnología base mediante 'X-Powered-By': ${headers['x-powered-by']}.`,
        autoFixCode: null,
      });
    }

    // Comprobar cookies
    const setCookieHeader = headers['set-cookie'];
    if (setCookieHeader && Array.isArray(setCookieHeader)) {
      for (const cookie of setCookieHeader) {
        const cookieStr = cookie.toLowerCase();
        if (!cookieStr.includes('httponly')) {
          await db.insert(vulnerabilities).values({
            scanId,
            type: 'COOKIE_MISSING_HTTPONLY',
            severity: 'MEDIUM',
            description: `Se detectó una Cookie que no tiene la bandera 'HttpOnly'. Es vulnerable a robos mediante XSS.`,
            autoFixCode: null,
          });
        }
        if (!cookieStr.includes('secure')) {
          await db.insert(vulnerabilities).values({
            scanId,
            type: 'COOKIE_MISSING_SECURE',
            severity: 'MEDIUM',
            description: `Se detectó una Cookie que no tiene la bandera 'Secure'. Puede ser interceptada en conexiones no cifradas.`,
            autoFixCode: null,
          });
        }
      }
    }

    // Escaneo de cabeceras finalizado
    console.log(`[Scan ${scanId}] Escaneo de cabeceras completado.`);

  } catch (error: any) {
    console.error(`[Scan ${scanId}] Error en escaneo de cabeceras:`, error.message);
  }
}
