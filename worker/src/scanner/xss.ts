import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

// Payload inofensivo pero fácil de detectar
const XSS_PAYLOAD = "<script>console.log('fixguard_xss_test_1337')</script>";

export async function runXssScan(scanId: number, targetUrl: string) {
  try {
    const urlObj = new URL(targetUrl);
    
    // Si la URL no tiene parámetros, inventamos uno para inyectar
    if (Array.from(urlObj.searchParams.keys()).length === 0) {
      urlObj.searchParams.set('search', 'test');
    }

    const originalParams = new URLSearchParams(urlObj.search);
    let foundVulnerability = false;

    // Fuzzing: Probar inyectar el script en cada parámetro
    for (const [key, value] of originalParams.entries()) {
      if (foundVulnerability) break;

      try {
        // Construir URL maliciosa (inyectamos nuestro payload en el parámetro)
        const attackUrl = new URL(urlObj.toString());
        attackUrl.searchParams.set(key, payloadEncode(XSS_PAYLOAD)); // Algunos servidores requieren url-encode, otros no. Enviamos el raw string primero.

        // Enviar ataque
        const response = await axios.get(attackUrl.toString(), {
          timeout: 5000,
          validateStatus: () => true 
        });

        const html = typeof response.data === 'string' ? response.data : '';

        // Análisis crucial: Si el payload aparece LITERALMENTE en el HTML devuelto, 
        // significa que el servidor no "escapó" los caracteres especiales (< y >).
        if (html.includes(XSS_PAYLOAD)) {
          await db.insert(vulnerabilities).values({
            scanId,
            type: 'REFLECTED_XSS_VULNERABILITY',
            severity: 'HIGH',
            description: `Vulnerabilidad ALTA de Cross-Site Scripting (XSS Reflejado) detectada en el parámetro '${key}'. El servidor devolvió código JavaScript sin sanitizar, lo que permitiría a un atacante ejecutar scripts maliciosos en el navegador de la víctima y robar cookies de sesión.`,
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
    console.error(`[Scan ${scanId}] XSS scan error:`, error);
  }
}

// Función auxiliar en caso de necesitar probar codificado
function payloadEncode(payload: string) {
    return payload; // En reflected XSS a veces el navegador lo encodifica automáticamente
}
