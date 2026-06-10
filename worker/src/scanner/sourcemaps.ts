import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runSourceMapScan(scanId: number, targetUrl: string) {
  try {
    const baseUrl = new URL(targetUrl).origin;
    
    // 1. Obtener el HTML principal
    const response = await axios.get(targetUrl, {
      timeout: 5000,
      validateStatus: () => true
    });

    const html = typeof response.data === 'string' ? response.data : '';
    
    // 2. Extraer rutas de archivos JS (ej: src="/_next/static/chunks/main.js")
    const jsFiles = [...html.matchAll(/src="([^"]+\.js)"/g)].map(m => m[1]);
    
    // Si no hay scripts, probamos con rutas comunes de frameworks modernos
    if (jsFiles.length === 0) {
      jsFiles.push('/_next/static/chunks/main.js');
      jsFiles.push('/static/js/bundle.js');
      jsFiles.push('/assets/index.js');
    }

    let foundMap = false;

    // 3. Comprobar si existe el archivo .map para cada script
    for (let jsPath of jsFiles) {
      if (foundMap) break;

      // Asegurar que la ruta sea absoluta respecto al dominio
      if (!jsPath.startsWith('http')) {
        jsPath = jsPath.startsWith('/') ? `${baseUrl}${jsPath}` : `${baseUrl}/${jsPath}`;
      }

      const mapUrl = `${jsPath}.map`;

      try {
        const mapResponse = await axios.head(mapUrl, {
          timeout: 3000,
          validateStatus: () => true
        });

        if (mapResponse.status === 200) {
          await db.insert(vulnerabilities).values({
            scanId,
            type: 'SOURCE_MAP_EXPOSURE',
            severity: 'MEDIUM',
            description: `Vulnerabilidad MEDIA por Source Maps expuestos en '${mapUrl}'. Un atacante puede descargar este archivo y reconstruir todo el código fuente original (TypeScript/React) de tu frontend, exponiendo lógica de negocio interna, secretos harcodeados o comentarios de los desarrolladores.`,
            autoFixCode: null,
          });
          foundMap = true;
          break;
        }
      } catch (e) {
        // Ignorar
      }
    }
  } catch (error: any) {
    console.error(`[Scan ${scanId}] Source Maps scan error:`, error?.message || String(error));
  }
}
