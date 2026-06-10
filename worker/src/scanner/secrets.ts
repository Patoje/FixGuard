import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

const SECRET_PATHS = [
  '/.env',
  '/.env.local',
  '/.env.production',
  '/.git/config'
];

// Regex agresivas para cazar secretos en el JavaScript minificado
const JS_SECRET_PATTERNS = [
  { name: 'Stripe Live Key', regex: /sk_live_[0-9a-zA-Z]{24}/ },
  { name: 'Stripe Publishable Key', regex: /pk_live_[0-9a-zA-Z]{24}/ },
  { name: 'Supabase Anon Key', regex: /ey[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/ }, // Pattern general de JWT
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/ },
  { name: 'Generic Password/Secret', regex: /(?:password|secret|token)["']?\s*:\s*["']([^"']+)["']/i }
];

export async function runSecretsScan(scanId: number, targetUrl: string) {
  try {
    const baseUrl = new URL(targetUrl).origin;
    let foundVulnerability = false;

    // 1. Búsqueda clásica de archivos de configuración (.env, .git)
    for (const path of SECRET_PATHS) {
      if (foundVulnerability) break;

      const endpoint = `${baseUrl}${path}`;
      try {
        const response = await axios.get(endpoint, {
          timeout: 4000,
          validateStatus: () => true
        });

        // Verificamos si devuelve texto y no es una página de error 404 de HTML
        if (response.status === 200 && typeof response.data === 'string' && !response.data.includes('<html')) {
           const data = response.data.toLowerCase();
           if (data.includes('database_url') || data.includes('api_key') || data.includes('secret') || data.includes('core]')) {
             await db.insert(vulnerabilities).values({
               scanId,
               type: 'SECRET_FILE_EXPOSURE',
               severity: 'CRITICAL',
               description: `Vulnerabilidad CRÍTICA. Se encontró un archivo de configuración expuesto en '${endpoint}'. Esto probablemente filtra credenciales de base de datos o claves de API que permiten tomar control total del servidor.`,
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

    // 2. Búsqueda moderna: Extracción de Secretos desde los JS Chunks de React/Next.js
    try {
      const htmlResponse = await axios.get(targetUrl, { timeout: 5000, validateStatus: () => true });
      if (typeof htmlResponse.data !== 'string') return;

      // Buscar todos los archivos JS inyectados en la página
      const scriptMatches = htmlResponse.data.matchAll(/<script[^>]*src=["']([^"']+\.js)["'][^>]*>/g);
      
      for (const match of scriptMatches) {
        const scriptUrl = match[1].startsWith('http') ? match[1] : `${baseUrl}${match[1].startsWith('/') ? '' : '/'}${match[1]}`;
        
        try {
          const jsResponse = await axios.get(scriptUrl, { timeout: 3000 });
          if (typeof jsResponse.data !== 'string') continue;

          for (const pattern of JS_SECRET_PATTERNS) {
            const foundSecret = jsResponse.data.match(pattern.regex);
            
            // Excluimos falsos positivos comunes de los JWT (rutas muy largas que parecen base64)
            if (foundSecret && !(pattern.name === 'Supabase Anon Key' && foundSecret[0].length < 40)) {
               await db.insert(vulnerabilities).values({
                scanId,
                type: 'HARDCODED_JS_SECRET',
                severity: 'HIGH',
                description: `Vulnerabilidad ALTA. Se detectó una posible clave secreta dura (${pattern.name}) quemada en el código fuente de frontend: '${scriptUrl}'. Los atacantes pueden extraer esta clave leyendo el código fuente minificado y usarla para interactuar con APIs externas (Stripe, AWS, Supabase) en tu nombre.`,
                autoFixCode: null,
              });
              break; // No spamear 50 veces por archivo
            }
          }
        } catch (e) {
           // Si falla la descarga de un script, pasamos al siguiente
        }
      }
    } catch (e) {
      // Ignorar
    }

  } catch (error: any) {
    console.error(`[Scan ${scanId}] Secrets scan error:`, error?.message || String(error));
  }
}
