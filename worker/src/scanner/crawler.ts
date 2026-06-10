import axios from 'axios';
import * as cheerio from 'cheerio';

/**
 * Realiza un Crawling Inteligente de la aplicación objetivo.
 * Extrae todas las rutas accesibles (mismo dominio) para que los motores ataquen la superficie completa.
 */
export async function runCrawler(scanId: number, targetUrl: string): Promise<string[]> {
  const discoveredUrls = new Set<string>();
  discoveredUrls.add(targetUrl);
  
  const baseUrl = new URL(targetUrl).origin;
  const maxPagesToVisit = 15; // Límite para no atascar el escaneo
  
  const queue = [targetUrl];
  const visited = new Set<string>();

  console.log(`[Scan ${scanId}] Crawler: Iniciando mapeo SPA en ${targetUrl}...`);

  while (queue.length > 0 && visited.size < maxPagesToVisit) {
    const currentUrl = queue.shift()!;
    
    if (visited.has(currentUrl)) continue;
    visited.add(currentUrl);

    try {
      const response = await axios.get(currentUrl, {
        timeout: 5000,
        validateStatus: () => true, // Aceptar 404s también (pueden revelar info)
      });

      if (typeof response.data !== 'string') continue;

      // Usamos cheerio para parsear el DOM (mucho más rápido y preciso que regex)
      const $ = cheerio.load(response.data);

      $('a').each((_, element) => {
        const href = $(element).attr('href');
        if (!href) return;

        // Ignorar anclas internas o javascript:
        if (href.startsWith('#') || href.startsWith('javascript:')) return;
        // Ignorar mails y telefonos
        if (href.startsWith('mailto:') || href.startsWith('tel:')) return;

        try {
          // Resolver la URL (maneja relativas como '/dashboard' y absolutas)
          const resolvedUrl = new URL(href, currentUrl);

          // Solo guardar URLs del MISMO dominio (no queremos hackear google.com por accidente)
          if (resolvedUrl.origin === baseUrl) {
            // Normalizar eliminando hashes al final
            resolvedUrl.hash = '';
            const finalUrl = resolvedUrl.toString();
            
            if (!discoveredUrls.has(finalUrl)) {
              discoveredUrls.add(finalUrl);
              queue.push(finalUrl);
            }
          }
        } catch (e) {
          // URL inválida, ignorar
        }
      });

      // Extraer Next.js data URLs (/_next/data/...) del código fuente
      const nextDataMatches = response.data.matchAll(/"(\/_next\/data\/[^"]+)"/g);
      for (const match of nextDataMatches) {
        const nextUrl = `${baseUrl}${match[1]}`;
        discoveredUrls.add(nextUrl);
      }

      // EXTRA: Extracción agresiva por Regex para SPAs (React/Next.js) que inyectan rutas en el JS/JSON
      const rawPathMatches = response.data.matchAll(/href=["'](\/[a-zA-Z0-9\-_/]+)["']/g);
      for (const match of rawPathMatches) {
        try {
          const resolvedUrl = new URL(match[1], currentUrl).toString();
          if (!discoveredUrls.has(resolvedUrl)) {
            discoveredUrls.add(resolvedUrl);
            queue.push(resolvedUrl);
          }
        } catch(e) {}
      }

    } catch (error: any) {
      // Ignorar timeouts de páginas individuales
      console.log(`[Scan ${scanId}] Crawler: Timeout visitando ${currentUrl}`);
    }
  }

  const result = Array.from(discoveredUrls);
  console.log(`[Scan ${scanId}] Crawler: Mapeo completado. ${result.length} rutas descubiertas.`);
  return result;
}
