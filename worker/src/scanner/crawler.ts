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

  console.log(`[Scan ${scanId}] Crawler: Iniciando mapeo SPA profundo en ${targetUrl}...`);

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
      const html = response.data;

      // Usamos cheerio para parsear el DOM clásico
      const $ = cheerio.load(html);

      $('a').each((_, element) => {
        const href = $(element).attr('href');
        if (!href) return;

        // Ignorar anclas internas o javascript:
        if (href.startsWith('#') || href.startsWith('javascript:')) return;
        // Ignorar mails y telefonos
        if (href.startsWith('mailto:') || href.startsWith('tel:')) return;

        try {
          const resolvedUrl = new URL(href, currentUrl);
          if (resolvedUrl.origin === baseUrl) {
            resolvedUrl.hash = '';
            const finalUrl = resolvedUrl.toString();
            if (!discoveredUrls.has(finalUrl)) {
              discoveredUrls.add(finalUrl);
              queue.push(finalUrl);
            }
          }
        } catch (e) {
          // URL inválida
        }
      });

      // 1. Next.js Pages Router: Extraer data URLs (/_next/data/...)
      const nextDataMatches = html.matchAll(/"(\/_next\/data\/[^"]+)"/g);
      for (const match of nextDataMatches) {
        const nextUrl = `${baseUrl}${match[1]}`;
        discoveredUrls.add(nextUrl);
      }

      // 2. Extracción Agresiva React/Next.js (App Router & Minified JS)
      // Buscamos cualquier cadena que parezca una ruta interna (empieza con / y tiene caracteres de ruta válidos)
      const rawPathMatches = html.matchAll(/(?<=['"`])(\/[a-zA-Z0-9\-_/]+)(?=['"`])/g);
      for (const match of rawPathMatches) {
        try {
          const path = match[1];
          // Excluir rutas de assets estáticos que no son páginas
          if (path.includes('_next/static') || path.includes('.js') || path.includes('.css') || path.includes('.woff') || path.includes('.png')) {
            continue;
          }

          const resolvedUrl = new URL(path, currentUrl).toString();
          if (!discoveredUrls.has(resolvedUrl)) {
            discoveredUrls.add(resolvedUrl);
            queue.push(resolvedUrl);
          }
        } catch(e) {}
      }

      // 3. Extracción desde JSON serializado (RSC Payload u otros)
      const jsonLikePaths = html.matchAll(/\\"(?:\/)([a-zA-Z0-9\-_/]+)\\"/g);
      for (const match of jsonLikePaths) {
         try {
          const path = `/${match[1]}`;
          if (path.includes('_next/static') || path.includes('.js')) continue;

          const resolvedUrl = new URL(path, currentUrl).toString();
          if (!discoveredUrls.has(resolvedUrl)) {
            discoveredUrls.add(resolvedUrl);
            queue.push(resolvedUrl);
          }
        } catch(e) {}
      }

    } catch (error: any) {
      console.log(`[Scan ${scanId}] Crawler: Timeout visitando ${currentUrl}`);
    }
  }

  const result = Array.from(discoveredUrls);
  console.log(`[Scan ${scanId}] Crawler: Mapeo profundo completado. ${result.length} rutas descubiertas.`);
  return result;
}
