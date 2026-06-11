import { chromium } from 'playwright';
import type { Browser } from 'playwright';

/**
 * Realiza un Crawling Dinámico de la aplicación objetivo usando Playwright.
 * Permite renderizar SPAs (React, Next.js, Vite) y escuchar peticiones de red (Fetch/XHR)
 * en segundo plano para descubrir APIs ocultas.
 */
export async function runCrawler(scanId: number, targetUrl: string): Promise<{endpoints: string[], jsFiles: string[]}> {
  const discoveredUrls = new Set<string>();
  const discoveredJsFiles = new Set<string>();
  discoveredUrls.add(targetUrl);
  
  const baseUrl = new URL(targetUrl).origin;
  const maxPagesToVisit = 15; // Límite para no atascar el escaneo
  
  const queue = [targetUrl];
  const visited = new Set<string>();

  console.log(`[Scan ${scanId}] Crawler: Iniciando SPA Headless Crawler (Playwright) en ${targetUrl}...`);

  let browser: Browser | null = null;
  try {
    browser = await chromium.launch({ 
      headless: true, 
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu'] 
    });
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    
    // Intercepción global para extraer peticiones de red
    context.on('request', request => {
      const reqUrl = request.url();
      try {
        const u = new URL(reqUrl);
        if (u.origin === baseUrl) {
          // Si es un script
          if (u.pathname.endsWith('.js')) {
            discoveredJsFiles.add(u.toString());
          } else if (request.resourceType() === 'fetch' || request.resourceType() === 'xhr') {
            // Es un endpoint de API u otro recurso REST
            discoveredUrls.add(u.toString());
          }
        }
      } catch (e) {}
    });

    const page = await context.newPage();

    while (queue.length > 0 && visited.size < maxPagesToVisit) {
      const currentUrl = queue.shift()!;
      
      if (visited.has(currentUrl)) continue;
      visited.add(currentUrl);

      // console.log(`[Scan ${scanId}] Crawler: Visitando ${currentUrl}...`);

      try {
        // networkidle puede fallar si la página hace polling infinito. 
        // Primero vamos con domcontentloaded, y luego intentamos esperar a networkidle sin que explote.
        await page.goto(currentUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
        await page.waitForLoadState('networkidle', { timeout: 3000 }).catch(() => {});
        
        // Extraer todos los links hidratados dinámicamente
        const links = await page.$$eval('a', (anchors) => 
          anchors.map(a => a.href).filter(href => href && !href.startsWith('javascript:') && !href.startsWith('mailto:') && !href.startsWith('tel:'))
        );

        for (const href of links) {
          try {
            const resolvedUrl = new URL(href);
            if (resolvedUrl.origin === baseUrl) {
              resolvedUrl.hash = '';
              const finalUrl = resolvedUrl.toString();
              if (!discoveredUrls.has(finalUrl)) {
                discoveredUrls.add(finalUrl);
                queue.push(finalUrl);
              }
            }
          } catch(e) {}
        }

        // Extraer scripts inyectados dinámicamente
        const scripts = await page.$$eval('script', (tags) => tags.map(s => s.src).filter(src => src));
        for (const src of scripts) {
          try {
            const resolvedUrl = new URL(src, currentUrl);
            if (resolvedUrl.origin === baseUrl || src.startsWith('/')) {
               discoveredJsFiles.add(resolvedUrl.toString());
            }
          } catch(e) {}
        }

      } catch (error: any) {
        // Ignorar timeouts por protección anti-bot o carga pesada
        // console.log(`[Scan ${scanId}] Crawler: Timeout visitando ${currentUrl}`);
      }
    }

  } catch (err: any) {
    console.error(`[Scan ${scanId}] Crawler Error crítico de Playwright: ${err.message}`);
  } finally {
    if (browser) {
      await browser.close();
    }
  }

  const result = Array.from(discoveredUrls);
  const jsResult = Array.from(discoveredJsFiles);
  console.log(`[Scan ${scanId}] Crawler: Mapeo Headless completado. ${result.length} rutas/endpoints descubiertos, ${jsResult.length} archivos JS interceptados.`);
  return { endpoints: result, jsFiles: jsResult };
}
