import { chromium } from 'playwright';
import type { Browser, Page } from 'playwright';
import fs from 'fs';
import path from 'path';
import { SessionManager } from './SessionManager';
import { scoreUrl, getHighValueRoutesForStack } from './urlPrioritizer';

/**
 * Realiza un Crawling Dinámico de la aplicación objetivo usando Playwright.
 * - Inyecta estado de autenticación (si se provee)
 * - Navega recursivamente
 * - Interactúa con componentes (clicks, tabs)
 * - Hace scroll infinito para Lazy Loading
 * - Llena formularios "fantasma"
 * - Extrae APIs de Fetch/XHR, GraphQL, WebSockets y Service Workers
 */
export async function runCrawler(scanId: number, targetUrl: string, detectedStack?: string): Promise<{
  endpoints: string[], 
  jsFiles: string[],
  runtimeIntelligence: {
    totalClicks: number;
    totalFormsFilled: number;
    totalScrolls: number;
    requestsIntercepted: number;
    endpointsDiscovered: number;
  }
}> {
  const discoveredUrls = new Set<string>();
  const discoveredJsFiles = new Set<string>();
  discoveredUrls.add(targetUrl);
  
  const baseUrl = new URL(targetUrl).origin;
  const maxPagesToVisit = 50; // Límite extendido para permitir exploración profunda
  
  let queue: {url: string, score: number}[] = [{url: targetUrl, score: scoreUrl(targetUrl, detectedStack)}];
  if (detectedStack) {
    const highValueRoutes = getHighValueRoutesForStack(targetUrl, detectedStack);
    for (const route of highValueRoutes) {
      queue.push({ url: route, score: 90 });
    }
  }
  const visited = new Set<string>();

  // Metrics
  let totalClicks = 0;
  let totalFormsFilled = 0;
  let totalScrolls = 0;
  let requestsIntercepted = 0;

  console.log(`[Scan ${scanId}] Crawler: Iniciando User Journey Explorer en ${targetUrl}...`);

  let browser: Browser | null = null;
  try {
    browser = await chromium.launch({ 
      headless: true, 
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu'] 
    });
    
    const context = await browser.newContext({ ignoreHTTPSErrors: true });

    // 1. Inyección de Estado de Autenticación (Auth State) dinámico desde DB
    try {
      const activeSession = await SessionManager.getActiveSession(targetUrl);
      if (activeSession) {
        if (activeSession.authType === 'cookie' && activeSession.cookieHeader) {
          // Asumimos formato simple CookieName=CookieValue
          const parts = activeSession.cookieHeader.split(';');
          for (const part of parts) {
             const [name, ...valParts] = part.split('=');
             if (name && valParts.length > 0) {
                 await context.addCookies([{ 
                    name: name.trim(), 
                    value: valParts.join('=').trim(), 
                    domain: new URL(targetUrl).hostname, 
                    path: '/' 
                 }]);
             }
          }
          console.log(`[Scan ${scanId}] Crawler: Sesión COOKIE inyectada dinámicamente desde DB.`);
        } else if (activeSession.authType === 'jwt' && activeSession.jwtToken) {
          await context.setExtraHTTPHeaders({
            'Authorization': `Bearer ${activeSession.jwtToken}`
          });
          console.log(`[Scan ${scanId}] Crawler: Sesión JWT inyectada dinámicamente desde DB.`);
        }
      }
    } catch(e) {
      console.log(`[Scan ${scanId}] Crawler: Fallo al intentar inyectar sesión de la DB. Ignorando.`);
    }
    
    // Intercepción global (Network Intelligence)
    context.on('request', request => {
      requestsIntercepted++;
      const reqUrl = request.url();
      try {
        const u = new URL(reqUrl);
        if (u.origin === baseUrl) {
          if (u.pathname.endsWith('.js')) {
            discoveredJsFiles.add(u.toString());
          } else if (['fetch', 'xhr', 'websocket'].includes(request.resourceType())) {
            // Guardamos todos los endpoints de datos interceptados en vivo
            discoveredUrls.add(u.toString());
          }
        }
      } catch (e) {}
    });

    const page = await context.newPage();

    while (queue.length > 0 && visited.size < maxPagesToVisit) {
      // Reordenar la cola por score descendente (Priorización Semántica)
      queue.sort((a, b) => b.score - a.score);
      
      const currentItem = queue.shift()!;
      const currentUrl = currentItem.url;
      
      if (visited.has(currentUrl)) continue;
      visited.add(currentUrl);

      console.log(`[Scan ${scanId}] Crawler: Explorando a fondo ${currentUrl} (Score Semántico: ${currentItem.score})...`);

      try {
        await page.goto(currentUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
        await page.waitForLoadState('networkidle', { timeout: 3000 }).catch(() => {});
        
        // 2. Service Worker & Cache Storage Analysis
        try {
          const cachedUrls = await page.evaluate(async () => {
             const urls: string[] = [];
             try {
                const keys = await caches.keys();
                for (const key of keys) {
                   const cache = await caches.open(key);
                   const reqs = await cache.keys();
                   reqs.forEach(r => urls.push(r.url));
                }
             } catch(e) {}
             return urls;
          });
          cachedUrls.forEach(url => {
            if (url.startsWith(baseUrl)) discoveredUrls.add(url);
          });
        } catch(e) {}

        // 3. Scroll Infinito Automático (Lazy Loading Discovery)
        const scrollsDone = await page.evaluate(async () => {
            return await new Promise<number>((resolve) => {
                let totalHeight = 0;
                const distance = 500;
                const maxScrolls = 4; // Bajar 4 veces
                let scrolls = 0;
                const timer = setInterval(() => {
                    const scrollHeight = document.body.scrollHeight;
                    window.scrollBy(0, distance);
                    totalHeight += distance;
                    scrolls++;
                    if(totalHeight >= scrollHeight - window.innerHeight || scrolls >= maxScrolls){
                        clearInterval(timer);
                        resolve(scrolls);
                    }
                }, 800); // 800ms entre scrolls para dar tiempo a peticiones
            });
        });
        totalScrolls += (scrollsDone as number || 0);
        await page.waitForTimeout(1000); // Dar un respiro a la red

        // 4. Component Discovery & Auto-Clickeador
        // Encontrar botones, tabs, y dropdowns que puedan cargar cosas nuevas
        const interactables = await page.$$('button, [role="button"], [role="tab"], .dropdown-toggle, [aria-expanded]');
        // Limitamos los clics a 25 por página para no volvernos locos pero explorar más
        const maxClicks = Math.min(interactables.length, 25);
        if (maxClicks > 0) {
          console.log(`[Scan ${scanId}] Crawler: Interactuando con ${maxClicks} componentes UI...`);
        }
        for (let i = 0; i < maxClicks; i++) {
           try {
              const box = await interactables[i].boundingBox();
              if (box) {
                 await interactables[i].click({ timeout: 1000, delay: 50 }).catch(()=>{});
                 totalClicks++;
                 // Esperamos medio segundo tras cada clic para interceptar fetches
                 await page.waitForTimeout(500); 
              }
           } catch(e) {}
        }

        // 5. Llenado de Formularios Fantasma (Ghost Form Filling)
        const forms = await page.$$('form');
        if (forms.length > 0) {
           console.log(`[Scan ${scanId}] Crawler: Inyectando datos en ${forms.length} formulario(s)...`);
           for (const form of forms) {
              try {
                // Llenar inputs genéricos
                const textInputs = await form.$$('input[type="text"], input[type="email"], input:not([type])');
                for (const input of textInputs) {
                   await input.fill('test@fixguard.local').catch(()=>{});
                }
                const passInputs = await form.$$('input[type="password"]');
                for (const input of passInputs) {
                   await input.fill('FixGuardPwd123!').catch(()=>{});
                }
                
                // Click en Submit (esperamos que no navegue de inmediato, sino que intercepte XHR/Fetch)
                const submitBtn = await form.$('button[type="submit"], input[type="submit"]');
                if (submitBtn) {
                   // Clickeamos el submit sin esperar navegación para atrapar el POST en la red
                   submitBtn.click().catch(()=>{});
                   totalFormsFilled++;
                   await page.waitForTimeout(1000);
                }
              } catch(e) {}
           }
        }

        // 6. Extracción de Links para Navegación Dinámica
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
                queue.push({url: finalUrl, score: scoreUrl(finalUrl, detectedStack)});
              }
            }
          } catch(e) {}
        }

        // Extraer scripts JS
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
        // console.log(`[Scan ${scanId}] Crawler: Timeout explorando ${currentUrl}`);
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
  console.log(`[Scan ${scanId}] Crawler: Exploración de Viaje completada. ${result.length} rutas/endpoints descubiertos, ${jsResult.length} archivos JS interceptados. (${totalClicks} clics, ${totalFormsFilled} forms, ${requestsIntercepted} reqs)`);
  
  return { 
    endpoints: result, 
    jsFiles: jsResult,
    runtimeIntelligence: {
      totalClicks,
      totalFormsFilled,
      totalScrolls,
      requestsIntercepted,
      endpointsDiscovered: result.length
    }
  };
}
