import { chromium } from 'playwright';
import type { TechStackItem } from '../TechStackItem';

export class PlaywrightRuntimeAnalyzer {
  static async analyze(url: string): Promise<TechStackItem[]> {
    const findings: TechStackItem[] = [];
    const add = (name: string, category: TechStackItem['category'], confidence: number, evidence: string, role: string, version?: string) => {
      findings.push({ name, category, confidence, evidence: [evidence], role, version });
    };

    let browser;
    try {
      browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] });
      const context = await browser.newContext({ ignoreHTTPSErrors: true });
      const page = await context.newPage();

      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });
      // Esperamos un momento corto para que se inyecten las variables globales
      await page.waitForTimeout(1000);

      const runtimeData = await page.evaluate(() => {
        const data: any = {};
        const win = window as any;

        // Next.js
        if (win.__NEXT_DATA__) {
          data.nextjs = {
            hasData: true,
            buildId: win.__NEXT_DATA__.buildId,
            isAppRouter: !!win.__NEXT_DATA__.appGip
          };
        }
        
        // React
        if (win.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
          data.react = true;
          try {
            const renderers = win.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers;
            if (renderers && renderers.size > 0) {
              const firstRenderer = Array.from(renderers.values())[0] as any;
              if (firstRenderer && firstRenderer.version) {
                data.reactVersion = firstRenderer.version;
              }
            }
          } catch(e) {}
        }

        // Vue / Nuxt
        if (win.__NUXT__) data.nuxt = true;
        if (win.__VUE__) data.vue = true;

        // External SDKs
        if (win.__clerk) data.clerk = win.__clerk.version || true;
        
        return data;
      });

      if (runtimeData.nextjs) {
        add('Next.js', 'Frontend Framework', 100, `__NEXT_DATA__ found. Build: ${runtimeData.nextjs.buildId}`, 'SSR Framework', runtimeData.nextjs.isAppRouter ? 'App Router' : 'Pages Router');
      }
      if (runtimeData.react) {
        add('React', 'Frontend Framework', 100, '__REACT_DEVTOOLS_GLOBAL_HOOK__ found', 'UI Library', runtimeData.reactVersion);
      }
      if (runtimeData.nuxt) {
        add('Nuxt.js', 'Frontend Framework', 100, '__NUXT__ object found', 'Vue SSR');
      }
      if (runtimeData.vue) {
        add('Vue.js', 'Frontend Framework', 100, '__VUE__ object found', 'UI Library');
      }
      if (runtimeData.clerk) {
        add('Clerk', 'Authentication', 100, '__clerk object found', 'Gestión de identidad', typeof runtimeData.clerk === 'string' ? runtimeData.clerk : undefined);
      }

    } catch (e) {
      console.error('PlaywrightRuntimeAnalyzer error:', e);
    } finally {
      if (browser) await browser.close();
    }

    return findings;
  }
}
