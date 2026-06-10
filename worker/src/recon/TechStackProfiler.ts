import axios from 'axios';
import * as cheerio from 'cheerio';

export interface TechStackItem {
  name: string;
  category: 'Frontend Framework' | 'Backend Framework' | 'Database' | 'Authentication' | 'Hosting / Infrastructure' | 'External Services';
  confidence: number;
  evidence: string[];
  role: string;
}

export async function runTechStackProfiler(targetUrl: string): Promise<TechStackItem[]> {
  const stack: TechStackItem[] = [];
  try {
    const response = await axios.get(targetUrl, { timeout: 10000, validateStatus: () => true });
    const html = typeof response.data === 'string' ? response.data : '';
    const headers = response.headers;
    const $ = cheerio.load(html);

    // Helper function to add to stack
    const addStack = (name: string, category: TechStackItem['category'], confidence: number, evidence: string, role: string) => {
      const existing = stack.find(s => s.name === name);
      if (existing) {
        existing.confidence = Math.min(100, existing.confidence + confidence);
        if (!existing.evidence.includes(evidence)) existing.evidence.push(evidence);
      } else {
        stack.push({ name, category, confidence, evidence: [evidence], role });
      }
    };

    // --- FRONTEND FRAMEWORKS ---
    if (html.includes('__NEXT_DATA__') || html.includes('_next/static')) {
      addStack('Next.js', 'Frontend Framework', 95, '/_next/static or __NEXT_DATA__ found', 'Renderizado SSR/SSG y routing');
    }
    if ($('div[data-reactroot], div#root').length > 0 || html.includes('react-dom')) {
      addStack('React', 'Frontend Framework', 80, 'React root div or library found', 'Librería de UI principal');
    }
    if (html.includes('data-v-') || html.includes('__VUE_SSR_CONTEXT__')) {
      addStack('Vue', 'Frontend Framework', 90, 'Vue specific data attributes found', 'Framework UI principal');
    }
    if (html.includes('_nuxt/') || html.includes('window.__NUXT__')) {
      addStack('Nuxt', 'Frontend Framework', 95, '/_nuxt/ path found', 'Renderizado SSR/SSG (Vue)');
    }
    if (html.includes('svelte-') || html.includes('__svelte')) {
      addStack('Svelte', 'Frontend Framework', 90, 'Svelte specific classes found', 'Compilador UI');
    }

    // --- BACKEND FRAMEWORKS ---
    const poweredBy = headers['x-powered-by'] ? String(headers['x-powered-by']).toLowerCase() : '';
    if (poweredBy.includes('express')) {
      addStack('Express', 'Backend Framework', 95, 'X-Powered-By: Express header', 'Servidor HTTP Node.js');
    }
    if (poweredBy.includes('next.js')) {
      addStack('Node.js', 'Backend Framework', 80, 'Implied by Next.js', 'Entorno de ejecución');
    }
    if (poweredBy.includes('php')) {
      addStack('PHP', 'Backend Framework', 95, `X-Powered-By: ${headers['x-powered-by']}`, 'Procesador Backend');
    }
    if (html.includes('wp-content')) {
      addStack('WordPress', 'Backend Framework', 99, 'wp-content/ path found', 'CMS / Backend System');
      addStack('PHP', 'Backend Framework', 90, 'Implied by WordPress', 'Procesador Backend');
    }

    // --- HOSTING / INFRASTRUCTURE ---
    const serverHeader = headers['server'] ? String(headers['server']).toLowerCase() : '';
    if (serverHeader.includes('cloudflare')) {
      addStack('Cloudflare', 'Hosting / Infrastructure', 99, 'Server: cloudflare', 'WAF / CDN');
    }
    if (serverHeader.includes('vercel') || headers['x-vercel-id']) {
      addStack('Vercel', 'Hosting / Infrastructure', 95, 'Server/Headers indicate Vercel', 'Serverless Hosting / Edge');
    }
    if (serverHeader.includes('netlify') || headers['x-nf-request-id']) {
      addStack('Netlify', 'Hosting / Infrastructure', 95, 'Server/Headers indicate Netlify', 'Jamstack Hosting');
    }

    // --- AUTHENTICATION ---
    if (html.includes('clerk.com') || html.includes('ClerkProvider')) {
      addStack('Clerk', 'Authentication', 95, 'Clerk SDK or URLs found', 'Gestión de identidad y usuarios');
    }
    if (html.includes('auth0.com')) {
      addStack('Auth0', 'Authentication', 95, 'Auth0 SDK found', 'Proveedor de identidad');
    }
    if (html.includes('supabase.co')) {
      addStack('Supabase', 'Database', 95, 'Supabase URL/SDK found', 'BaaS / Base de Datos PostgreSQL');
      addStack('Supabase Auth', 'Authentication', 80, 'Implied by Supabase usage', 'Módulo de Autenticación');
    }

    // --- EXTERNAL SERVICES ---
    if (html.includes('stripe.com')) {
      addStack('Stripe', 'External Services', 90, 'Stripe SDK found', 'Procesamiento de pagos');
    }
    if (html.includes('js.sentry-cdn.com')) {
      addStack('Sentry', 'External Services', 95, 'Sentry CDN found', 'Monitoreo de errores y rendimiento');
    }

    return stack;
  } catch (error) {
    console.error('TechStackProfiler Error:', error);
    return stack;
  }
}
