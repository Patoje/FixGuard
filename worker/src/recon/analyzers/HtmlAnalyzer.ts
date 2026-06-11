import type { TechStackItem } from '../TechStackItem';
import * as cheerio from 'cheerio';

export class HtmlAnalyzer {
  static analyze(html: string): TechStackItem[] {
    const findings: TechStackItem[] = [];
    if (!html) return findings;

    const $ = cheerio.load(html);

    const add = (name: string, category: TechStackItem['category'], confidence: number, evidence: string, role: string, version?: string) => {
      findings.push({ name, category, confidence, evidence: [evidence], role, version });
    };

    // Generator Meta Tag
    const generator = $('meta[name="generator"]').attr('content') || '';
    if (generator.toLowerCase().includes('wordpress')) {
      const vMatch = generator.match(/WordPress\s*([0-9.]+)/i);
      add('WordPress', 'CMS', 99, 'Meta generator: WordPress', 'Gestor de Contenido', vMatch ? vMatch[1] : undefined);
      add('PHP', 'Backend Framework', 90, 'Implied by WordPress', 'Procesador Backend');
    }

    // Vue
    if (html.includes('data-v-') || html.includes('__VUE_SSR_CONTEXT__')) {
      add('Vue.js', 'Frontend Framework', 90, 'Vue specific data attributes', 'Framework UI');
    }
    if (html.includes('_nuxt/') || html.includes('window.__NUXT__')) {
      add('Nuxt.js', 'Frontend Framework', 95, 'Nuxt patterns found', 'SSR Framework (Vue)');
    }

    // React / Next
    if ($('div[data-reactroot], div#root').length > 0 || html.includes('react-dom')) {
      add('React', 'Frontend Framework', 80, 'React root or lib found', 'Librería de UI');
    }
    if (html.includes('__NEXT_DATA__') || html.includes('_next/static')) {
      add('Next.js', 'Frontend Framework', 95, 'Next.js static paths', 'Renderizado SSR/SSG y routing');
    }

    // Libraries & Frameworks
    if (html.includes('tailwindcss') || html.includes('tw-')) {
      add('Tailwind CSS', 'Frontend Framework', 80, 'Tailwind classes/scripts', 'Framework CSS');
    }
    if (html.includes('bootstrap')) {
      add('Bootstrap', 'Frontend Framework', 90, 'Bootstrap references', 'Framework CSS');
    }
    if (html.includes('svelte-') || html.includes('__svelte')) {
      add('Svelte', 'Frontend Framework', 90, 'Svelte specific classes found', 'Compilador UI');
    }

    // Authentication
    if (html.includes('clerk.com') || html.includes('ClerkProvider')) {
      add('Clerk', 'Authentication', 95, 'Clerk SDK or URLs found', 'Gestión de identidad y usuarios');
    }
    if (html.includes('auth0.com')) {
      add('Auth0', 'Authentication', 95, 'Auth0 SDK found', 'Proveedor de identidad');
    }
    if (html.includes('supabase.co')) {
      add('Supabase', 'Database', 95, 'Supabase URL/SDK found', 'BaaS / Base de Datos PostgreSQL');
      add('Supabase Auth', 'Authentication', 80, 'Implied by Supabase usage', 'Módulo de Autenticación');
    }

    // Ext services
    if (html.includes('stripe.com')) add('Stripe', 'External Services', 90, 'Stripe SDK', 'Procesamiento de pagos');
    if (html.includes('js.sentry-cdn.com') || html.includes('sentry.io')) add('Sentry', 'External Services', 95, 'Sentry CDN/URL found', 'Monitoreo de errores');
    if (html.includes('google-analytics.com') || html.includes('G-')) add('Google Analytics', 'External Services', 95, 'GA tags found', 'Analítica de tráfico');
    if (html.includes('googletagmanager.com') || html.includes('GTM-')) add('Google Tag Manager', 'External Services', 95, 'GTM script found', 'Gestión de tags');
    if (html.includes('intercom.io') || html.includes('Intercom(')) add('Intercom', 'External Services', 95, 'Intercom SDK found', 'Soporte y Chat');
    if (html.includes('posthog.com') || html.includes('posthog.init')) add('PostHog', 'External Services', 95, 'PostHog analytics found', 'Analítica de Producto');
    if (html.includes('segment.com') || html.includes('analytics.js')) add('Segment', 'External Services', 90, 'Segment tracking found', 'Datos de Clientes');
    if (html.includes('algolia.net') || html.includes('algoliasearch')) add('Algolia', 'External Services', 95, 'Algolia search script found', 'Motor de Búsqueda');
    if (html.includes('twilio.com')) add('Twilio', 'External Services', 90, 'Twilio references found', 'Comunicaciones');
    if (html.includes('sendgrid.net') || html.includes('sendgrid.com')) add('SendGrid', 'External Services', 90, 'SendGrid found', 'Email');
    if (html.includes('resend.com')) add('Resend', 'External Services', 90, 'Resend found', 'API de Email');
    if (html.includes('firebaseapp.com') || html.includes('firebase.js')) add('Firebase', 'External Services', 95, 'Firebase SDK found', 'BaaS / DB');
    if (html.includes('openai.com') || html.includes('chatgpt')) add('OpenAI', 'External Services', 85, 'OpenAI API references', 'IA (LLM)');
    if (html.includes('anthropic.com') || html.includes('claude')) add('Anthropic', 'External Services', 85, 'Anthropic API references', 'IA (LLM)');
    if (html.includes('gemini') || html.includes('generativelanguage.googleapis.com')) add('Google Gemini', 'External Services', 85, 'Gemini API references', 'IA (LLM)');
    if (html.includes('mapbox.com')) add('Mapbox', 'External Services', 95, 'Mapbox SDK found', 'Mapas');
    if (html.includes('browser.sentry-cdn.com') || html.includes('datadoghq-browser-agent')) add('Datadog', 'External Services', 95, 'Datadog RUM/Logs found', 'Observabilidad');

    return findings;
  }
}
