import type { TechStackItem } from '../TechStackItem';
import * as cheerio from 'cheerio';

export class ExpandedTechAnalyzer {
  static analyze(html: string, headers: Record<string, string | string[]>, cookies: string[]): TechStackItem[] {
    const findings: TechStackItem[] = [];
    const htmlLower = html.toLowerCase();
    const headersString = JSON.stringify(headers).toLowerCase();
    const cookieString = cookies.join(';').toLowerCase();

    const add = (name: string, category: TechStackItem['category'], confidence: number, evidence: string) => {
      findings.push({ name, category, confidence, evidence: [evidence], role: 'Detección Expandida' });
    };

    // Helper para buscar en HTML
    const hasHtml = (str: string) => htmlLower.includes(str.toLowerCase());
    const hasRegexHtml = (regex: RegExp) => regex.test(html);
    const hasHeader = (key: string, valPattern: string) => {
      const h = (headers[key.toLowerCase()] || headers[key]) as string | string[];
      if (!h) return false;
      return String(h).toLowerCase().includes(valPattern.toLowerCase());
    };
    const hasHeaderKey = (key: string) => !!(headers[key.toLowerCase()] || headers[key]);

    // ─── 1. SERVIDORES WEB (Web Server) ────────────────────────────────────────────────
    if (hasHeader('server', 'apache')) add('Apache', 'Web Server', 99, 'Header Server: Apache');
    if (hasHeader('server', 'nginx')) add('Nginx', 'Web Server', 99, 'Header Server: Nginx');
    if (hasHeader('server', 'iis') || hasHeader('server', 'microsoft-iis')) add('IIS', 'Web Server', 99, 'Header Server: IIS');
    if (hasHeader('server', 'litespeed')) add('LiteSpeed', 'Web Server', 99, 'Header Server: LiteSpeed');
    if (hasHeader('server', 'caddy')) add('Caddy', 'Web Server', 99, 'Header Server: Caddy');
    if (hasHeader('server', 'tomcat') || hasHeader('x-powered-by', 'tomcat')) add('Apache Tomcat', 'Web Server', 99, 'Tomcat headers');
    if (hasHeader('server', 'jetty')) add('Jetty', 'Web Server', 99, 'Jetty server header');

    // ─── 2. LENGUAJES DE PROGRAMACIÓN & RUNTIMES ───────────────────────────────────────
    if (hasHeader('x-powered-by', 'php') || cookieString.includes('phpsessid')) add('PHP', 'Programming Language', 99, 'PHP headers or cookies');
    if (hasHeader('x-powered-by', 'asp.net') || cookieString.includes('asp.net_sessionid')) {
      add('ASP.NET', 'Backend Framework', 99, 'ASP.NET headers/cookies');
      add('C#', 'Programming Language', 90, 'Implied by ASP.NET');
    }
    if (cookieString.includes('jsessionid') || hasHtml('.jsp') || hasHeader('x-powered-by', 'jsp') || hasHeader('x-powered-by', 'java')) {
      add('Java', 'Programming Language', 99, 'JSESSIONID or JSP references');
    }
    if (hasHeader('x-powered-by', 'express') || hasHeader('x-powered-by', 'sails') || hasHeader('x-powered-by', 'next.js')) {
      add('Node.js', 'Programming Language', 95, 'Implied by Node frameworks');
    }
    if (hasHtml('.rb') || hasHeader('server', 'webrick') || hasHeader('x-powered-by', 'phusion passenger') || cookieString.includes('_session_id')) {
      add('Ruby', 'Programming Language', 80, 'Ruby indicators');
    }
    if (hasHeader('server', 'gunicorn') || hasHeader('server', 'werkzeug') || hasHtml('.py')) {
      add('Python', 'Programming Language', 90, 'Python server headers');
    }
    if (hasHeader('x-powered-by', 'coldfusion') || cookieString.includes('cfid') || cookieString.includes('cftoken')) {
      add('ColdFusion', 'Programming Language', 99, 'ColdFusion headers/cookies');
    }

    // ─── 3. BACKEND FRAMEWORKS ────────────────────────────────────────────────────────
    if (hasHtml('django') || cookieString.includes('csrftoken')) add('Django', 'Backend Framework', 85, 'Django csrf token');
    if (cookieString.includes('laravel_session') || hasHtml('laravel')) add('Laravel', 'Backend Framework', 99, 'Laravel session cookie');
    if (hasHeader('x-powered-by', 'express')) add('Express', 'Backend Framework', 99, 'Express header');
    if (hasHeader('x-powered-by', 'spring') || hasHtml('spring-form')) add('Spring', 'Backend Framework', 90, 'Spring framework hints');
    if (hasHeader('x-powered-by', 'rubyonrails') || hasHtml('csrf-param" content="authenticity_token"')) add('Ruby on Rails', 'Backend Framework', 95, 'Rails csrf token');

    // ─── 4. FRONTEND FRAMEWORKS & LIBRARIES ───────────────────────────────────────────
    if (hasHtml('react-dom') || hasHtml('data-reactroot')) add('React', 'Frontend Framework', 95, 'React DOM found');
    if (hasHtml('__NEXT_DATA__') || hasHtml('_next/static')) add('Next.js', 'Frontend Framework', 99, 'Next.js static assets');
    if (hasHtml('__VUE_SSR_CONTEXT__') || hasHtml('data-v-')) add('Vue.js', 'Frontend Framework', 95, 'Vue.js references');
    if (hasHtml('window.__NUXT__') || hasHtml('_nuxt/')) add('Nuxt.js', 'Frontend Framework', 99, 'Nuxt references');
    if (hasHtml('ng-app') || hasHtml('ng-controller') || hasHtml('ng-version')) add('Angular', 'Frontend Framework', 99, 'Angular directives');
    if (hasHtml('svelte-') || hasHtml('__svelte')) add('Svelte', 'Frontend Framework', 95, 'Svelte classes');
    
    // UI/CSS Frameworks
    if (hasHtml('tailwindcss') || hasHtml('tw-bg-')) add('Tailwind CSS', 'Frontend Framework', 90, 'Tailwind classes');
    if (hasHtml('bootstrap') || hasHtml('col-md-')) add('Bootstrap', 'Frontend Framework', 90, 'Bootstrap classes');
    if (hasHtml('material-ui') || hasHtml('MuiButton-root')) add('Material UI', 'Frontend Framework', 95, 'MUI classes');
    if (hasHtml('ant-design') || hasHtml('ant-btn')) add('Ant Design', 'Frontend Framework', 90, 'Ant classes');
    if (hasHtml('bulma')) add('Bulma', 'Frontend Framework', 90, 'Bulma classes');
    
    // JS Libraries
    if (hasHtml('jquery') || hasRegexHtml(/jquery[-0-9.]*\.js/i)) add('jQuery', 'JavaScript Library', 99, 'jQuery script tag');
    if (hasHtml('lodash') || hasHtml('underscore')) add('Lodash / Underscore', 'JavaScript Library', 85, 'Lodash references');
    if (hasHtml('moment.js')) add('Moment.js', 'JavaScript Library', 90, 'Moment.js script');

    // ─── 5. CMS (Gestores de Contenido) ───────────────────────────────────────────────
    if (hasHtml('wp-content') || hasHtml('wp-includes') || hasRegexHtml(/<meta name="generator" content="WordPress/i)) {
      add('WordPress', 'CMS', 99, 'WordPress directories or meta generator');
      add('PHP', 'Programming Language', 90, 'Implied by WordPress');
    }
    if (hasHtml('sites/default/files') || hasHeader('x-generator', 'drupal')) add('Drupal', 'CMS', 95, 'Drupal hints');
    if (hasHtml('joomla') || hasHeader('x-content-encoded-by', 'joomla')) add('Joomla', 'CMS', 95, 'Joomla hints');
    if (hasHtml('magento') || cookieString.includes('frontend')) add('Magento', 'CMS', 90, 'Magento hints');
    if (hasHtml('shopify.com') || hasHeader('x-shopid')) add('Shopify', 'CMS', 99, 'Shopify headers/URLs');

    // ─── 6. HOSTING & INFRAESTRUCTURA ─────────────────────────────────────────────────
    if (hasHeader('server', 'cloudflare') || hasHeaderKey('cf-ray')) add('Cloudflare', 'Hosting / Infrastructure', 99, 'Cloudflare headers');
    if (hasHeader('server', 'vercel') || hasHeaderKey('x-vercel-id')) add('Vercel', 'Hosting / Infrastructure', 99, 'Vercel headers');
    if (hasHeader('server', 'netlify') || hasHeaderKey('x-nf-request-id')) add('Netlify', 'Hosting / Infrastructure', 99, 'Netlify headers');
    if (hasHeaderKey('x-amz-cf-id')) add('AWS CloudFront', 'Hosting / Infrastructure', 99, 'CloudFront headers');
    if (hasHeaderKey('x-fastly-request-id')) add('Fastly', 'Hosting / Infrastructure', 99, 'Fastly CDN headers');

    // ─── 7. ANALYTICS & EXTERNAL SERVICES ─────────────────────────────────────────────
    if (hasHtml('google-analytics.com') || hasHtml('gtag')) add('Google Analytics', 'Analytics', 99, 'GA tracking code');
    if (hasHtml('googletagmanager.com')) add('Google Tag Manager', 'Analytics', 99, 'GTM tracking code');
    if (hasHtml('hotjar.com') || hasHtml('hj(')) add('Hotjar', 'Analytics', 95, 'Hotjar tracking code');
    if (hasHtml('posthog.com')) add('PostHog', 'Analytics', 95, 'PostHog tracking code');
    if (hasHtml('sentry.io') || hasHtml('@sentry/')) add('Sentry', 'External Services', 95, 'Sentry error tracking');
    if (hasHtml('stripe.com')) add('Stripe', 'External Services', 95, 'Stripe SDK');
    if (hasHtml('intercom.io')) add('Intercom', 'External Services', 95, 'Intercom SDK');
    if (hasHtml('auth0.com')) add('Auth0', 'Authentication', 95, 'Auth0 SDK');
    if (hasHtml('clerk.com')) add('Clerk', 'Authentication', 95, 'Clerk SDK');

    return findings;
  }
}
