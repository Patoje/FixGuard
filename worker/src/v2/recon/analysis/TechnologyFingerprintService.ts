/**
 * Milestone P4-2 — Analytical Technology Fingerprint Service
 *
 * Pure Layer 6 Analytical Service for deterministic, passive technology fingerprinting.
 * Consumes already captured HTTP responses (headers + HTML body) and reconnaissance
 * observations to extract typed technology models (with exact versions and signals)
 * and synthesize a coherent TechEcosystemProfile without generating any new network requests.
 */

import type {
  DetectedTechnology,
  TechEcosystemProfile,
  TechnologyCategory,
  TechnologyFingerprintInput,
  TechnologyFingerprintResult,
} from '../../core/TechnologyContracts.js';

function extractHeaderValue(
  headers: Readonly<Record<string, string | string[] | undefined>> | undefined,
  targetKey: string
): string | undefined {
  if (!headers) return undefined;
  const lowerKey = targetKey.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lowerKey) {
      if (Array.isArray(v)) {
        return v.join('; ');
      }
      return typeof v === 'string' ? v : undefined;
    }
  }
  return undefined;
}

function parseVersionFromQueryOrPath(text: string, prefixRegex: RegExp): string | undefined {
  const match = text.match(prefixRegex);
  return match && match[1] ? match[1] : undefined;
}

export class TechnologyFingerprintService {
  /**
   * Pure deterministic analytical fingerprinting over captured response data.
   */
  public analyze(input: TechnologyFingerprintInput): TechnologyFingerprintResult {
    const detectedMap = new Map<string, DetectedTechnology>();

    function addTech(tech: DetectedTechnology): void {
      const existing = detectedMap.get(tech.name.toLowerCase());
      if (!existing) {
        detectedMap.set(tech.name.toLowerCase(), tech);
        return;
      }
      // Upgrade if existing lacks version and new one has it, or if higher confidence
      const shouldReplace =
        (!existing.version && tech.version) ||
        (existing.confidence === 'low' && (tech.confidence === 'medium' || tech.confidence === 'high')) ||
        (existing.confidence === 'medium' && tech.confidence === 'high');

      if (shouldReplace) {
        detectedMap.set(tech.name.toLowerCase(), {
          ...tech,
          version: tech.version ?? existing.version,
        });
      }
    }

    const headers = input.headers;
    const bodyText = input.bodyText ?? '';
    const url = input.url ?? '';
    const rawObs = input.rawObservations ?? [];

    // -------------------------------------------------------------------------
    // 1. Header Analysis
    // -------------------------------------------------------------------------
    const serverHeader = extractHeaderValue(headers, 'server');
    if (serverHeader) {
      const lower = serverHeader.toLowerCase();
      // Nginx
      const nginxMatch = serverHeader.match(/nginx(?:\/([0-9.]+))?/i);
      if (nginxMatch) {
        addTech({
          name: 'Nginx',
          version: nginxMatch[1],
          category: 'server',
          confidence: 'high',
          detectionSignal: `Server header: ${serverHeader}`,
          cpeIdentifier: nginxMatch[1] ? `cpe:2.3:a:f5:nginx:${nginxMatch[1]}:*:*:*:*:*:*:*` : 'cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*',
        });
      }
      // Apache
      const apacheMatch = serverHeader.match(/Apache(?:\/([0-9.]+))?/i);
      if (apacheMatch) {
        addTech({
          name: 'Apache HTTP Server',
          version: apacheMatch[1],
          category: 'server',
          confidence: 'high',
          detectionSignal: `Server header: ${serverHeader}`,
          cpeIdentifier: apacheMatch[1] ? `cpe:2.3:a:apache:http_server:${apacheMatch[1]}:*:*:*:*:*:*:*` : 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*',
        });
      }
      // Microsoft IIS
      const iisMatch = serverHeader.match(/Microsoft-IIS(?:\/([0-9.]+))?/i);
      if (iisMatch) {
        addTech({
          name: 'Microsoft IIS',
          version: iisMatch[1],
          category: 'server',
          confidence: 'high',
          detectionSignal: `Server header: ${serverHeader}`,
          cpeIdentifier: iisMatch[1] ? `cpe:2.3:a:microsoft:internet_information_services:${iisMatch[1]}:*:*:*:*:*:*:*` : 'cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*',
        });
        addTech({
          name: 'Windows Server',
          category: 'runtime',
          confidence: 'medium',
          detectionSignal: `Inferred from Microsoft-IIS server header`,
        });
      }
      // Cloudflare
      if (lower.includes('cloudflare')) {
        addTech({
          name: 'Cloudflare',
          category: 'cdn',
          confidence: 'high',
          detectionSignal: `Server header: ${serverHeader}`,
        });
      }
      // LiteSpeed / OpenResty / Caddy / Envoy
      if (lower.includes('litespeed')) {
        addTech({ name: 'LiteSpeed', category: 'server', confidence: 'high', detectionSignal: `Server: ${serverHeader}` });
      }
      if (lower.includes('openresty')) {
        const orMatch = serverHeader.match(/openresty(?:\/([0-9.]+))?/i);
        addTech({ name: 'OpenResty', version: orMatch?.[1], category: 'server', confidence: 'high', detectionSignal: `Server: ${serverHeader}` });
      }
      if (lower.includes('caddy')) {
        addTech({ name: 'Caddy', category: 'server', confidence: 'high', detectionSignal: `Server: ${serverHeader}` });
      }
      if (lower.includes('envoy')) {
        addTech({ name: 'Envoy Proxy', category: 'server', confidence: 'high', detectionSignal: `Server: ${serverHeader}` });
      }
      // Gunicorn
      const gunicornMatch = serverHeader.match(/gunicorn(?:\/([0-9.]+))?/i);
      if (gunicornMatch) {
        addTech({
          name: 'Gunicorn',
          version: gunicornMatch[1],
          category: 'runtime',
          confidence: 'high',
          detectionSignal: `Server header: ${serverHeader}`,
        });
        addTech({ name: 'Python', category: 'runtime', confidence: 'medium', detectionSignal: `Inferred from Gunicorn WSGI server` });
      }
      // Werkzeug / Python
      const pythonMatch = serverHeader.match(/Python\/([0-9.]+)/i);
      if (pythonMatch) {
        addTech({
          name: 'Python',
          version: pythonMatch[1],
          category: 'runtime',
          confidence: 'high',
          detectionSignal: `Server header: ${serverHeader}`,
        });
      }
      const werkzeugMatch = serverHeader.match(/Werkzeug\/([0-9.]+)/i);
      if (werkzeugMatch) {
        addTech({
          name: 'Werkzeug',
          version: werkzeugMatch[1],
          category: 'framework',
          confidence: 'high',
          detectionSignal: `Server header: ${serverHeader}`,
        });
      }
    }

    // X-Powered-By
    const poweredBy = extractHeaderValue(headers, 'x-powered-by');
    if (poweredBy) {
      const phpMatch = poweredBy.match(/PHP(?:\/([0-9.]+))?/i);
      if (phpMatch) {
        addTech({
          name: 'PHP',
          version: phpMatch[1],
          category: 'runtime',
          confidence: 'high',
          detectionSignal: `X-Powered-By header: ${poweredBy}`,
          cpeIdentifier: phpMatch[1] ? `cpe:2.3:a:php:php:${phpMatch[1]}:*:*:*:*:*:*:*` : 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*',
        });
      }
      if (poweredBy.toLowerCase().includes('express')) {
        addTech({
          name: 'Express',
          category: 'framework',
          confidence: 'high',
          detectionSignal: `X-Powered-By header: ${poweredBy}`,
        });
        addTech({
          name: 'Node.js',
          category: 'runtime',
          confidence: 'medium',
          detectionSignal: `Inferred from Express framework`,
        });
      }
      if (poweredBy.toLowerCase().includes('next.js')) {
        addTech({
          name: 'Next.js',
          category: 'framework',
          confidence: 'high',
          detectionSignal: `X-Powered-By header: ${poweredBy}`,
        });
        addTech({
          name: 'React',
          category: 'frontend',
          confidence: 'medium',
          detectionSignal: `Inferred from Next.js X-Powered-By header`,
        });
      }
      if (poweredBy.toLowerCase().includes('asp.net')) {
        addTech({
          name: 'ASP.NET',
          category: 'framework',
          confidence: 'high',
          detectionSignal: `X-Powered-By header: ${poweredBy}`,
        });
      }
    }

    // Phase D1 — Next.js / RSC response fingerprint signals
    const varyHeader = extractHeaderValue(headers, 'vary');
    if (varyHeader) {
      const lowerVary = varyHeader.toLowerCase();
      if (lowerVary.includes('rsc') || /next-router-/.test(lowerVary)) {
        addTech({
          name: 'Next.js',
          category: 'framework',
          confidence: 'high',
          detectionSignal: `Vary header RSC/Next-Router signal: ${varyHeader}`,
        });
        addTech({
          name: 'React',
          category: 'frontend',
          confidence: 'medium',
          detectionSignal: `Inferred from Next.js RSC Vary header`,
        });
      }
    }

    const xMatchedPath = extractHeaderValue(headers, 'x-matched-path');
    if (xMatchedPath !== undefined && xMatchedPath.length > 0) {
      addTech({
        name: 'Next.js',
        category: 'framework',
        confidence: 'high',
        detectionSignal: `X-Matched-Path header: ${xMatchedPath}`,
      });
      addTech({
        name: 'React',
        category: 'frontend',
        confidence: 'medium',
        detectionSignal: `Inferred from Next.js X-Matched-Path header`,
      });
    }

    // X-Generator / Meta generators
    const xGenerator = extractHeaderValue(headers, 'x-generator');
    if (xGenerator) {
      this.extractFromGeneratorString(xGenerator, 'X-Generator header', addTech);
    }

    // Cookies (Set-Cookie)
    const setCookie = extractHeaderValue(headers, 'set-cookie');
    if (setCookie) {
      const lowerCookie = setCookie.toLowerCase();
      if (lowerCookie.includes('phpsessid')) {
        addTech({
          name: 'PHP',
          category: 'runtime',
          confidence: 'high',
          detectionSignal: `PHPSESSID session cookie in Set-Cookie header`,
        });
      }
      if (lowerCookie.includes('laravel_session')) {
        addTech({
          name: 'Laravel',
          category: 'framework',
          confidence: 'high',
          detectionSignal: `laravel_session cookie in Set-Cookie header`,
        });
        addTech({ name: 'PHP', category: 'runtime', confidence: 'medium', detectionSignal: `Inferred from Laravel cookie` });
      }
      if (lowerCookie.includes('asp.net_sessionid') || lowerCookie.includes('__requestverificationtoken')) {
        addTech({
          name: 'ASP.NET',
          category: 'framework',
          confidence: 'high',
          detectionSignal: `ASP.NET session cookie in Set-Cookie header`,
        });
      }
      if (lowerCookie.includes('jsessionid')) {
        addTech({
          name: 'Java',
          category: 'runtime',
          confidence: 'high',
          detectionSignal: `JSESSIONID session cookie in Set-Cookie header`,
        });
      }
      if (lowerCookie.includes('csrftoken') || lowerCookie.includes('sessionid')) {
        addTech({
          name: 'Django',
          category: 'framework',
          confidence: 'medium',
          detectionSignal: `Django session/csrftoken pattern in Set-Cookie header`,
        });
      }
      if (lowerCookie.includes('connect.sid')) {
        addTech({
          name: 'Express',
          category: 'framework',
          confidence: 'high',
          detectionSignal: `connect.sid session cookie in Set-Cookie header`,
        });
        addTech({ name: 'Node.js', category: 'runtime', confidence: 'medium', detectionSignal: `Inferred from connect.sid cookie` });
      }
      if (lowerCookie.includes('wp-settings') || lowerCookie.includes('wordpress_logged_in')) {
        addTech({
          name: 'WordPress',
          category: 'cms',
          confidence: 'high',
          detectionSignal: `WordPress cookie pattern in Set-Cookie header`,
        });
      }
    }

    // Specific Infrastructure Headers
    if (extractHeaderValue(headers, 'x-drupal-cache') || extractHeaderValue(headers, 'x-drupal-dynamic-cache')) {
      addTech({ name: 'Drupal', category: 'cms', confidence: 'high', detectionSignal: `X-Drupal-Cache response header` });
    }
    if (extractHeaderValue(headers, 'x-varnish')) {
      addTech({ name: 'Varnish Cache', category: 'server', confidence: 'high', detectionSignal: `X-Varnish response header` });
    }
    if (extractHeaderValue(headers, 'x-amz-cf-id')) {
      addTech({ name: 'Amazon CloudFront', category: 'cdn', confidence: 'high', detectionSignal: `X-Amz-Cf-Id CDN response header` });
    }
    if (extractHeaderValue(headers, 'x-vercel-id')) {
      addTech({ name: 'Vercel', category: 'cdn', confidence: 'high', detectionSignal: `X-Vercel-Id response header` });
    }
    if (extractHeaderValue(headers, 'x-shopify-stage')) {
      addTech({ name: 'Shopify', category: 'cms', confidence: 'high', detectionSignal: `X-Shopify-Stage response header` });
    }
    if (extractHeaderValue(headers, 'x-magento-tags')) {
      addTech({ name: 'Magento', category: 'cms', confidence: 'high', detectionSignal: `X-Magento-Tags response header` });
    }

    // -------------------------------------------------------------------------
    // 2. HTML Meta Tags & Generators
    // -------------------------------------------------------------------------
    if (bodyText.length > 0) {
      const metaGeneratorMatches = bodyText.matchAll(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/gi);
      for (const m of metaGeneratorMatches) {
        if (m[1]) {
          this.extractFromGeneratorString(m[1], '<meta name="generator"> HTML tag', addTech);
        }
      }
      const altMetaMatches = bodyText.matchAll(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/gi);
      for (const m of altMetaMatches) {
        if (m[1]) {
          this.extractFromGeneratorString(m[1], '<meta name="generator"> HTML tag', addTech);
        }
      }

      // -----------------------------------------------------------------------
      // 3. Script / Link / Asset Paths & Query Parameter Versions
      // -----------------------------------------------------------------------
      // WordPress Asset & Plugin detection
      if (bodyText.includes('/wp-content/') || bodyText.includes('/wp-includes/')) {
        addTech({
          name: 'WordPress',
          category: 'cms',
          confidence: 'high',
          detectionSignal: `WordPress asset path in HTML source`,
        });

        // Version from wp-embed or style.css or script query string
        const wpCoreVer =
          parseVersionFromQueryOrPath(bodyText, /\/wp-includes\/js\/wp-embed(?:\.min)?\.js\?ver=([0-9.]+)/i) ??
          parseVersionFromQueryOrPath(bodyText, /\/wp-includes\/css\/dist\/block-library\/style(?:\.min)?\.css\?ver=([0-9.]+)/i);
        if (wpCoreVer) {
          addTech({
            name: 'WordPress',
            version: wpCoreVer,
            category: 'cms',
            confidence: 'high',
            detectionSignal: `WordPress core asset version query (?ver=${wpCoreVer})`,
            cpeIdentifier: `cpe:2.3:a:wordpress:wordpress:${wpCoreVer}:*:*:*:*:*:*:*`,
          });
        }

        // WordPress plugins
        const pluginMatches = bodyText.matchAll(/\/wp-content\/plugins\/([a-zA-Z0-9_-]+)\/[^"']*\?ver=([0-9.]+)/gi);
        for (const pm of pluginMatches) {
          const rawSlug = pm[1];
          const ver = pm[2];
          if (rawSlug) {
            const pluginName = this.formatPluginName(rawSlug);
            addTech({
              name: pluginName,
              version: ver,
              category: 'cms',
              confidence: 'high',
              detectionSignal: `WordPress plugin asset (/wp-content/plugins/${rawSlug}/...?ver=${ver})`,
            });
          }
        }
      }

      // Next.js & React Fingerprints
      if (bodyText.includes('__NEXT_DATA__') || bodyText.includes('/_next/static/')) {
        addTech({
          name: 'Next.js',
          category: 'framework',
          confidence: 'high',
          detectionSignal: bodyText.includes('__NEXT_DATA__') ? `__NEXT_DATA__ hydration script in DOM` : `/_next/static/ script path`,
        });
        addTech({
          name: 'React',
          category: 'frontend',
          confidence: 'high',
          detectionSignal: `React hydration signal via Next.js DOM markers`,
        });
      }

      // Nuxt.js & Vue.js Fingerprints
      if (bodyText.includes('window.__nuxt__') || bodyText.includes('id="__nuxt"') || bodyText.includes('/_nuxt/')) {
        addTech({
          name: 'Nuxt.js',
          category: 'framework',
          confidence: 'high',
          detectionSignal: `Nuxt.js DOM/script marker in HTML`,
        });
        addTech({
          name: 'Vue.js',
          category: 'frontend',
          confidence: 'high',
          detectionSignal: `Vue.js hydration signal via Nuxt.js markers`,
        });
      }

      // Angular Fingerprints
      const ngMatch = bodyText.match(/ng-version=["']([0-9.]+)["']/i);
      if (ngMatch) {
        addTech({
          name: 'Angular',
          version: ngMatch[1],
          category: 'frontend',
          confidence: 'high',
          detectionSignal: `ng-version attribute: ${ngMatch[1]}`,
          cpeIdentifier: `cpe:2.3:a:angular:angular:${ngMatch[1]}:*:*:*:*:*:*:*`,
        });
      } else if (bodyText.includes('ng-app') || bodyText.includes('ng-controller')) {
        addTech({
          name: 'AngularJS',
          category: 'frontend',
          confidence: 'high',
          detectionSignal: `AngularJS directive in HTML attributes`,
        });
      }

      // React Root
      if (bodyText.includes('data-reactroot') || (bodyText.includes('id="root"') && (bodyText.includes('react') || bodyText.includes('main.jsx') || bodyText.includes('bundle.js')))) {
        addTech({
          name: 'React',
          category: 'frontend',
          confidence: 'high',
          detectionSignal: `data-reactroot or React root mount point in DOM`,
        });
      }

      // Vue Root
      if (bodyText.includes('id="__vue-app"') || bodyText.includes('data-v-')) {
        addTech({
          name: 'Vue.js',
          category: 'frontend',
          confidence: 'high',
          detectionSignal: `Vue.js data-v- scope attribute or mount point in DOM`,
        });
      }

      // Svelte / SvelteKit
      if (bodyText.includes('__sveltekit') || bodyText.includes('data-sveltekit-')) {
        addTech({
          name: 'SvelteKit',
          category: 'framework',
          confidence: 'high',
          detectionSignal: `SvelteKit DOM/hydration marker in HTML`,
        });
        addTech({
          name: 'Svelte',
          category: 'frontend',
          confidence: 'high',
          detectionSignal: `Inferred from SvelteKit framework`,
        });
      }

      // jQuery
      const jqMatch =
        bodyText.match(/jquery(?:\.min)?\.js\?ver=([0-9.]+)/i) ??
        bodyText.match(/jquery-([0-9.]+)(?:\.min)?\.js/i);
      if (jqMatch) {
        addTech({
          name: 'jQuery',
          version: jqMatch[1],
          category: 'frontend',
          confidence: 'high',
          detectionSignal: `jQuery script asset match (?ver=${jqMatch[1]})`,
          cpeIdentifier: `cpe:2.3:a:jquery:jquery:${jqMatch[1]}:*:*:*:*:*:*:*`,
        });
      }

      // Bootstrap
      const bsMatch =
        bodyText.match(/bootstrap(?:\.min)?\.css\?ver=([0-9.]+)/i) ??
        bodyText.match(/bootstrap(?:\.min)?\.js\?ver=([0-9.]+)/i) ??
        bodyText.match(/bootstrap\/([0-9.]+)\/(?:css|js)\/bootstrap/i);
      if (bsMatch) {
        addTech({
          name: 'Bootstrap',
          version: bsMatch[1],
          category: 'frontend',
          confidence: 'high',
          detectionSignal: `Bootstrap stylesheet/script version match (${bsMatch[1]})`,
          cpeIdentifier: `cpe:2.3:a:getbootstrap:bootstrap:${bsMatch[1]}:*:*:*:*:*:*:*`,
        });
      }

      // Tailwind CSS
      if (bodyText.includes('tailwindcss') || bodyText.includes('/tailwind.css') || bodyText.includes('cdn.tailwindcss.com')) {
        addTech({
          name: 'Tailwind CSS',
          category: 'frontend',
          confidence: 'high',
          detectionSignal: `Tailwind CSS asset reference in HTML`,
        });
      }
    }

    // -------------------------------------------------------------------------
    // 4. Raw Observations Ingestion (SPA & Recon Adapters)
    // -------------------------------------------------------------------------
    for (const obs of rawObs) {
      if (typeof obs === 'object' && obs !== null) {
        const rec = obs as Record<string, unknown>;
        if (Array.isArray(rec.technologies)) {
          for (const t of rec.technologies) {
            if (typeof t === 'string' && t.trim().length > 0) {
              const name = t.trim();
              const category = this.inferCategoryFromName(name);
              addTech({
                name,
                category,
                confidence: 'medium',
                detectionSignal: `Recon adapter observation (technologies list)`,
              });
            }
          }
        }
        if (Array.isArray(rec.frameworks)) {
          for (const f of rec.frameworks) {
            if (typeof f === 'string' && f.trim().length > 0) {
              const name = f.trim();
              addTech({
                name,
                category: 'framework',
                confidence: 'high',
                detectionSignal: `SPA crawler framework observation`,
              });
            }
          }
        }
        if (typeof rec.webServer === 'string' && rec.webServer.trim().length > 0) {
          addTech({
            name: rec.webServer.trim(),
            category: 'server',
            confidence: 'high',
            detectionSignal: `Web inspection webServer observation`,
          });
        }
      }
    }

    // -------------------------------------------------------------------------
    // 5. Synthesize TechEcosystemProfile
    // -------------------------------------------------------------------------
    const techArray = Array.from(detectedMap.values()).sort((a, b) => a.name.localeCompare(b.name));

    const spaFramework = this.deriveSpaFramework(techArray);
    const hasSpa = spaFramework !== undefined;

    const cmsType = this.deriveCmsType(techArray);
    const hasCms = cmsType !== undefined;

    const hasGraphQL =
      url.toLowerCase().includes('/graphql') ||
      bodyText.toLowerCase().includes('/graphql') ||
      bodyText.includes('__schema') ||
      techArray.some((t) => t.name.toLowerCase().includes('graphql') || t.name.toLowerCase().includes('apollo'));

    const phpTech = techArray.find((t) => t.name.toLowerCase() === 'php');
    const hasPhpLegacy = Boolean(
      phpTech &&
      phpTech.version &&
      (phpTech.version.startsWith('5.') || phpTech.version.startsWith('7.'))
    );

    const hasExposedSourcemaps =
      bodyText.includes('sourceMappingURL=') ||
      bodyText.includes('//# sourceMappingURL=') ||
      bodyText.includes('/*# sourceMappingURL=');

    const ecosystemProfile: TechEcosystemProfile = {
      hasSpa,
      spaFramework,
      hasCms,
      cmsType,
      hasGraphQL,
      hasPhpLegacy,
      hasExposedSourcemaps,
    };

    return {
      technologies: techArray,
      ecosystemProfile,
    };
  }

  private extractFromGeneratorString(
    gen: string,
    sourceDesc: string,
    addTech: (t: DetectedTechnology) => void
  ): void {
    const trimmed = gen.trim();
    if (!trimmed) return;

    // WordPress
    const wpMatch = trimmed.match(/^WordPress(?:\s+([0-9.]+))?/i);
    if (wpMatch) {
      addTech({
        name: 'WordPress',
        version: wpMatch[1],
        category: 'cms',
        confidence: 'high',
        detectionSignal: `${sourceDesc}: ${trimmed}`,
        cpeIdentifier: wpMatch[1] ? `cpe:2.3:a:wordpress:wordpress:${wpMatch[1]}:*:*:*:*:*:*:*` : 'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*',
      });
      return;
    }

    // Drupal
    const drupalMatch = trimmed.match(/^Drupal(?:\s+([0-9.]+))?/i);
    if (drupalMatch) {
      addTech({
        name: 'Drupal',
        version: drupalMatch[1],
        category: 'cms',
        confidence: 'high',
        detectionSignal: `${sourceDesc}: ${trimmed}`,
        cpeIdentifier: drupalMatch[1] ? `cpe:2.3:a:drupal:drupal:${drupalMatch[1]}:*:*:*:*:*:*:*` : 'cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*',
      });
      return;
    }

    // Joomla
    const joomlaMatch = trimmed.match(/^Joomla!?\s*(?:-\s*Open Source Content Management)?(?:\s+([0-9.]+))?/i);
    if (joomlaMatch || trimmed.toLowerCase().includes('joomla')) {
      const verMatch = trimmed.match(/([0-9]+\.[0-9]+(?:\.[0-9]+)?)/);
      addTech({
        name: 'Joomla',
        version: verMatch?.[1],
        category: 'cms',
        confidence: 'high',
        detectionSignal: `${sourceDesc}: ${trimmed}`,
        cpeIdentifier: verMatch?.[1] ? `cpe:2.3:a:joomla:joomla\!:*${verMatch[1]}:*:*:*:*:*:*:*` : 'cpe:2.3:a:joomla:joomla\!:*:*:*:*:*:*:*:*',
      });
      return;
    }

    // Gatsby
    const gatsbyMatch = trimmed.match(/^Gatsby(?:\s+([0-9.]+))?/i);
    if (gatsbyMatch) {
      addTech({
        name: 'Gatsby',
        version: gatsbyMatch[1],
        category: 'framework',
        confidence: 'high',
        detectionSignal: `${sourceDesc}: ${trimmed}`,
      });
      addTech({ name: 'React', category: 'frontend', confidence: 'high', detectionSignal: `Inferred from Gatsby framework` });
      return;
    }

    // Hugo
    const hugoMatch = trimmed.match(/^Hugo(?:\s+([0-9.]+))?/i);
    if (hugoMatch) {
      addTech({
        name: 'Hugo',
        version: hugoMatch[1],
        category: 'framework',
        confidence: 'high',
        detectionSignal: `${sourceDesc}: ${trimmed}`,
      });
      return;
    }

    // Generic generator fallback
    addTech({
      name: trimmed,
      category: 'unknown',
      confidence: 'medium',
      detectionSignal: `${sourceDesc}: ${trimmed}`,
    });
  }

  private formatPluginName(slug: string): string {
    const words = slug.replace(/[-_]/g, ' ').split(' ');
    return words.map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
  }

  private inferCategoryFromName(name: string): TechnologyCategory {
    const lower = name.toLowerCase();
    if (['wordpress', 'drupal', 'joomla', 'shopify', 'wix', 'squarespace', 'magento', 'ghost'].some((c) => lower.includes(c))) {
      return 'cms';
    }
    if (['react', 'vue', 'angular', 'svelte', 'jquery', 'bootstrap', 'tailwind'].some((f) => lower.includes(f))) {
      return 'frontend';
    }
    if (['next.js', 'nuxt', 'express', 'laravel', 'django', 'flask', 'rails', 'spring', 'asp.net', 'fastapi'].some((f) => lower.includes(f))) {
      return 'framework';
    }
    if (['nginx', 'apache', 'iis', 'caddy', 'litespeed', 'envoy', 'openresty', 'traefik'].some((s) => lower.includes(s))) {
      return 'server';
    }
    if (['cloudflare', 'cloudfront', 'fastly', 'akamai', 'vercel'].some((c) => lower.includes(c))) {
      return 'cdn';
    }
    if (['php', 'node.js', 'python', 'java', 'ruby', 'go', 'dotnet', 'c#'].some((r) => lower.includes(r))) {
      return 'runtime';
    }
    if (['mysql', 'postgres', 'mongodb', 'redis', 'elasticsearch'].some((d) => lower.includes(d))) {
      return 'database';
    }
    return 'unknown';
  }

  private deriveSpaFramework(
    techs: readonly DetectedTechnology[]
  ): 'react' | 'vue' | 'angular' | 'nextjs' | 'nuxtjs' | 'unknown' | undefined {
    const names = techs.map((t) => t.name.toLowerCase());
    if (names.some((n) => n.includes('next.js'))) return 'nextjs';
    if (names.some((n) => n.includes('nuxt'))) return 'nuxtjs';
    if (names.some((n) => n.includes('react'))) return 'react';
    if (names.some((n) => n.includes('vue'))) return 'vue';
    if (names.some((n) => n.includes('angular'))) return 'angular';
    if (names.some((n) => n.includes('svelte'))) return 'unknown';
    return undefined;
  }

  private deriveCmsType(
    techs: readonly DetectedTechnology[]
  ): 'wordpress' | 'joomla' | 'drupal' | 'unknown' | undefined {
    const names = techs.map((t) => t.name.toLowerCase());
    if (names.some((n) => n.includes('wordpress'))) return 'wordpress';
    if (names.some((n) => n.includes('drupal'))) return 'drupal';
    if (names.some((n) => n.includes('joomla'))) return 'joomla';
    if (techs.some((t) => t.category === 'cms')) return 'unknown';
    return undefined;
  }
}
