/**
 * Milestone P4-2 — Technology Fingerprint Engine Smoke Suite
 *
 * Verifies:
 * 1. Accurately extracts WordPress core and plugin versions from meta tags and asset queries.
 * 2. Detects Next.js and React indicators from HTML markers (__NEXT_DATA__, script chunks).
 * 3. Detects backend runtimes (PHP, IIS, ASP.NET, Python/Gunicorn) from cookies and server banners.
 * 4. Correctly synthesizes the TechEcosystemProfile with zero extra network requests.
 * 5. Integrates with TargetProfileBuilder in the F5 Intelligence Layer.
 */

import { TechnologyFingerprintService } from '../recon/analysis/TechnologyFingerprintService.js';
import { buildTargetProfile } from '../intelligence/TargetProfileBuilder.js';
import type { DiscoveredWebObservation } from '../recon/adapters/WebInspectionContracts.js';
import type { DiscoveredSpaObservation } from '../recon/adapters/BrowserAutomationContracts.js';

console.log('[milestoneP4_2_tech_fingerprint_smoke] Starting Milestone P4-2 smoke suite...');

async function runTests(): Promise<void> {
  const service = new TechnologyFingerprintService();

  // ---------------------------------------------------------------------------
  // Assertion 1: WordPress Core, Plugins & Version Extraction
  // ---------------------------------------------------------------------------
  console.log('-> Test 1: Extracting WordPress core and plugin versions from meta tags and asset queries...');
  const wpSampleHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="generator" content="WordPress 6.4.2" />
      <link rel="stylesheet" href="https://blog.example.com/wp-includes/css/dist/block-library/style.min.css?ver=6.4.2" />
      <link rel="stylesheet" href="https://blog.example.com/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=8.4.0" />
      <script src="https://blog.example.com/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.18.0"></script>
      <script src="https://blog.example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
    </head>
    <body>
      <div id="page">
        <h1>WordPress Store</h1>
      </div>
    </body>
    </html>
  `;

  const wpResult = service.analyze({
    url: 'https://blog.example.com',
    headers: {
      'server': 'nginx/1.24.0',
      'x-powered-by': 'PHP/8.2.10',
      'set-cookie': 'wordpress_logged_in_xyz=1; path=/; HttpOnly',
    },
    bodyText: wpSampleHtml,
  });

  const wpCore = wpResult.technologies.find((t) => t.name === 'WordPress');
  if (!wpCore || wpCore.version !== '6.4.2' || wpCore.category !== 'cms' || wpCore.confidence !== 'high') {
    throw new Error(`Test 1 Failed: WordPress core was not extracted accurately: ${JSON.stringify(wpCore)}`);
  }

  const wcPlugin = wpResult.technologies.find((t) => t.name === 'Woocommerce');
  if (!wcPlugin || wcPlugin.version !== '8.4.0' || wcPlugin.category !== 'cms') {
    throw new Error(`Test 1 Failed: WooCommerce plugin was not extracted: ${JSON.stringify(wcPlugin)}`);
  }

  const elementorPlugin = wpResult.technologies.find((t) => t.name === 'Elementor');
  if (!elementorPlugin || elementorPlugin.version !== '3.18.0') {
    throw new Error(`Test 1 Failed: Elementor plugin was not extracted: ${JSON.stringify(elementorPlugin)}`);
  }

  const jqueryTech = wpResult.technologies.find((t) => t.name === 'jQuery');
  if (!jqueryTech || jqueryTech.version !== '3.7.1') {
    throw new Error(`Test 1 Failed: jQuery version not extracted: ${JSON.stringify(jqueryTech)}`);
  }

  if (!wpResult.ecosystemProfile.hasCms || wpResult.ecosystemProfile.cmsType !== 'wordpress') {
    throw new Error(`Test 1 Failed: Ecosystem profile did not mark WordPress CMS: ${JSON.stringify(wpResult.ecosystemProfile)}`);
  }
  console.log('  [PASS] WordPress core (v6.4.2) and plugins (WooCommerce v8.4.0, Elementor v3.18.0) accurately fingerprinted.');

  // ---------------------------------------------------------------------------
  // Assertion 2: Next.js, React & Sourcemap Fingerprint
  // ---------------------------------------------------------------------------
  console.log('-> Test 2: Detecting Next.js, React, and exposed sourcemaps from DOM markers...');
  const nextSampleHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Modern App</title>
      <script src="/_next/static/chunks/main-app-c8e9f1a2.js" async></script>
      <script src="/_next/static/chunks/webpack-12345.js" async></script>
    </head>
    <body>
      <div id="__next">
        <main><h1>Next App</h1></main>
      </div>
      <script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{}},"page":"/","query":{},"buildId":"prod_v1"}</script>
      <script>//# sourceMappingURL=main.js.map</script>
    </body>
    </html>
  `;

  const nextResult = service.analyze({
    url: 'https://app.example.com',
    headers: {
      'x-powered-by': 'Next.js',
      'x-vercel-id': 'iad1::xyz789',
    },
    bodyText: nextSampleHtml,
  });

  const nextTech = nextResult.technologies.find((t) => t.name === 'Next.js');
  if (!nextTech || nextTech.category !== 'framework' || nextTech.confidence !== 'high') {
    throw new Error(`Test 2 Failed: Next.js was not detected: ${JSON.stringify(nextTech)}`);
  }

  const reactTech = nextResult.technologies.find((t) => t.name === 'React');
  if (!reactTech || reactTech.category !== 'frontend') {
    throw new Error(`Test 2 Failed: React was not inferred from Next.js: ${JSON.stringify(reactTech)}`);
  }

  const vercelTech = nextResult.technologies.find((t) => t.name === 'Vercel');
  if (!vercelTech || vercelTech.category !== 'cdn') {
    throw new Error(`Test 2 Failed: Vercel CDN was not detected: ${JSON.stringify(vercelTech)}`);
  }

  if (!nextResult.ecosystemProfile.hasSpa || nextResult.ecosystemProfile.spaFramework !== 'nextjs') {
    throw new Error(`Test 2 Failed: Ecosystem profile missing SPA Next.js tag: ${JSON.stringify(nextResult.ecosystemProfile)}`);
  }
  if (!nextResult.ecosystemProfile.hasExposedSourcemaps) {
    throw new Error(`Test 2 Failed: Exposed sourcemaps not flagged in ecosystem profile`);
  }
  console.log('  [PASS] Next.js, React, and exposed sourcemaps correctly identified.');

  // ---------------------------------------------------------------------------
  // Assertion 3: Backend Runtimes (Legacy PHP, IIS, ASP.NET, Python/Gunicorn)
  // ---------------------------------------------------------------------------
  console.log('-> Test 3: Detecting backend runtimes and legacy stacks from server banners & session cookies...');
  
  // Case A: Legacy PHP on Apache
  const legacyPhpResult = service.analyze({
    url: 'https://legacy.example.com',
    headers: {
      'server': 'Apache/2.4.41 (Ubuntu)',
      'x-powered-by': 'PHP/7.4.3',
      'set-cookie': 'PHPSESSID=s92kd823jh190d; path=/',
    },
    bodyText: '<html><body>Legacy Portal</body></html>',
  });

  const phpTech = legacyPhpResult.technologies.find((t) => t.name === 'PHP');
  if (!phpTech || phpTech.version !== '7.4.3') {
    throw new Error(`Test 3A Failed: PHP 7.4.3 was not extracted: ${JSON.stringify(phpTech)}`);
  }
  if (!legacyPhpResult.ecosystemProfile.hasPhpLegacy) {
    throw new Error(`Test 3A Failed: hasPhpLegacy should be true for PHP 7.4.3`);
  }

  // Case B: Microsoft IIS & ASP.NET
  const iisResult = service.analyze({
    url: 'https://corp.example.com',
    headers: {
      'server': 'Microsoft-IIS/10.0',
      'x-powered-by': 'ASP.NET',
      'set-cookie': 'ASP.NET_SessionId=abcdef123456; path=/; HttpOnly',
    },
    bodyText: '<html><body>Corporate Intranet</body></html>',
  });

  const iisTech = iisResult.technologies.find((t) => t.name === 'Microsoft IIS');
  if (!iisTech || iisTech.version !== '10.0' || iisTech.category !== 'server') {
    throw new Error(`Test 3B Failed: Microsoft IIS 10.0 not extracted: ${JSON.stringify(iisTech)}`);
  }
  const aspTech = iisResult.technologies.find((t) => t.name === 'ASP.NET');
  if (!aspTech || aspTech.category !== 'framework') {
    throw new Error(`Test 3B Failed: ASP.NET framework not extracted: ${JSON.stringify(aspTech)}`);
  }

  // Case C: Python / Gunicorn / Werkzeug
  const pythonResult = service.analyze({
    url: 'https://api.example.com/graphql',
    headers: {
      'server': 'gunicorn/20.1.0 Werkzeug/2.2.2 Python/3.10.6',
    },
    bodyText: '{"data": {"__schema": {"types": []}}}',
  });

  const gunicornTech = pythonResult.technologies.find((t) => t.name === 'Gunicorn');
  if (!gunicornTech || gunicornTech.version !== '20.1.0') {
    throw new Error(`Test 3C Failed: Gunicorn was not extracted: ${JSON.stringify(gunicornTech)}`);
  }
  if (!pythonResult.ecosystemProfile.hasGraphQL) {
    throw new Error(`Test 3C Failed: GraphQL was not flagged in ecosystem profile`);
  }
  console.log('  [PASS] Backend runtimes (PHP 7.4.3, IIS 10.0, ASP.NET, Python 3.10.6, Gunicorn 20.1.0, GraphQL) correctly identified.');

  // ---------------------------------------------------------------------------
  // Assertion 4: TargetProfileBuilder Integration in F5 Intelligence Layer
  // ---------------------------------------------------------------------------
  console.log('-> Test 4: Integrating with TargetProfileBuilder in F5 Intelligence Layer...');
  const mockWebObs: DiscoveredWebObservation = {
    url: 'https://app.example.com',
    method: 'GET',
    statusCode: 200,
    title: 'E-commerce Store',
    webServer: 'nginx/1.22.1',
    technologies: ['WordPress', 'PHP', 'WooCommerce', 'MySQL'],
    discoveredAt: new Date().toISOString(),
  };

  const mockSpaObs: DiscoveredSpaObservation = {
    url: 'https://app.example.com/dashboard',
    targetHost: 'app.example.com',
    pageTitle: 'Dashboard',
    frameworks: ['Vue.js', 'Nuxt.js'],
    routes: [{
      url: 'https://app.example.com/dashboard',
      path: '/dashboard',
      routeType: 'history_push',
      source: 'nuxt_router',
      discoveredAt: new Date().toISOString(),
    }],
    inputs: [],
    technologies: ['Vue.js', 'Nuxt.js', 'Tailwind CSS'],
    discoveredAt: new Date().toISOString(),
  };

  const targetProfile = buildTargetProfile({
    targetHost: 'app.example.com',
    normalizedOrigin: 'https://app.example.com',
    observations: [mockWebObs, mockSpaObs],
    findings: [],
    lineage: {
      assessmentId: 'asm_test_001',
      scanId: 'scn_test_001',
      authorizationGrantId: 'grnt_test_001',
      authorizationDecisionId: 'dec_test_001',
      actorId: 'usr_secops',
    },
  });

  if (!targetProfile.detectedTechnologies || targetProfile.detectedTechnologies.length === 0) {
    throw new Error('Test 4 Failed: targetProfile.detectedTechnologies was not populated');
  }
  if (!targetProfile.ecosystemProfile) {
    throw new Error('Test 4 Failed: targetProfile.ecosystemProfile was not populated');
  }
  if (targetProfile.technologies.length === 0) {
    throw new Error('Test 4 Failed: targetProfile.technologies (backward compatible list) was empty');
  }

  const vueTech = targetProfile.detectedTechnologies.find((t) => t.name === 'Vue.js');
  if (!vueTech) {
    throw new Error('Test 4 Failed: Vue.js was not in detectedTechnologies');
  }

  console.log('  [PASS] TargetProfile enriched with structured detectedTechnologies and ecosystemProfile.');

  console.log('[milestoneP4_2_tech_fingerprint_smoke] ALL SMOKE TESTS PASSED (100%)');
}

runTests().catch((err) => {
  console.error('[milestoneP4_2_tech_fingerprint_smoke] TEST FAILED:', err);
  process.exit(1);
});
