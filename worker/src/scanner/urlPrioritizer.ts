export function scoreUrl(url: string, detectedStack?: string): number {
  const parsed = new URL(url);
  const path = parsed.pathname.toLowerCase();
  const search = parsed.search;

  let score = 10; // Default score

  // Capa 1 — Prioridad universal
  if (path.match(/\/(admin|administrator|manager|dashboard|control|panel)\b/)) {
    score = Math.max(score, 100);
  } else if (path.match(/\/(api|ajax|rest|graphql|rpc)\b/)) {
    score = Math.max(score, 90);
  } else if (path.match(/\/(webservice|service|endpoint)\b/)) {
    score = Math.max(score, 85);
  } else if (search.length > 1) { // Tiene query parameters
    score = Math.max(score, 80);
  } else if (path.match(/\/(config|setup|install|settings)\b/)) {
    score = Math.max(score, 75);
  } else if (path.match(/\/(user\/edit|account|profile\/edit|password)\b/)) {
    score = Math.max(score, 70);
  } else if (path.match(/\/(upload|import|export|file|attachment|media)\b/)) {
    score = Math.max(score, 65);
  } else if (path.match(/\/(report|log|audit|debug|trace)\b/)) {
    score = Math.max(score, 60);
  } else if (path.match(/\/(backup|dump|download)\b/)) {
    score = Math.max(score, 55);
  } else if (path.match(/\/(search|query|filter)\b/)) {
    score = Math.max(score, 40);
  } else if (path.match(/\/(blog|news|calendar|help|faq|about)\b/)) {
    score = Math.max(score, 20);
  }

  // Capa 2 — Bonus por stack detectado
  if (detectedStack) {
    const stack = detectedStack.toLowerCase();
    
    if (stack.includes('wordpress')) {
      if (path.match(/\/(wp-admin|wp-json|wp-content\/uploads|xmlrpc\.php)\b/)) score += 20;
    }
    if (stack.includes('moodle') || stack.includes('moodlesession')) {
      if (path.match(/\/(admin|lib\/ajax|webservice\/rest|mod\/assign|grade)\b/)) score += 20;
    }
    if (stack.includes('laravel')) {
      if (path.match(/\/(telescope|_ignition|horizon|api)\b/)) score += 20;
    }
    if (stack.includes('django')) {
      if (path.match(/\/(admin|api|__debug__|static\/admin)\b/)) score += 20;
    }
    if (stack.includes('express') || stack.includes('node')) {
      if (path.match(/\/(api|graphql|swagger|docs|\.env)\b/)) score += 20;
    }
    if (stack.includes('next.js') || stack.includes('nextjs') || stack.includes('react')) {
      if (path.match(/\/(api|_next|admin)\b/)) score += 20;
    }
    if (stack.includes('spring') || stack.includes('java')) {
      if (path.match(/\/(actuator|swagger-ui|api|h2-console)\b/)) score += 20;
    }
    if (stack.includes('rails') || stack.includes('ruby')) {
      if (path.match(/\/(rails\/info|admin|sidekiq|api)\b/)) score += 20;
    }
  }

  return score;
}

/**
 * Retorna las rutas de mayor valor a inyectar en la cola inicial basándose en el stack.
 */
export function getHighValueRoutesForStack(targetUrl: string, detectedStack: string): string[] {
  const routes: string[] = [];
  const base = targetUrl.replace(/\/$/, '');
  const stack = detectedStack.toLowerCase();

  if (stack.includes('wordpress')) {
    routes.push('/wp-admin/', '/wp-json/', '/xmlrpc.php');
  }
  if (stack.includes('moodle') || stack.includes('moodlesession')) {
    routes.push('/admin/', '/lib/ajax/service-nologin.php', '/webservice/rest/server.php');
  }
  if (stack.includes('laravel')) {
    routes.push('/telescope', '/_ignition/execute-solution', '/horizon', '/api/');
  }
  if (stack.includes('django')) {
    routes.push('/admin/', '/api/', '/__debug__/');
  }
  if (stack.includes('express') || stack.includes('node')) {
    routes.push('/api/', '/graphql', '/api-docs', '/swagger');
  }
  if (stack.includes('next.js') || stack.includes('nextjs') || stack.includes('react')) {
    routes.push('/api/', '/admin/');
  }
  if (stack.includes('spring') || stack.includes('java')) {
    routes.push('/actuator/env', '/swagger-ui.html', '/h2-console/');
  }
  if (stack.includes('rails') || stack.includes('ruby')) {
    routes.push('/rails/info/properties', '/admin/', '/sidekiq/');
  }

  return routes.map(r => base + r);
}
