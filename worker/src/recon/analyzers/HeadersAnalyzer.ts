import type { TechStackItem } from '../TechStackItem';

export class HeadersAnalyzer {
  static analyze(headers: Record<string, string | string[]>): TechStackItem[] {
    const findings: TechStackItem[] = [];

    const add = (name: string, category: TechStackItem['category'], confidence: number, evidence: string, role: string, version?: string) => {
      findings.push({ name, category, confidence, evidence: [evidence], role, version });
    };

    const server = String(headers['server'] || '').toLowerCase();
    const poweredBy = String(headers['x-powered-by'] || '').toLowerCase();

    // Server
    if (server.includes('nginx')) {
      const vMatch = server.match(/nginx\/([0-9.]+)/);
      add('NGINX', 'Hosting / Infrastructure', 90, 'Server header contains nginx', 'Servidor Web / Proxy Inverso', vMatch ? vMatch[1] : undefined);
    }
    if (server.includes('apache')) {
      const vMatch = server.match(/apache\/([0-9.]+)/);
      add('Apache', 'Hosting / Infrastructure', 90, 'Server header contains apache', 'Servidor Web', vMatch ? vMatch[1] : undefined);
    }
    if (server.includes('cloudflare') || headers['cf-ray']) {
      add('Cloudflare', 'Hosting / Infrastructure', 99, 'Server/Headers indicate Cloudflare', 'WAF / CDN / Proxy Inverso');
    }
    if (server.includes('vercel') || headers['x-vercel-id']) {
      add('Vercel', 'Hosting / Infrastructure', 99, 'Vercel headers found', 'Serverless Hosting / Edge');
    }
    if (server.includes('netlify') || headers['x-nf-request-id']) {
      add('Netlify', 'Hosting / Infrastructure', 95, 'Server/Headers indicate Netlify', 'Jamstack Hosting');
    }
    if (headers['x-amz-cf-id'] || server.includes('cloudfront')) {
      add('AWS CloudFront', 'Hosting / Infrastructure', 95, 'AWS Headers found', 'CDN / Edge Network');
    }

    // Frameworks
    if (poweredBy.includes('express')) {
      add('Express', 'Backend Framework', 95, 'X-Powered-By: Express', 'Servidor HTTP Node.js');
      add('Node.js', 'Backend Framework', 80, 'Implied by Express', 'Entorno de ejecución');
    }
    if (poweredBy.includes('next.js')) {
      const vMatch = poweredBy.match(/next\.js\s*([0-9.]+)?/i);
      add('Next.js', 'Frontend Framework', 90, 'X-Powered-By: Next.js', 'Renderizado SSR/SSG', vMatch ? vMatch[1] : undefined);
      add('Node.js', 'Backend Framework', 80, 'Implied by Next.js', 'Entorno de ejecución');
    }
    if (poweredBy.includes('php')) {
      const vMatch = poweredBy.match(/php\/([0-9.]+)/i);
      add('PHP', 'Backend Framework', 95, 'X-Powered-By: PHP', 'Procesador Backend', vMatch ? vMatch[1] : undefined);
    }

    // Microsoft
    if (headers['x-aspnet-version']) {
      add('ASP.NET', 'Backend Framework', 99, 'ASP.NET Headers found', 'Web Framework Microsoft', String(headers['x-aspnet-version']));
    }

    return findings;
  }
}
