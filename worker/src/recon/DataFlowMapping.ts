export interface DataFlowNode {
  id: string;
  name: string;
  type: string; // "Client", "WAF", "API Gateway", "Backend", "Database", "ThirdParty"
  icon?: string;
}

export interface DataFlowEdge {
  source: string;
  target: string;
  protocol: string; // "HTTPS", "WebSocket", "GraphQL", "TCP"
  description: string;
}

export class DataFlowMapping {
  
  /**
   * Construye un mapa de flujo de datos infiriendo la infraestructura y servicios 
   * a partir de las cabeceras HTTP, subdominios y patrones de endpoints.
   */
  public static mapFlow(targetUrl: string, endpoints: string[], headers: Record<string, string> = {}): { nodes: DataFlowNode[], edges: DataFlowEdge[] } {
    const nodes: DataFlowNode[] = [];
    const edges: DataFlowEdge[] = [];

    // 1. Añadir el Cliente siempre (Punto de origen)
    nodes.push({ id: 'client', name: 'User Client', type: 'Client' });

    // 2. Analizar WAF / CDN a partir de headers simulados o reales
    let entryPointId = 'backend';
    const serverHeader = (headers['server'] || '').toLowerCase();
    const viaHeader = (headers['via'] || '').toLowerCase();
    
    if (serverHeader.includes('cloudflare') || viaHeader.includes('cloudflare')) {
      nodes.push({ id: 'waf', name: 'Cloudflare WAF', type: 'WAF' });
      edges.push({ source: 'client', target: 'waf', protocol: 'HTTPS', description: 'Tráfico cifrado a través de WAF' });
      entryPointId = 'waf';
    } else if (serverHeader.includes('awselb') || serverHeader.includes('cloudfront')) {
      nodes.push({ id: 'waf', name: 'AWS CloudFront/ALB', type: 'WAF' });
      edges.push({ source: 'client', target: 'waf', protocol: 'HTTPS', description: 'Tráfico cifrado a través de AWS' });
      entryPointId = 'waf';
    }

    // 3. Añadir el Backend Principal
    nodes.push({ id: 'backend', name: 'Primary Backend API', type: 'Backend' });
    if (entryPointId !== 'backend') {
      edges.push({ source: entryPointId, target: 'backend', protocol: 'HTTPS', description: 'Enrutamiento interno' });
    } else {
      edges.push({ source: 'client', target: 'backend', protocol: 'HTTPS', description: 'Conexión directa a API' });
    }

    // 4. Inferir Base de Datos (Si es un backend típico asume DB)
    nodes.push({ id: 'database', name: 'Primary Database', type: 'Database' });
    edges.push({ source: 'backend', target: 'database', protocol: 'TCP', description: 'Consultas internas (CRUD)' });

    // 5. Detectar integraciones de Terceros basadas en Endpoints (Stripe, Auth0, etc)
    const thirdParties = new Set<string>();
    
    endpoints.forEach(url => {
      const u = url.toLowerCase();
      if (u.includes('stripe')) thirdParties.add('Stripe (Payment Gateway)');
      if (u.includes('auth0')) thirdParties.add('Auth0 (Identity Provider)');
      if (u.includes('sendgrid') || u.includes('email')) thirdParties.add('Email Provider');
      if (u.includes('s3') || u.includes('storage') || u.includes('bucket')) thirdParties.add('Cloud Storage');
    });

    let i = 1;
    thirdParties.forEach(tp => {
      const tpId = `tp_${i++}`;
      nodes.push({ id: tpId, name: tp, type: 'ThirdParty' });
      edges.push({ source: 'backend', target: tpId, protocol: 'HTTPS', description: `Llamada a API Externa (${tp})` });
    });

    return { nodes, edges };
  }
}
