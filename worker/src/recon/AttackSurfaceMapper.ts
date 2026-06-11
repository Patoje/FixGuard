import { Wordlists } from './wordlists';

export type RiskLevel = 'CRÍTICO' | 'ALTO' | 'MEDIO' | 'BAJO';

export interface AttackSurfaceItem {
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'WS' | 'ANY';
  riskLevel: RiskLevel;
  type: string;
  // Nuevos campos del Módulo 2: Advanced API Catalog
  params?: string[];
  headers?: string[];
  authType?: string;
  framework?: string;
  relationships?: string[];
}

function calculateRisk(path: string, type: string): RiskLevel {
  const p = path.toLowerCase();
  
  // Exact match or includes checking from wordlists
  if (type.includes('WebSocket') || Wordlists.critical.some(w => p.includes(w.toLowerCase()))) {
    return 'CRÍTICO';
  }
  if (Wordlists.high.some(w => p.includes(w.toLowerCase()))) {
    return 'ALTO';
  }
  if (Wordlists.medium.some(w => p.includes(w.toLowerCase()))) {
    return 'MEDIO';
  }
  // Si parece una ruta dinámica RESTful (ej. /league/pepito o /users/123) tiene riesgo de BOLA/IDOR
  if (p.match(/\/(user|profile|account|order|league|item|product)\/[a-z0-9_-]+/)) {
    return 'MEDIO';
  }
  if (Wordlists.low.some(w => p.includes(w.toLowerCase()))) {
    return 'BAJO';
  }
  return 'BAJO';
}

function determineType(path: string): string {
  const p = path.toLowerCase();
  
  if (p.includes('graphql')) return 'GraphQL Endpoint';
  if (p.includes('socket.io') || p.includes('ws')) return 'WebSocket';
  if (p.includes('api') || p.includes('rest')) return 'REST API';
  if (p.includes('upload') || p.includes('storage') || p.includes('s3')) return 'File Upload / Storage';
  if (Wordlists.critical.some(w => p.includes(w.toLowerCase()))) return 'Ruta Sensible / Admin / Backup';
  if (p.includes('auth') || p.includes('login') || p.includes('oauth') || p.includes('register')) return 'Autenticación';
  if (Wordlists.high.some(w => p.endsWith(w.toLowerCase()))) return 'Archivo de Configuración / Secreto';
  if (p.match(/\/(user|profile|account|order|league|item|product)\/[a-z0-9_-]+/)) return 'Vista Dinámica (Posible BOLA)';
  if (Wordlists.low.some(w => p.includes(w.toLowerCase())) || p.endsWith('.js') || p.endsWith('.css') || p.endsWith('.png') || p.endsWith('.jpg') || p.endsWith('.svg')) return 'Recurso Estático / Config Pública';
  return 'Ruta General';
}

export function runAttackSurfaceMapper(discoveredPaths: string[]): AttackSurfaceItem[] {
  const surface: AttackSurfaceItem[] = [];
  const uniquePaths = Array.from(new Set(discoveredPaths));

  for (const path of uniquePaths) {
    const type = determineType(path);
    const riskLevel = calculateRisk(path, type);
    
    let method: AttackSurfaceItem['method'] = 'ANY';
    if (type === 'WebSocket') method = 'WS';
    else if (type === 'GraphQL Endpoint') method = 'POST';
    else if (type === 'REST API') method = 'ANY'; 
    else if (type === 'Recurso Estático') method = 'GET';
    else if (path.toLowerCase().includes('/api/')) method = 'POST'; // Asumimos que muchas APIs son POST

    const params: string[] = [];
    if (path.includes('?')) {
      const qs = path.split('?')[1];
      const urlParams = new URLSearchParams(qs);
      for (const [key] of urlParams) {
        if (!params.includes(key)) params.push(key);
      }
    }
    
    // Extraer path parameters (ej: /user/123 -> id estimado)
    if (path.match(/\/([a-z0-9_-]+)\/(\d+|[a-f0-9-]{36})(\/|$)/i)) {
      params.push('id_path_param');
    }

    surface.push({ 
      path, 
      method, 
      riskLevel, 
      type,
      params: params.length > 0 ? params : undefined,
      headers: ['User-Agent', 'Accept'], // Default inferred headers
      authType: path.includes('/api/admin') ? 'Bearer/JWT' : 'None',
      framework: path.includes('/_next/') ? 'Next.js' : undefined
    });
  }

  // Sort by risk (CRÍTICO -> ALTO -> MEDIO -> BAJO)
  const riskOrder = { 'CRÍTICO': 1, 'ALTO': 2, 'MEDIO': 3, 'BAJO': 4 };
  return surface.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);
}
