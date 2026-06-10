export type RiskLevel = 'CRÍTICO' | 'ALTO' | 'MEDIO' | 'BAJO';

export interface AttackSurfaceItem {
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'WS' | 'ANY';
  riskLevel: RiskLevel;
  type: string;
}

function calculateRisk(path: string, type: string): RiskLevel {
  const p = path.toLowerCase();
  
  if (p.includes('admin') || p.includes('graphql') || type.includes('WebSocket')) {
    return 'CRÍTICO';
  }
  if (p.includes('auth') || p.includes('login') || p.includes('upload') || p.includes('users') || p.includes('payment')) {
    return 'ALTO';
  }
  if (p.includes('api')) {
    return 'MEDIO';
  }
  return 'BAJO';
}

function determineType(path: string): string {
  const p = path.toLowerCase();
  if (p.includes('graphql')) return 'GraphQL Endpoint';
  if (p.includes('socket.io') || p.includes('ws')) return 'WebSocket';
  if (p.includes('api')) return 'REST API';
  if (p.includes('upload')) return 'File Upload';
  if (p.includes('admin')) return 'Panel de Administración';
  if (p.includes('auth') || p.includes('login') || p.includes('oauth')) return 'Autenticación';
  if (p.endsWith('.js') || p.endsWith('.css') || p.endsWith('.png') || p.endsWith('.jpg')) return 'Recurso Estático';
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
    else if (type === 'REST API') method = 'ANY'; // Could be GET/POST
    else if (type === 'Recurso Estático') method = 'GET';
    
    surface.push({ path, method, riskLevel, type });
  }

  // Sort by risk (CRÍTICO -> ALTO -> MEDIO -> BAJO)
  const riskOrder = { 'CRÍTICO': 1, 'ALTO': 2, 'MEDIO': 3, 'BAJO': 4 };
  return surface.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);
}
