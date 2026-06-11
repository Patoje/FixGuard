import axios from 'axios';

export interface ArtifactIntelligence {
  discoveredRoutes: string[];
  hiddenRoutes: string[];
  manifestType?: 'Next.js BuildManifest' | 'React AssetManifest' | 'Vite Manifest' | 'Angular chunks';
}

export class ArtifactIntelligenceEngine {
  static async analyze(targetUrl: string, jsCodes: string[]): Promise<ArtifactIntelligence> {
    const intel: ArtifactIntelligence = {
      discoveredRoutes: [],
      hiddenRoutes: []
    };

    const baseUrl = new URL(targetUrl).origin;

    // 1. Buscar Next.js __BUILD_MANIFEST en los códigos JS (generalmente en _buildManifest.js)
    for (const code of jsCodes) {
      if (code.includes('__BUILD_MANIFEST') || code.includes('sortedPages')) {
        intel.manifestType = 'Next.js BuildManifest';
        
        // Expresión regular para extraer las rutas del array de sortedPages
        // Ejemplo: sortedPages:["/","/api/users","/dashboard"]
        const sortedPagesMatch = code.match(/sortedPages\s*:\s*\[(.*?)\]/);
        if (sortedPagesMatch && sortedPagesMatch[1]) {
          const routes = sortedPagesMatch[1]
            .split(',')
            .map(r => r.trim().replace(/"/g, '').replace(/'/g, ''))
            .filter(r => r.startsWith('/'));
          
          for (const route of routes) {
            if (!intel.discoveredRoutes.includes(route)) {
              intel.discoveredRoutes.push(route);
              if (this.isHiddenOrAdminRoute(route)) intel.hiddenRoutes.push(route);
            }
          }
        }
      }
    }

    // 2. Probar si existe asset-manifest.json (típico de Create React App)
    if (!intel.manifestType) {
      try {
        const response = await axios.get(`${baseUrl}/asset-manifest.json`, { timeout: 3000 });
        if (response.status === 200 && response.data && response.data.files) {
          intel.manifestType = 'React AssetManifest';
          const files = Object.keys(response.data.files);
          for (const file of files) {
            intel.discoveredRoutes.push(`(Asset) ${file}`);
          }
        }
      } catch (e) {}
    }

    return intel;
  }

  private static isHiddenOrAdminRoute(route: string): boolean {
    const p = route.toLowerCase();
    return p.includes('admin') || p.includes('dashboard') || p.includes('test') || 
           p.includes('internal') || p.includes('staging') || p.includes('debug') ||
           p.includes('manage') || p.includes('config') || p.includes('secret');
  }
}
