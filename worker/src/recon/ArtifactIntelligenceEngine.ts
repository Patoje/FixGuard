import axios from 'axios';

export interface ArtifactIntelligence {
  discoveredRoutes: string[];
  hiddenRoutes: string[];
  manifestType?: 'Next.js BuildManifest' | 'React AssetManifest' | 'Vite Manifest' | 'Angular chunks';
  exposedSecrets: Array<{ type: string; value: string }>;
  hiddenApiEndpoints: string[];
  exposedSourceMaps: string[];
}

export class ArtifactIntelligenceEngine {
  // Regex patterns para SecretFinder (Prioridad: Precisión Extrema sobre Velocidad)
  private static SECRET_PATTERNS = [
    { type: 'AWS Access Key', regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g },
    { type: 'AWS Secret Key', regex: /(?i)aws_secret_access_key\s*[:=]\s*["']?[0-9a-zA-Z\/+]{40}["']?/g },
    { type: 'Stripe Secret Key', regex: /sk_(live|test)_[0-9a-zA-Z]{24}/g },
    { type: 'Stripe Restricted Key', regex: /rk_(live|test)_[0-9a-zA-Z]{24}/g },
    { type: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g },
    { type: 'Google OAuth Access Token', regex: /ya29\.[0-9A-Za-z\-_]+/g },
    { type: 'Mailgun API Key', regex: /key-[0-9a-zA-Z]{32}/g },
    { type: 'Twilio API Key', regex: /SK[0-9a-fA-F]{32}/g },
    { type: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/g },
    { type: 'Slack Bot Token', regex: /xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/g },
    { type: 'Slack User Token', regex: /xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/g },
    { type: 'GitHub Personal Access Token', regex: /ghp_[0-9a-zA-Z]{36}/g },
    { type: 'GitHub OAuth Access Token', regex: /gho_[0-9a-zA-Z]{36}/g },
    { type: 'Database URI', regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[^\s"']+/g },
    { type: 'JSON Web Token (JWT)', regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
    { type: 'RSA Private Key', regex: /-----BEGIN RSA PRIVATE KEY-----/g },
    { type: 'Generic API Key / Secret', regex: /(?i)(?:api_key|apikey|secret|token|password)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{16,64})["']?/g }
  ];

  // Regex pattern para LinkFinder (simplificado)
  private static LINK_PATTERN = /(?:"|')(\/api\/[a-zA-Z0-9_\-\/]+|\/v[0-9]+\/[a-zA-Z0-9_\-\/]+|https?:\/\/[a-zA-Z0-9_\-\.]+\/api\/[a-zA-Z0-9_\-\/]+)(?:"|')/g;

  static async analyze(targetUrl: string, jsCodes: string[], jsUrls: string[] = []): Promise<ArtifactIntelligence> {
    const intel: ArtifactIntelligence = {
      discoveredRoutes: [],
      hiddenRoutes: [],
      exposedSecrets: [],
      hiddenApiEndpoints: [],
      exposedSourceMaps: []
    };

    const baseUrl = new URL(targetUrl).origin;

    // --- FASE 1: Análisis de Manifests Original ---
    for (const code of jsCodes) {
      if (code.includes('__BUILD_MANIFEST') || code.includes('sortedPages')) {
        intel.manifestType = 'Next.js BuildManifest';
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

    // --- FASE 2: SecretFinder y LinkFinder ---
    console.log(`[ArtifactIntelligence] Escaneando ${jsCodes.length} chunks de JS en busca de secretos y rutas ocultas...`);
    
    // Usaremos un Set para evitar secretos duplicados si aparecen en múltiples chunks
    const foundSecrets = new Set<string>();
    const foundApis = new Set<string>();

    for (const code of jsCodes) {
      // SecretFinder
      for (const pattern of this.SECRET_PATTERNS) {
        let match;
        while ((match = pattern.regex.exec(code)) !== null) {
          const secretValue = match[0];
          const secretKey = `${pattern.type}::${secretValue}`;
          if (!foundSecrets.has(secretKey)) {
            foundSecrets.add(secretKey);
            intel.exposedSecrets.push({ type: pattern.type, value: secretValue });
            // Redactamos una parte del valor en consola para seguridad visual
            const safeLog = secretValue.substring(0, 8) + '***';
            console.log(`[ArtifactIntelligence] 🚨 Peligro: ${pattern.type} encontrado en el código fuente (${safeLog})`);
          }
        }
      }

      // LinkFinder
      let linkMatch;
      while ((linkMatch = this.LINK_PATTERN.exec(code)) !== null) {
        const endpoint = linkMatch[1];
        if (!foundApis.has(endpoint)) {
          foundApis.add(endpoint);
          intel.hiddenApiEndpoints.push(endpoint);
        }
      }
    }

    if (intel.hiddenApiEndpoints.length > 0) {
      console.log(`[ArtifactIntelligence] 🔍 LinkFinder extrajo ${intel.hiddenApiEndpoints.length} endpoints de API ocultos en el código.`);
    }

    // --- FASE 2.5: Detector de Source Maps ---
    // Por cada URL de un chunk JS interceptado, verificamos si existe su versión .map
    for (const jsUrl of jsUrls) {
      if (jsUrl.endsWith('.js')) {
        const sourceMapUrl = `${jsUrl}.map`;
        try {
          // Petición HEAD muy rápida para no descargar megabytes de mapas inútilmente
          const res = await axios.head(sourceMapUrl, { timeout: 3000 });
          if (res.status === 200) {
             console.log(`[ArtifactIntelligence] 🔥 CRÍTICO: Source Map expuesto en ${sourceMapUrl}`);
             intel.exposedSourceMaps.push(sourceMapUrl);
          }
        } catch (e) {
          // Si da 404 o timeout, ignoramos. El desarrollador hizo las cosas bien.
        }
      }
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
