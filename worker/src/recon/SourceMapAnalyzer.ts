import axios from 'axios';
import { ArtifactIntelligenceEngine } from './ArtifactIntelligenceEngine';

export interface SourceMapResult {
  exposedSourceMaps: string[];
  hiddenApiEndpoints: string[];
  hiddenRoutes: string[];
}

export class SourceMapAnalyzer {
  /**
   * Toma los endpoints descubiertos, busca archivos JS históricos en Wayback Machine
   * y los analiza buscando Source Maps y código expuesto.
   */
  public static async runSourceMapAnalysis(endpoints: {url: string, source: string}[]): Promise<SourceMapResult> {
    const result: SourceMapResult = {
      exposedSourceMaps: [],
      hiddenApiEndpoints: [],
      hiddenRoutes: []
    };

    // Filtrar solo los archivos .js o .map de GAU u otros módulos pasivos
    const jsEndpoints = endpoints.filter(e => e.url.endsWith('.js') || e.url.endsWith('.map'));
    
    if (jsEndpoints.length === 0) return result;

    console.log(`[SourceMapAnalyzer] Iniciando análisis histórico de ${jsEndpoints.length} archivos JS en Wayback Machine...`);

    const limit = 5; // Límite de snapshots por archivo para no demorar demasiado
    const maxFilesToProcess = 20; // Límite de archivos JS a procesar para evitar cuellos de botella
    const endpointsToProcess = jsEndpoints.slice(0, maxFilesToProcess);

    for (const endpoint of endpointsToProcess) {
      try {
        const jsUrl = endpoint.url.endsWith('.map') ? endpoint.url.replace(/\.map$/, '') : endpoint.url;
        
        // Consultar CDX API para encontrar snapshots
        const cdxUrl = `http://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(jsUrl)}&output=json&limit=${limit}&fl=timestamp,original`;
        const cdxResponse = await axios.get(cdxUrl, { timeout: 10000 });
        
        if (cdxResponse.status === 200 && Array.isArray(cdxResponse.data) && cdxResponse.data.length > 1) {
          // CDX response: [["timestamp", "original"], ["20230101120000", "http://example.com/main.js"], ...]
          const snapshots = cdxResponse.data.slice(1);
          
          for (const snapshot of snapshots) {
            const timestamp = snapshot[0];
            const originalUrl = snapshot[1];
            
            // Construir URL del snapshot del Source Map en Wayback Machine
            const waybackMapUrl = `https://web.archive.org/web/${timestamp}id_/${originalUrl}.map`;
            
            try {
              const mapRes = await axios.get(waybackMapUrl, { timeout: 5000, maxContentLength: 5 * 1024 * 1024 });
              if (mapRes.status === 200 && mapRes.data && mapRes.data.sources) {
                console.log(`[SourceMapAnalyzer] 🔥 ÉXITO: Source Map histórico recuperado de ${waybackMapUrl}`);
                if (!result.exposedSourceMaps.includes(waybackMapUrl)) {
                  result.exposedSourceMaps.push(waybackMapUrl);
                }
                
                // Extraer rutas de carpetas originales
                const sources: string[] = mapRes.data.sources;
                const internalDirs = new Set(sources.map(s => s.split('/').slice(0, -1).join('/')));
                for (const dir of Array.from(internalDirs)) {
                   if (dir.length > 2 && !dir.includes('node_modules')) {
                       const route = `(SourceMap Histórico) ${dir}`;
                       if (!result.hiddenRoutes.includes(route)) result.hiddenRoutes.push(route);
                   }
                }
              }
            } catch (mapErr) {
              // El map no estaba disponible en esta snapshot
            }
            
            // Opcional: Podríamos descargar también el JS crudo y pasarlo por los Regex de ArtifactIntelligenceEngine
            // Aquí lo dejamos limitado a la recuperación de Source Maps estructurales por rendimiento
          }
        }
      } catch (e: any) {
         // Silently ignore errors for individual endpoints to keep pipeline robust
      }
    }

    console.log(`[SourceMapAnalyzer] Análisis finalizado. Recuperados ${result.exposedSourceMaps.length} source maps históricos.`);
    return result;
  }
}
