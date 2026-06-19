import axios from 'axios';

export interface HttpxResult {
  url: string;
  statusCode: number;
  title: string;
  webServer?: string;
  technologies: string[];
  cdn?: string;
}

export async function runHttpxScan(scanId: number, subdomains: string[]): Promise<HttpxResult[]> {
  if (subdomains.length === 0) return [];
  console.log(`[HTTPX Native Fallback] Escaneando ${subdomains.length} subdominios vivos...`);

  const results: HttpxResult[] = [];
  
  // Analizar en paralelo con límite de concurrencia
  const chunkSize = 10;
  for (let i = 0; i < subdomains.length; i += chunkSize) {
    const chunk = subdomains.slice(i, i + chunkSize);
    
    await Promise.all(chunk.map(async (domain) => {
      const targetUrl = domain.startsWith('http') ? domain : `https://${domain}`;
      try {
        const response = await axios.get(targetUrl, {
          timeout: 5000,
          validateStatus: () => true, // resolve for all status codes
          headers: {
            'User-Agent': 'FixGuard-Scanner/1.0'
          }
        });

        // Extraer título básico
        let title = '';
        if (typeof response.data === 'string') {
          const match = response.data.match(/<title>([^<]*)<\/title>/i);
          if (match) title = match[1].trim();
        }

        const serverHeader = (response.headers['server'] || '').toString();
        const technologies: string[] = [];
        let cdn = '';

        if (serverHeader.toLowerCase().includes('cloudflare') || !!response.headers['cf-ray']) {
          technologies.push('Cloudflare');
          cdn = 'Cloudflare';
        }
        if (response.headers['x-vercel-id']) {
          technologies.push('Vercel');
          cdn = 'Vercel';
        }
        
        if (serverHeader) {
          technologies.push(serverHeader);
        }

        results.push({
          url: targetUrl,
          statusCode: response.status,
          title,
          webServer: serverHeader,
          technologies,
          cdn
        });
      } catch (e) {
        // Ignorar si el host no responde
      }
    }));
  }

  console.log(`[HTTPX] Detectados ${results.length} hosts vivos.`);
  return results;
}
