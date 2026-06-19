import axios from 'axios';

export async function runGauScan(scanId: number, subdomains: string[]): Promise<string[]> {
  if (subdomains.length === 0) return [];

  console.log(`[GAU Fallback] Extrayendo historial de URLs para ${subdomains.length} hosts usando AlienVault OTX...`);
  
  const allUrls = new Set<string>();

  for (const domain of subdomains) {
    try {
      // Usar OTX en lugar de WaybackMachine para evitar timeouts masivos
      const response = await axios.get(`https://otx.alienvault.com/api/v1/indicators/hostname/${domain}/url_list?limit=500`, {
        timeout: 10000,
        headers: {
          'User-Agent': 'FixGuard-Scanner/1.0'
        }
      });

      if (response.data && response.data.url_list) {
        for (const item of response.data.url_list) {
          if (item.url) {
            allUrls.add(item.url);
          }
        }
      }
    } catch (error: any) {
      console.error(`[GAU] Error obteniendo historial para ${domain}:`, error.message);
    }
  }

  const uniqueUrls = Array.from(allUrls);
  console.log(`[GAU] Extraídas ${uniqueUrls.length} URLs históricas únicas.`);
  return uniqueUrls;
}
