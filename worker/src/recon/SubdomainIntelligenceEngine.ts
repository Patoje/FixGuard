import axios from 'axios';

export interface SubdomainIntelligence {
  discoveredCount: number;
  interestingSubdomains: Array<{
    subdomain: string;
    type: 'STAGING' | 'DEV' | 'API' | 'ADMIN' | 'INTERNAL' | 'OTHER';
  }>;
  allSubdomains: string[];
}

export class SubdomainIntelligenceEngine {
  // Configuración para simular un navegador real y evitar bloqueos básicos
  private static axiosConfig = {
    timeout: 15000, // Timeout más alto como pediste, no importa si tarda
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
  };

  static async discover(domain: string): Promise<SubdomainIntelligence> {
    const intel: SubdomainIntelligence = {
      discoveredCount: 0,
      interestingSubdomains: [],
      allSubdomains: []
    };

    const subdomains = new Set<string>();
    console.log(`[SubdomainIntelligence] Lanzando motores OSINT concurrentes para ${domain}...`);

    // Ejecutar todas las fuentes en paralelo. Si una falla, no frena a las demás.
    const results = await Promise.allSettled([
      this.fetchCrtSh(domain),
      this.fetchHackerTarget(domain),
      this.fetchAlienVault(domain)
    ]);

    // Recolectar resultados exitosos
    results.forEach((result, index) => {
      const sourceName = ['crt.sh', 'HackerTarget', 'AlienVault'][index];
      if (result.status === 'fulfilled') {
        const found = result.value;
        console.log(`[SubdomainIntelligence] ✅ ${sourceName} encontró ${found.length} subdominios.`);
        found.forEach(sub => subdomains.add(sub));
      } else {
        console.warn(`[SubdomainIntelligence] ⚠️ ${sourceName} falló: ${result.reason.message}`);
      }
    });

    intel.allSubdomains = Array.from(subdomains).sort();
    intel.discoveredCount = intel.allSubdomains.length;

    // Categorizar subdominios interesantes
    for (const sub of intel.allSubdomains) {
      const type = this.categorizeSubdomain(sub);
      if (type !== 'OTHER') {
        intel.interestingSubdomains.push({ subdomain: sub, type });
      }
    }

    return intel;
  }

  /**
   * Fuente 1: crt.sh (Certificados SSL)
   */
  private static async fetchCrtSh(domain: string): Promise<string[]> {
    const found: string[] = [];
    try {
      const response = await axios.get(`https://crt.sh/?q=%.${domain}&output=json`, this.axiosConfig);
      if (Array.isArray(response.data)) {
        for (const cert of response.data) {
          if (cert.name_value) {
            const names = cert.name_value.split('\n');
            for (let name of names) {
              name = this.cleanSubdomain(name, domain);
              if (name) found.push(name);
            }
          }
        }
      }
    } catch (error) {
      throw new Error('Fallo en conexión o timeout');
    }
    return found;
  }

  /**
   * Fuente 2: HackerTarget (DNS Pasivo)
   */
  private static async fetchHackerTarget(domain: string): Promise<string[]> {
    const found: string[] = [];
    try {
      const response = await axios.get(`https://api.hackertarget.com/hostsearch/?q=${domain}`, this.axiosConfig);
      // Retorna CSV: subdomain,ip
      const lines = response.data.split('\n');
      for (const line of lines) {
        const parts = line.split(',');
        if (parts.length > 0) {
          const name = this.cleanSubdomain(parts[0], domain);
          if (name) found.push(name);
        }
      }
    } catch (error) {
      throw new Error('Fallo en conexión o límite de API superado');
    }
    return found;
  }

  /**
   * Fuente 3: AlienVault OTX (Threat Intelligence)
   */
  private static async fetchAlienVault(domain: string): Promise<string[]> {
    const found: string[] = [];
    try {
      const response = await axios.get(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`, this.axiosConfig);
      if (response.data && Array.isArray(response.data.passive_dns)) {
        for (const record of response.data.passive_dns) {
          if (record.hostname) {
            const name = this.cleanSubdomain(record.hostname, domain);
            if (name) found.push(name);
          }
        }
      }
    } catch (error) {
      throw new Error('Fallo en conexión o timeout');
    }
    return found;
  }

  /**
   * Limpia y valida el subdominio
   */
  private static cleanSubdomain(sub: string, domain: string): string | null {
    let clean = sub.trim().toLowerCase();
    // Eliminar wildcards
    if (clean.startsWith('*.')) clean = clean.substring(2);
    
    // Validar que realmente sea un subdominio válido del dominio principal
    if (clean && 
        clean.endsWith(domain) && 
        clean !== domain && 
        clean !== `www.${domain}` &&
        !clean.includes(' ')) {
      return clean;
    }
    return null;
  }

  private static categorizeSubdomain(sub: string): SubdomainIntelligence['interestingSubdomains'][0]['type'] {
    if (sub.includes('staging') || sub.includes('stg')) return 'STAGING';
    if (sub.includes('dev') || sub.includes('qa') || sub.includes('test') || sub.includes('sandbox')) return 'DEV';
    if (sub.includes('api') || sub.includes('graph') || sub.includes('rest')) return 'API';
    if (sub.includes('admin') || sub.includes('panel') || sub.includes('backoffice') || sub.includes('manage') || sub.includes('cms')) return 'ADMIN';
    if (sub.includes('internal') || sub.includes('corp') || sub.includes('intranet') || sub.includes('vpn')) return 'INTERNAL';
    return 'OTHER';
  }
}
