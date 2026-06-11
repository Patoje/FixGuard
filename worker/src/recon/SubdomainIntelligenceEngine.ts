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
  static async discover(domain: string): Promise<SubdomainIntelligence> {
    const intel: SubdomainIntelligence = {
      discoveredCount: 0,
      interestingSubdomains: [],
      allSubdomains: []
    };

    try {
      // Usar crt.sh para buscar certificados TLS registrados para el dominio y sus subdominios
      const response = await axios.get(`https://crt.sh/?q=%.${domain}&output=json`, {
        timeout: 10000
      });

      if (Array.isArray(response.data)) {
        const subdomains = new Set<string>();

        for (const cert of response.data) {
          if (cert.name_value) {
            const names = cert.name_value.split('\n');
            for (let name of names) {
              name = name.trim().toLowerCase();
              if (name && !name.includes('*') && name.endsWith(domain) && name !== domain && name !== `www.${domain}`) {
                subdomains.add(name);
              }
            }
          }
        }

        intel.allSubdomains = Array.from(subdomains);
        intel.discoveredCount = intel.allSubdomains.length;

        // Categorizar subdominios interesantes
        for (const sub of intel.allSubdomains) {
          const type = this.categorizeSubdomain(sub);
          if (type !== 'OTHER') {
            intel.interestingSubdomains.push({ subdomain: sub, type });
          }
        }
      }
    } catch (e) {
      console.warn(`[SubdomainIntelligence] No se pudo consultar crt.sh para ${domain}.`, (e as any).message);
    }

    return intel;
  }

  private static categorizeSubdomain(sub: string): SubdomainIntelligence['interestingSubdomains'][0]['type'] {
    if (sub.includes('staging') || sub.includes('stg')) return 'STAGING';
    if (sub.includes('dev') || sub.includes('qa') || sub.includes('test')) return 'DEV';
    if (sub.includes('api') || sub.includes('graph')) return 'API';
    if (sub.includes('admin') || sub.includes('panel') || sub.includes('backoffice') || sub.includes('manage')) return 'ADMIN';
    if (sub.includes('internal') || sub.includes('corp') || sub.includes('intranet')) return 'INTERNAL';
    return 'OTHER';
  }
}
