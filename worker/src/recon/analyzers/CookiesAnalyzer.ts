import type { TechStackItem } from '../TechStackItem';

export class CookiesAnalyzer {
  static analyze(headers: Record<string, string | string[]>): TechStackItem[] {
    const findings: TechStackItem[] = [];
    const setCookie = headers['set-cookie'] || [];
    const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];

    const add = (name: string, category: TechStackItem['category'], confidence: number, evidence: string, role: string) => {
      findings.push({ name, category, confidence, evidence: [evidence], role });
    };

    const cookiesStr = cookies.join(';');

    if (cookiesStr.includes('PHPSESSID')) {
      add('PHP', 'Backend Framework', 95, 'PHPSESSID cookie', 'Procesador Backend');
    }
    if (cookiesStr.includes('JSESSIONID')) {
      add('Java', 'Backend Framework', 95, 'JSESSIONID cookie', 'Backend Language');
    }
    if (cookiesStr.includes('.AspNetCore') || cookiesStr.includes('ASP.NET_SessionId')) {
      add('ASP.NET', 'Backend Framework', 95, 'ASP.NET session cookie', 'Web Framework Microsoft');
    }
    if (cookiesStr.includes('XSRF-TOKEN') || cookiesStr.includes('laravel_session')) {
      add('Laravel', 'Backend Framework', 95, 'Laravel specific cookies', 'Framework PHP');
    }
    if (cookiesStr.includes('AWSELB') || cookiesStr.includes('AWSALB')) {
      add('AWS ELB', 'Hosting / Infrastructure', 95, 'AWS Load Balancer cookie', 'Balanceador de Carga');
    }

    return findings;
  }
}
