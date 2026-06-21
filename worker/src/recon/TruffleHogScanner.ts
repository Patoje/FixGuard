import { runCliCommand } from '../scanner/cliRunner';
import axios from 'axios';
import * as cheerio from 'cheerio';

export interface TruffleHogFinding {
  repo: string;
  secretType: string;
  detectorName: string;
  raw: string;
}

export class TruffleHogScanner {
  /**
   * Infiere el nombre de la organización de GitHub usando la lógica de fallback especificada:
   * 1. Dominio sin TLD
   * 2. Links a github.com en el HTML del target
   * 3. Menciones de github.com en endpoints de gau
   */
  private static async inferGithubOrg(domain: string, targetUrl: string, endpoints: any[]): Promise<string | null> {
    const domainWithoutTld = domain.split('.')[0];
    
    try {
      // 2. Links a github.com en el HTML
      const response = await axios.get(targetUrl, { timeout: 5000, validateStatus: () => true });
      if (response.status === 200 && typeof response.data === 'string') {
        const $ = cheerio.load(response.data);
        const ghLinks = $('a[href*="github.com/"]').map((i, el) => $(el).attr('href')).get();
        for (const link of ghLinks) {
          const match = link.match(/github\.com\/([a-zA-Z0-9_-]+)/);
          if (match && match[1]) {
            console.log(`[TruffleHogScanner] Inferencia de org exitosa desde HTML: ${match[1]}`);
            return match[1];
          }
        }
      }
    } catch (e) {
      console.warn(`[TruffleHogScanner] Inferencia de org desde HTML falló: ${e.message}`);
    }

    // 3. Menciones en GAU endpoints
    const ghEndpoint = endpoints.find(e => e.url && e.url.includes('github.com/'));
    if (ghEndpoint) {
       const match = ghEndpoint.url.match(/github\.com\/([a-zA-Z0-9_-]+)/);
       if (match && match[1]) {
         console.log(`[TruffleHogScanner] Inferencia de org exitosa desde GAU: ${match[1]}`);
         return match[1];
       }
    }

    // 1. Fallback: Dominio sin TLD
    console.log(`[TruffleHogScanner] Fallback a dominio sin TLD: ${domainWithoutTld}`);
    return domainWithoutTld;
  }

  public static async runTruffleHogGithubScan(domain: string, targetUrl: string, endpoints: any[]): Promise<TruffleHogFinding[]> {
    const org = await this.inferGithubOrg(domain, targetUrl, endpoints);
    
    if (!org) {
      console.log(`[TruffleHogScanner] No se pudo inferir la organización de GitHub para ${domain}. Salteando escaneo.`);
      return [];
    }

    console.log(`[TruffleHogScanner] Iniciando escaneo de secretos en repos públicos de GitHub para la org: ${org}`);
    
    const tokenArg = process.env.GH_TOKEN ? `--token=${process.env.GH_TOKEN}` : '';
    // Ejecutar trufflehog con salida JSON. Solo escanea repositorios públicos si no hay token.
    const command = `trufflehog github --org=${org} ${tokenArg} --json --no-update`;

    try {
      // Pasamos un "targetUrl" dummy para satisfacer la firma de runCliCommand (solo usado si es relativo)
      const output = await runCliCommand(command, `https://${domain}`);
      const findings: TruffleHogFinding[] = [];

      const lines = output.split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);
          if (parsed && parsed.DetectorName) {
            findings.push({
              repo: parsed.Repository || parsed.SourceName || org,
              secretType: parsed.DetectorName,
              detectorName: parsed.DetectorName,
              raw: parsed.Raw || ''
            });
          }
        } catch (parseErr) {
          // Ignorar lineas que no sean JSON válido (banners, logs de info)
        }
      }

      console.log(`[TruffleHogScanner] Finalizado. Secretos encontrados: ${findings.length}`);
      return findings;
    } catch (e: any) {
      console.warn(`[TruffleHogScanner] Error al ejecutar TruffleHog: ${e.message}`);
      return [];
    }
  }
}
