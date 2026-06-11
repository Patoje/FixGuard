import axios from 'axios';
import * as cheerio from 'cheerio';
import { HeadersAnalyzer } from './analyzers/HeadersAnalyzer';
import { CookiesAnalyzer } from './analyzers/CookiesAnalyzer';
import { HtmlAnalyzer } from './analyzers/HtmlAnalyzer';
import { JsAnalyzer } from './analyzers/JsAnalyzer';
import { DnsAnalyzer } from './analyzers/DnsAnalyzer';
import { PlaywrightRuntimeAnalyzer } from './analyzers/PlaywrightRuntimeAnalyzer';
import { TechStackCorrelationEngine } from './TechStackCorrelationEngine';
import type { TechStackItem } from './TechStackItem';



export async function runTechStackProfiler(targetUrl: string): Promise<TechStackItem[]> {
  try {
    const response = await axios.get(targetUrl, { timeout: 10000, validateStatus: () => true });
    const html = typeof response.data === 'string' ? response.data : '';
    const headers = response.headers;
    
    // 1. Analizadores Pasivos (Ultra rápidos)
    const headerFindings = HeadersAnalyzer.analyze(headers);
    const cookieFindings = CookiesAnalyzer.analyze(headers);
    const htmlFindings = HtmlAnalyzer.analyze(html);
    const dnsFindings = await DnsAnalyzer.analyze(new URL(targetUrl).hostname);
    
    // Analizar scripts referenciados superficialmente
    let jsFindings: TechStackItem[] = [];
    const $ = cheerio.load(html);
    const scriptUrls: string[] = [];
    $('script').each((_, el) => {
      const src = $(el).attr('src');
      if (src) scriptUrls.push(src);
    });

    for (const src of scriptUrls) {
      // Simular JS Analyzer con la URL del script (para jQuery, etc.)
      jsFindings = jsFindings.concat(JsAnalyzer.analyze('', src));
    }

    // 2. Analizador Dinámico (El Santo Grial)
    const runtimeFindings = await PlaywrightRuntimeAnalyzer.analyze(targetUrl);

    // 3. Unir todos los hallazgos
    const allFindings = [
      ...headerFindings,
      ...cookieFindings,
      ...htmlFindings,
      ...dnsFindings,
      ...jsFindings,
      ...runtimeFindings
    ];

    // 4. Correlacionar y consolidar
    const finalStack = TechStackCorrelationEngine.correlate(allFindings);

    return finalStack;
  } catch (error) {
    console.error('TechStackProfiler Error:', error);
    return [];
  }
}
