import fs from 'fs';
import path from 'path';
import type { NormalizedReconProfile } from '../../db/schema';
import { filterInScope } from '../../utils/scope';

export interface MutatedVector {
  id: string;
  originalCommand: string;
  mutatedCommand: string;
  tamperApplied: boolean;
  tamperNames: string[];
}

export interface PipelineDecision {
  executionOrder: string[];
  mutatedVectors: MutatedVector[];
  disabledModules: string[];
  immediateActions: string[];
  wordlistPath?: string;
}

const WAF_EVASION_PROFILES: Record<string, any> = {
  "cloudflare": {
    sqlmap_tampers: ["space2comment", "between", "charencode", "randomcase"],
    dalfox_flags: ["--skip-bav", "--waf-evasion"],
    nuclei_flags: ["-H", "X-Forwarded-For: 127.0.0.1"],
    ffuf_flags: ["-H", "X-Originating-IP: 127.0.0.1", "-rate", "10"]
  },
  "modsecurity": {
    sqlmap_tampers: ["apostrophemask", "equaltolike", "greatest", "ifnull2ifisnull"],
    dalfox_flags: ["--waf-evasion"],
    nuclei_flags: [],
    ffuf_flags: ["-rate", "20"]
  },
  "aws": {
    sqlmap_tampers: ["space2comment", "charencode"],
    dalfox_flags: ["--waf-evasion"],
    nuclei_flags: [],
    ffuf_flags: ["-rate", "15"]
  },
  "none": {
    sqlmap_tampers: [],
    dalfox_flags: [],
    nuclei_flags: [],
    ffuf_flags: ["-rate", "100"]
  }
};

export class PipelineSelector {

  static detectPipelineType(recon: NormalizedReconProfile): 'modern_spa' | 'legacy' {
    const stackFrontend = recon?.stack?.frontend?.toLowerCase() || '';
    const stackRuntime = recon?.stack?.runtime?.toLowerCase() || '';
    const hasLegacyStackHint = stackFrontend.includes('wordpress') || stackRuntime.includes('php') || stackRuntime.includes('apache') || stackRuntime.includes('nginx');
    const hasLegacyEndpoints = recon?.endpoints?.some(e => {
       const urlLower = e.url.toLowerCase();
       return urlLower.includes('.php') || urlLower.includes('.asp') || urlLower.includes('.aspx') || urlLower.includes('.jsp') || urlLower.includes('.cfm') || urlLower.includes('.cgi') || urlLower.includes('/wp-content/') || urlLower.includes('/wp-admin/') || urlLower.includes('/wp-json/');
    });

    return (hasLegacyStackHint || hasLegacyEndpoints) ? 'legacy' : 'modern_spa';
  }

  static selectPipeline(recon: NormalizedReconProfile, rawVectors: {id: string, command: string}[]): PipelineDecision {
    const decision: PipelineDecision = {
      executionOrder: [],
      mutatedVectors: [],
      disabledModules: [],
      immediateActions: []
    };

    // 1. Detección específica Next.js desde endpoints históricos
    const isNextJs = this.detectNextjsFromEndpoints(recon?.endpoints || []) || recon?.stack?.frontend?.toLowerCase().includes('next');
    
    // 1.5 Detección Legacy (PHP, WordPress, Apache, Nginx, .php, .asp, .aspx)
    recon.stack.pipeline = this.detectPipelineType(recon);

    // 2. WAF Profile
    const wafName = recon.stack.waf?.toLowerCase() || 'none';
    let wafProfile = WAF_EVASION_PROFILES['none'];
    
    for (const key of Object.keys(WAF_EVASION_PROFILES)) {
      if (wafName.includes(key)) {
        wafProfile = WAF_EVASION_PROFILES[key];
        break;
      }
    }

    // 3. Wordlist dinámica
    const wordlistPath = this.buildDynamicWordlist(recon);
    if (wordlistPath) {
      decision.wordlistPath = wordlistPath;
    }

    // 4. Lógica de priorización
    if (recon.credentials.some(c => c.type === "jwt_secret")) {
      decision.immediateActions.push("clerk_jwt", "jwt_tool");
      decision.executionOrder.unshift("clerk_jwt", "jwt_tool");
    }

    if (recon.subdomains.some(s => s.takeover_candidate)) {
      decision.immediateActions.push("static_takeover");
      decision.executionOrder.unshift("static_takeover");
    }

    const hasSqlHints = recon.stack.database_hints?.some(h => ['mysql', 'postgresql', 'postgres'].includes(h.toLowerCase()));
    if (!hasSqlHints && recon.stack.pipeline !== 'legacy') { // Keep SQLi for legacy as it's common
      decision.disabledModules.push("pg_sqli", "pg_blind_sqli", "pg_time_sqli", "sqlmap");
    } else if (hasSqlHints) {
      // If we have SQL hints, disable NoSQL
      decision.disabledModules.push("nosql_injection");
    }

    if (recon.stack.database_hints?.some(h => h.toLowerCase().includes('mongodb') || h.toLowerCase().includes('couchdb'))) {
      decision.executionOrder.push("nosql_injection");
    }

    // 5. Mutación de Vectores
    for (const vector of rawVectors) {
      if (decision.disabledModules.includes(vector.id)) continue;
      
      let mutatedCommand = vector.command;
      const tampersApplied: string[] = [];
      let isMutated = false;

      // Inyectar evasiones (sqlmap y legacy php sqlmap)
      if (mutatedCommand.includes('sqlmap') && wafProfile.sqlmap_tampers.length > 0) {
        mutatedCommand += ` --tamper=${wafProfile.sqlmap_tampers.join(',')}`;
        tampersApplied.push(...wafProfile.sqlmap_tampers);
        isMutated = true;
      }

      if (mutatedCommand.includes('dalfox') && wafProfile.dalfox_flags.length > 0) {
        mutatedCommand += ` ${wafProfile.dalfox_flags.join(' ')}`;
        isMutated = true;
      }

      // Surgical Nuclei
      if (mutatedCommand.includes('nuclei')) {
        if (wafProfile.nuclei_flags.length > 0) {
          mutatedCommand += ` ${wafProfile.nuclei_flags.join(' ')}`;
        }
        
        const tags = this.extractNucleiTags(recon);
        if (tags.length > 0) {
           mutatedCommand += ` -tags ${tags.join(',')}`;
        } else {
           mutatedCommand += ` -tags cve,misconfig,exposure`;
        }
        isMutated = true;
      }
      
      // Multi-host Katana and Corsy
      if (mutatedCommand.includes('katana') || mutatedCommand.includes('corsy')) {
         const hostsPath = this.buildLiveHostsList(recon.scanId, recon.subdomains);
         if (hostsPath) {
            if (mutatedCommand.includes('katana')) {
                mutatedCommand = mutatedCommand.replace(/-u\s+<TARGET>/, `-list ${hostsPath}`);
            } else if (mutatedCommand.includes('corsy')) {
                mutatedCommand = mutatedCommand.replace(/-u\s+<TARGET>/, `-i ${hostsPath}`);
            }
            isMutated = true;
         }
      }

      // WPScan Enum Env Token Injection
      if (vector.id === 'wpscan_enum') {
         if (process.env.WPSCAN_API_TOKEN) {
             mutatedCommand += ` --api-token ${process.env.WPSCAN_API_TOKEN}`;
             isMutated = true;
         }
      }

      // JWT Secret Brute-forcing
      if (mutatedCommand.includes('jwt_tool')) {
         const jwtCred = recon.credentials.find(c => c.type === 'jwt_secret');
         if (jwtCred && jwtCred.password) {
            mutatedCommand += ` --secret "${jwtCred.password}"`;
            isMutated = true;
         }
      }

      if (mutatedCommand.includes('ffuf')) {
        const ext = recon.stack.pipeline === 'legacy' ? '.php,.asp,.aspx,.config,.bak' : '.json,.js,.map';
        
        if (vector.id === 'ffuf_dir' || mutatedCommand.includes('/FUZZ')) {
          mutatedCommand = `ffuf -u <TARGET>/FUZZ -w /tmp/fixguard_wordlist_${recon.scanId}.txt -ac -mc 200,201,204,301,302,307,401,403,405 -fc 404 -fs 0 -H "X-Originating-IP: 127.0.0.1" -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" -rate 10 -timeout 10 -recursion -recursion-depth 2 -e ${ext} -o /tmp/ffuf_${recon.scanId}.json -of json`;
        } else {
          // Keep the original base command (like lfi_fuzzer) but append the output formatting
          mutatedCommand += ` -o /tmp/ffuf_${recon.scanId}.json -of json`;
        }
        
        if (wafProfile.ffuf_flags.length > 0) {
          mutatedCommand += ` ${wafProfile.ffuf_flags.join(' ')}`;
        }
        isMutated = true;
      }

      if (mutatedCommand.includes('nuclei')) {
        const tags = this.extractNucleiTags(recon);
        const tagsStr = tags.length > 0 ? tags.join(',') : 'generic';
        mutatedCommand = `nuclei -u <TARGET> -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" -tags ${tagsStr} -severity low,medium,high,critical -etags dos -rl 10 -timeout 10 -retries 2 -no-interactsh -j -o /tmp/nuclei_${recon.scanId}.json`;
        isMutated = true;
      }

      decision.mutatedVectors.push({
        id: vector.id,
        originalCommand: vector.command,
        mutatedCommand,
        tamperApplied: tampersApplied.length > 0,
        tamperNames: tampersApplied
      });
      
      if (!decision.executionOrder.includes(vector.id)) {
        decision.executionOrder.push(vector.id);
      }
    }

    return decision;
  }

  private static detectNextjsFromEndpoints(endpoints: {url: string}[]): boolean {
    const nextjsPattern = endpoints.find(e => 
      e.url.includes('/_next/static/') || 
      e.url.includes('/_next/data/')
    );
    return !!nextjsPattern;
  }

  private static extractNucleiTags(recon: NormalizedReconProfile): string[] {
    const tags = new Set<string>();
    
    // Add explicitly detected stack
    Object.values(recon.stack).forEach(val => {
       if (typeof val === 'string' && val) tags.add(val.toLowerCase().replace(/[^a-z0-9]/g, ''));
       if (Array.isArray(val)) {
          val.forEach(v => tags.add(typeof v === 'string' ? v.toLowerCase().replace(/[^a-z0-9]/g, '') : ''));
       }
    });

    // Clean up empty tags
    tags.delete('');
    
    // Map known tech to standard nuclei tags
    const mappedTags = Array.from(tags).map(t => {
       if (t.includes('react')) return 'react';
       if (t.includes('next')) return 'nextjs';
       if (t.includes('node')) return 'nodejs';
       if (t.includes('php')) return 'php';
       if (t.includes('apache')) return 'apache';
       if (t.includes('nginx')) return 'nginx';
       if (t.includes('wordpress')) return 'wordpress';
       if (t.includes('laravel')) return 'laravel';
       if (t.includes('django')) return 'django';
       return t;
    });

    return [...new Set(mappedTags)].slice(0, 5); // Limit to top 5 tags to prevent command overload
  }

  private static buildLiveHostsList(scanId: number, subdomains: {subdomain: string, is_alive: boolean}[]): string | null {
     if (!subdomains || subdomains.length === 0) return null;
     
     const liveHosts = subdomains.filter(s => s.is_alive).map(s => `https://${s.subdomain}`);
     if (liveHosts.length === 0) return null;

     const tempFilePath = path.join('/tmp', `fixguard_hosts_${scanId}.txt`);
     try {
       fs.writeFileSync(tempFilePath, liveHosts.join('\n'));
       return tempFilePath;
     } catch (e) {
       console.error("Error creating Katana hosts list:", e);
       return null;
     }
  }

  private static buildDynamicWordlist(recon: NormalizedReconProfile): string | null {
    const scanId = recon.scanId;
    const endpoints = recon.endpoints;
    const targetUrl = recon.target;
    
    const fallbackPaths = ['/.env', '/admin', '/login', '/api', '/swagger', '/graphql', '/config.json', '/.git/config'];
    let paths: string[] = [];
    
    // 1. Recolectar rutas descubiertas dinámicamente
    if (endpoints && endpoints.length > 0) {
      const urls = endpoints.map(e => e.url);
      const { inScope, filtered } = filterInScope(urls, targetUrl);
      if (filtered > 0) {
         console.log(`[PipelineSelector] Wordlist dinámica: ${filtered} URLs fuera de scope eliminadas.`);
      }
      paths = inScope.map(u => {
        try { return new URL(u).pathname }
        catch { return null }
      }).filter(Boolean) as string[];
    }

    // Frecuencia y pesos por source
    const weights = paths.reduce((acc, p, index) => {
      const source = endpoints?.[index]?.source || 'fallback';
      const baseWeight = source === 'sourcemapper' ? 1000 : 1; // Priorizar sourcemapper masivamente
      acc[p] = (acc[p] || 0) + baseWeight;
      return acc;
    }, {} as Record<string, number>);

    // Únicos y ordenados por peso/frecuencia (descendente)
    let unique = [...new Set(paths)].sort((a, b) => (weights[b] || 0) - (weights[a] || 0));
    
    // 2. Inyección Inteligente Basada en Fingerprint (Diccionarios de Alta Calidad)
    const baseWordlistsDir = path.resolve(process.cwd(), 'wordlists');
    const injectWordlist = (category: string, filename: string) => {
        const filePath = path.join(baseWordlistsDir, category, filename);
        if (fs.existsSync(filePath)) {
            const content = fs.readFileSync(filePath, 'utf-8');
            const lines = content.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
            // Agregar con un peso alto artificial para que queden arriba o intermedios
            unique = [...new Set([...unique, ...lines])];
        }
    };

    // Siempre inyectar el Core
    injectWordlist('core', 'raft-small-directories.txt');
    injectWordlist('core', 'api-endpoints.txt');
    injectWordlist('core', 'common.txt');
    injectWordlist('core', 'trickest-directories.txt');

    // Analizar el Stack y decidir qué más inyectar
    const pipeline = recon.stack.pipeline || 'modern_spa';
    const isNextJs = recon.stack.frontend?.toLowerCase().includes('next') || false;
    const isExpress = recon.stack.runtime?.toLowerCase().includes('node') || false;
    const isWp = recon.stack.frontend?.toLowerCase().includes('wordpress') || false;

    if (pipeline === 'legacy') {
        injectWordlist('legacy', 'PHP.txt');
        injectWordlist('legacy', 'cgis.txt');
        injectWordlist('legacy', 'IIS.txt');
        injectWordlist('legacy', 'fuzzdb-cgi-bin.txt');
    }

    if (pipeline === 'modern_spa' || isExpress || isNextJs) {
        injectWordlist('modern', 'graphql.txt');
        injectWordlist('modern', 'swagger.txt');
        injectWordlist('modern', 'api-metrics.txt');
        injectWordlist('modern', 'assetnote-httparchive.txt');
        injectWordlist('modern', 'trickest-api.txt');
    }

    if (isWp) {
        injectWordlist('cms', 'wp-plugins.txt');
        injectWordlist('cms', 'wp-themes.txt');
        injectWordlist('cms', 'trickest-wordpress.txt');
    }

    // Si aún así no hay nada (falla de lectura o algo), usar fallbacks tontos
    if (unique.length === 0) {
       unique = fallbackPaths;
    }

    const tempFilePath = path.join('/tmp', `fixguard_wordlist_${scanId}.txt`);
    try {
      fs.writeFileSync(tempFilePath, unique.join('\n'));
      return tempFilePath;
    } catch(e) {
      console.error("[PipelineSelector] Error writing dynamic wordlist", e);
      return null;
    }
  }

}
