import fs from 'fs';
import path from 'path';
import type { NormalizedReconProfile } from '../../db/schema';

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

  static selectPipeline(recon: NormalizedReconProfile, rawVectors: {id: string, command: string}[]): PipelineDecision {
    const decision: PipelineDecision = {
      executionOrder: [],
      mutatedVectors: [],
      disabledModules: [],
      immediateActions: []
    };

    // 1. Detección específica Next.js desde endpoints históricos
    const isNextJs = this.detectNextjsFromEndpoints(recon?.endpoints || []) || recon?.stack?.frontend?.toLowerCase().includes('next');
    
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
    const wordlistPath = this.buildDynamicWordlist(recon.scanId, recon.endpoints);
    if (wordlistPath) {
      decision.wordlistPath = wordlistPath;
    }

    // 4. Lógica de priorización
    if (recon.credentials.some(c => c.type === "jwt_secret")) {
      decision.immediateActions.push("clerk_jwt");
      decision.executionOrder.unshift("clerk_jwt");
    }

    if (recon.subdomains.some(s => s.takeover_candidate)) {
      decision.immediateActions.push("static_takeover");
      decision.executionOrder.unshift("static_takeover");
    }

    const hasSqlHints = recon.stack.database_hints?.some(h => ['mysql', 'postgresql', 'postgres'].includes(h.toLowerCase()));
    if (!hasSqlHints) {
      decision.disabledModules.push("pg_sqli", "pg_blind_sqli", "pg_time_sqli", "sqlmap");
    }

    if (recon.stack.database_hints?.some(h => h.toLowerCase().includes('mongodb'))) {
      decision.executionOrder.push("nosqlmap");
    }

    // 5. Mutación de Vectores
    for (const vector of rawVectors) {
      if (decision.disabledModules.includes(vector.id)) continue;
      
      let mutatedCommand = vector.command;
      const tampersApplied: string[] = [];
      let isMutated = false;

      // Inyectar evasiones
      if (mutatedCommand.includes('sqlmap') && wafProfile.sqlmap_tampers.length > 0) {
        mutatedCommand += ` --tamper=${wafProfile.sqlmap_tampers.join(',')}`;
        tampersApplied.push(...wafProfile.sqlmap_tampers);
        isMutated = true;
      }

      if (mutatedCommand.includes('dalfox') && wafProfile.dalfox_flags.length > 0) {
        mutatedCommand += ` ${wafProfile.dalfox_flags.join(' ')}`;
        isMutated = true;
      }

      if (mutatedCommand.includes('nuclei') && wafProfile.nuclei_flags.length > 0) {
        mutatedCommand += ` ${wafProfile.nuclei_flags.join(' ')}`;
        // Surgical Nuclei if next.js detected
        if (isNextJs && mutatedCommand.includes('-u <TARGET>')) {
           // We might want to add -tags nextjs if not already specified
        }
        isMutated = true;
      }

      if (mutatedCommand.includes('ffuf') && decision.wordlistPath) {
        // Reemplazar wordlist estática
        mutatedCommand = mutatedCommand.replace(/-w\s+[^\s]+/, `-w ${decision.wordlistPath}`);
        if (wafProfile.ffuf_flags.length > 0) {
          mutatedCommand += ` ${wafProfile.ffuf_flags.join(' ')}`;
        }
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

  private static buildDynamicWordlist(scanId: number, endpoints: {url: string, source: string}[]): string | null {
    if (!endpoints || endpoints.length === 0) return null;

    const paths = endpoints.map(e => {
      try { return new URL(e.url).pathname }
      catch { return null }
    }).filter(Boolean) as string[];

    if (paths.length === 0) return null;

    // Frecuencia
    const frequency = paths.reduce((acc, path) => {
      acc[path] = (acc[path] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    // Únicos y ordenados por frecuencia (descendente)
    const unique = [...new Set(paths)].sort((a, b) => (frequency[b] || 0) - (frequency[a] || 0));

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
