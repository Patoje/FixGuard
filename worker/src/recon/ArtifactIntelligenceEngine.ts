import axios from 'axios';
import { ActiveSecretValidator } from './ActiveSecretValidator';

export interface ArtifactIntelligence {
  discoveredRoutes: string[];
  hiddenRoutes: string[];
  manifestType?: 'Next.js BuildManifest' | 'React AssetManifest' | 'Vite Manifest' | 'Angular chunks';
  exposedSecrets: Array<{ 
    type: string; 
    value: string;
    url?: string;
    source?: string;
    isLikelyFalsePositive?: boolean;
    falsePositiveReason?: string;
    verified?: boolean; // true = Activo, false = Revocado, undefined = No comprobable
  }>;
  hiddenApiEndpoints: string[];
  exposedSourceMaps: string[];
  nextJsData?: any; // Para guardar el state extraído
}

export class ArtifactIntelligenceEngine {
  // Regex patterns para SecretFinder (Prioridad: Precisión Extrema sobre Velocidad)
  private static SECRET_PATTERNS = [
    { type: 'AWS Access Key', regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g },
    { type: 'AWS Secret Key', regex: /aws_secret_access_key\s*[:=]\s*["']?[0-9a-zA-Z\/+]{40}["']?/gi },
    { type: 'Stripe Secret Key', regex: /sk_(live|test)_[0-9a-zA-Z]{24}/g },
    { type: 'Stripe Restricted Key', regex: /rk_(live|test)_[0-9a-zA-Z]{24}/g },
    { type: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g },
    { type: 'Google OAuth Access Token', regex: /ya29\.[0-9A-Za-z\-_]+/g },
    { type: 'Mailgun API Key', regex: /key-[0-9a-zA-Z]{32}/g },
    { type: 'Twilio API Key', regex: /SK[0-9a-fA-F]{32}/g },
    { type: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/g },
    { type: 'Slack Bot Token', regex: /xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/g },
    { type: 'Slack User Token', regex: /xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/g },
    { type: 'GitHub Personal Access Token', regex: /ghp_[0-9a-zA-Z]{36}/g },
    { type: 'GitHub OAuth Access Token', regex: /gho_[0-9a-zA-Z]{36}/g },
    { type: 'Database URI', regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[^\s"']+/g },
    { type: 'Stripe Publishable Key', regex: /pk_(live|test)_[0-9a-zA-Z]{24,34}/g },
    { type: 'OpenAI API Key', regex: /sk-[a-zA-Z0-9\-_]{48,}/g },
    { type: 'Anthropic API Key', regex: /sk-ant-[a-zA-Z0-9\-_]{40,}/g },
    { type: 'SendGrid API Key', regex: /SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}/g },
    { type: 'Square Access Token', regex: /sq0atp-[0-9A-Za-z\-_]{22}/g },
    { type: 'Square OAuth Secret', regex: /sq0csp-[0-9A-Za-z\-_]{43}/g },
    { type: 'GitHub App Token', regex: /(ghu|ghs)_[0-9a-zA-Z]{36}/g },
    { type: 'GitLab Personal Access Token', regex: /glpat-[0-9a-zA-Z\-\_]{20}/g },
    { type: 'Mapbox API Key', regex: /pk\.[a-zA-Z0-9]{60,}\.[a-zA-Z0-9]{22}/g },
    { type: 'Sentry DSN', regex: /https:\/\/[a-zA-Z0-9]{32}@([a-zA-Z0-9-]+\.)?sentry\.io\/[0-9]+/g },
    { type: 'Discord Bot Token', regex: /[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}/g },
    { type: 'Discord Webhook', regex: /https:\/\/discord\.com\/api\/webhooks\/[0-9]{18,19}\/[a-zA-Z0-9_-]{68}/g },
    { type: 'Figma Personal Access Token', regex: /figd_[a-zA-Z0-9\-_]{43}/g },
    { type: 'Postman API Key', regex: /PMAK-[a-zA-Z0-9]{59,60}/g },
    { type: 'Supabase URL', regex: /https:\/\/[a-z0-9]{20}\.supabase\.co/g },
    { type: 'JSON Web Token (JWT)', regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
    { type: 'RSA Private Key', regex: /-----BEGIN RSA PRIVATE KEY-----/g },
    { type: 'SSH Private Key', regex: /-----BEGIN OPENSSH PRIVATE KEY-----/g },
    { type: 'PGP Private Block', regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g },
    { type: 'Shopify Access Token', regex: /shpat_[a-fA-F0-9]{32}/g },
    { type: 'Shopify Custom App Token', regex: /shpca_[a-fA-F0-9]{32}/g },
    { type: 'Shopify Shared Secret', regex: /shpss_[a-fA-F0-9]{32}/g },
    { type: 'Hugging Face Token', regex: /hf_[a-zA-Z0-9]{34}/g },
    { type: 'Cloudinary URL', regex: /cloudinary:\/\/[0-9]+:[a-zA-Z0-9\-_]+@[a-zA-Z0-9\-_]+/g },
    { type: 'WhatsApp API Token', regex: /EA[A-Za-z0-9]{10,}/g },
    { type: 'Bitbucket App Password', regex: /[a-zA-Z0-9]{24}/g }, // Generico, requiere contexto
    { type: 'Telegram Bot Token', regex: /[0-9]{9}:[a-zA-Z0-9_-]{35}/g },
    { type: 'Heroku API Key', regex: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g }, // Note: Heroku keys are standard UUIDs, prone to false positives, but keeping for completeness if matched with key names. Will rely on generic fallback if standalone UUIDs.
    { type: 'Mailchimp API Key', regex: /[0-9a-f]{32}-us[0-9]{1,2}/g },
    { type: 'Typeform Personal Access Token', regex: /tfp_[a-zA-Z0-9]{43}_[a-zA-Z0-9]{43}/g },
    { type: 'Databricks Personal Access Token', regex: /dapi[a-h0-9]{32}/g },
    { type: 'Plaid Client ID', regex: /client_id[=:]\s*["'][0-9a-fA-F]{24}["']/g },
    { type: 'Plaid Secret', regex: /secret[=:]\s*["'][0-9a-fA-F]{30}["']/g },
    { type: 'Dynatrace API Token', regex: /dt0c01\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{64}/g },
    { type: 'Fastly Personal Token', regex: /fastly-tok-[a-zA-Z0-9\-_]{32}/g },
    { type: 'Doppler Service Token', regex: /dp\.st\.(?:dev|tst|stg|prd)\.[a-zA-Z0-9]{43}/g },
    { type: 'Npm Access Token', regex: /npm_[a-zA-Z0-9]{36}/g },
    { type: 'PyPI Upload Token', regex: /pypi-[a-zA-Z0-9_-]{164}/g },
    { type: 'Vercel Token', regex: /vercel_[a-zA-Z0-9]{24}/g },
    { type: 'Notion API Key', regex: /secret_[a-zA-Z0-9]{43}/g },
    { type: 'Generic API Key / Secret', regex: /(?:api_key|apikey|secret|token|password|auth_token|access_token|client_secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{16,64})["']?/gi },
    // Generic high-risk strings (will be heavily filtered by entropy and context)
    { type: 'Generic 40-char Hex (Sendbird/AWS/Commit)', regex: /\b[a-fA-F0-9]{40}\b/g },
    { type: 'Generic 32-char Hex (MD5/Algolia/Various)', regex: /\b[a-fA-F0-9]{32}\b/g },
    { type: 'Generic 43-char Base62 (Contentful/Typeform)', regex: /\b[a-zA-Z0-9\-_]{43}\b/g }
  ];

  // Regex pattern para LinkFinder ampliado a Literal Clustering
  private static LINK_PATTERN = /(?:"|')(\/api\/[a-zA-Z0-9_\-\/]+|\/v[0-9]+\/[a-zA-Z0-9_\-\/]+|\/graphql[a-zA-Z0-9_\-\/]*|https?:\/\/[a-zA-Z0-9_\-\.]+\/api\/[a-zA-Z0-9_\-\/]+|[a-zA-Z0-9_\-\/]+\.json)(?:"|')/g;

  /**
   * Calcula la entropía matemática de Shannon para detectar si un string es aleatorio o lenguaje humano.
   */
  private static calculateShannonEntropy(str: string): number {
    const len = str.length;
    if (len === 0) return 0;
    const frequencies: Record<string, number> = {};
    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  static async analyze(targetUrl: string, jsChunks: {code: string, url: string, source: string}[], jsUrls: string[] = []): Promise<ArtifactIntelligence> {
    const intel: ArtifactIntelligence = {
      discoveredRoutes: [],
      hiddenRoutes: [],
      exposedSecrets: [],
      hiddenApiEndpoints: [],
      exposedSourceMaps: []
    };

    const baseUrl = new URL(targetUrl).origin;

    // --- FASE 0.5: Extracción de window.__NEXT_DATA__ (Next.js Introspection) ---
    try {
      const { data: htmlBody } = await axios.get(targetUrl, { timeout: 3000 });
      const nextDataMatch = htmlBody.match(/id="__NEXT_DATA__" type="application\/json">([^<]+)<\/script>/);
      if (nextDataMatch && nextDataMatch[1]) {
        intel.nextJsData = JSON.parse(nextDataMatch[1]);
        console.log(`[ArtifactIntelligence] 💡 Next.js State interceptado (window.__NEXT_DATA__)`);
        
        // Extraer endpoints que puedan estar hardcodeados en el estado inicial de la app
        const stateString = JSON.stringify(intel.nextJsData);
        let linkMatch;
        while ((linkMatch = this.LINK_PATTERN.exec(stateString)) !== null) {
            intel.hiddenApiEndpoints.push(linkMatch[1]);
        }
      }
    } catch (e) {}

    // --- FASE 1: Análisis de Manifests Original ---
    for (const chunk of jsChunks) {
      const code = chunk.code;
      if (code.includes('__BUILD_MANIFEST') || code.includes('sortedPages')) {
        intel.manifestType = 'Next.js BuildManifest';
        const sortedPagesMatch = code.match(/sortedPages\s*:\s*\[(.*?)\]/);
        if (sortedPagesMatch && sortedPagesMatch[1]) {
          const routes = sortedPagesMatch[1]
            .split(',')
            .map(r => r.trim().replace(/"/g, '').replace(/'/g, ''))
            .filter(r => r.startsWith('/'));
          
          for (const route of routes) {
            if (!intel.discoveredRoutes.includes(route)) {
              intel.discoveredRoutes.push(route);
              if (this.isHiddenOrAdminRoute(route)) intel.hiddenRoutes.push(route);
            }
          }
        }
      }
    }

    if (!intel.manifestType) {
      try {
        const response = await axios.get(`${baseUrl}/asset-manifest.json`, { timeout: 3000 });
        if (response.status === 200 && response.data && response.data.files) {
          intel.manifestType = 'React AssetManifest';
          const files = Object.keys(response.data.files);
          for (const file of files) {
            intel.discoveredRoutes.push(`(Asset) ${file}`);
          }
        }
      } catch (e) {}
    }

    // --- FASE 2: SecretFinder y LinkFinder ---
    console.log(`[ArtifactIntelligence] Escaneando ${jsChunks.length} chunks de JS en busca de secretos y rutas ocultas...`);
    
    // Usaremos un Set para evitar secretos duplicados si aparecen en múltiples chunks
    const foundSecrets = new Set<string>();
    const foundApis = new Set<string>();

    for (const chunk of jsChunks) {
      const code = chunk.code;
      // SecretFinder
      for (const pattern of this.SECRET_PATTERNS) {
        let match;
        while ((match = pattern.regex.exec(code)) !== null) {
          let secretValue = match[0];
          // Si el regex tiene un grupo de captura, usamos el grupo en vez del match entero
          if (match.length > 1 && match[1]) {
             secretValue = match[1];
          }
          
          const secretKey = `${pattern.type}::${secretValue}`;
          if (!foundSecrets.has(secretKey)) {
            foundSecrets.add(secretKey);

            // --- FASE 2: Context Analysis ---
            let snippet = "";
            if (match.index !== undefined) {
               snippet = code.substring(Math.max(0, match.index - 30), Math.min(code.length, match.index + secretValue.length + 30)).toLowerCase();
            }
            
            let contextBonus = false;
            let contextPenalty = false;
            if (snippet) {
               if (snippet.includes('api_key') || snippet.includes('token') || snippet.includes('bearer') || snippet.includes('secret') || snippet.includes('authorization') || snippet.includes('password')) {
                   contextBonus = true;
               }
               if (snippet.includes('class=') || snippet.includes('href=') || snippet.includes('src=') || snippet.includes('classname=') || snippet.includes('.png') || snippet.includes('.jpg') || snippet.includes('.svg') || snippet.includes('style=')) {
                   contextPenalty = true;
               }
            }

            // Secondary Validation (Phase 1 Entropy + Dictionary)
            let isLikelyFalsePositive = false;
            let falsePositiveReason = undefined;
            const entropy = this.calculateEntropy(secretValue);
            const dictCheck = this.hasDictionaryWords(secretValue);

            if (pattern.type.includes('Algolia')) {
                if (entropy < 3.8 || secretValue.length !== 32 || !/^[A-Za-z0-9]+$/.test(secretValue)) {
                    isLikelyFalsePositive = true;
                    falsePositiveReason = `Falla validación estricta Algolia (Entropía: ${entropy.toFixed(2)})`;
                }
            } else if (pattern.type.includes('Heroku')) {
                if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(secretValue)) {
                    isLikelyFalsePositive = true;
                    falsePositiveReason = `Falla formato estricto UUID Heroku`;
                }
            } else if (pattern.type.includes('Stripe')) {
                if (!/^(pk_live_|pk_test_|sk_live_|sk_test_)/.test(secretValue) || secretValue.length < 20 || entropy <= 4.0) {
                    isLikelyFalsePositive = true;
                    falsePositiveReason = `Falla validación estricta Stripe (Entropía: ${entropy.toFixed(2)})`;
                }
            } else if (pattern.type.includes('JWT')) {
                if (entropy < 4.5) {
                    isLikelyFalsePositive = true;
                    falsePositiveReason = `Falla validación entropía JWT (Entropía: ${entropy.toFixed(2)})`;
                }
            } else if (pattern.type.includes('AWS')) {
                if (!/^AKIA[A-Z0-9]{16}/.test(secretValue) || entropy <= 3.5) {
                    isLikelyFalsePositive = true;
                    falsePositiveReason = `Falla validación estricta AWS (Entropía: ${entropy.toFixed(2)})`;
                }
            } else if (pattern.type.includes('GitHub')) {
                if (!/^(ghp_|gho_|ghs_|github_pat_)/.test(secretValue) || entropy <= 4.0) {
                    isLikelyFalsePositive = true;
                    falsePositiveReason = `Falla validación estricta GitHub (Entropía: ${entropy.toFixed(2)})`;
                }
            } else if (pattern.type.includes('Generic')) {
                // Generico: Validar si es "unknown_high_entropy" o falso positivo
                if (entropy > 4.2 && secretValue.length > 20 && !dictCheck.hasWords && !/^[A-Z][a-zA-Z0-9]+Id$/.test(secretValue)) {
                    pattern.type = 'unknown_high_entropy';
                } else if (contextBonus && entropy > 3.0 && !dictCheck.hasWords) {
                    // Si el contexto es bueno, bajamos la exigencia de entropía a 3.0
                    pattern.type = 'Contextual Generic Secret';
                } else {
                    isLikelyFalsePositive = true;
                    falsePositiveReason = dictCheck.hasWords ? dictCheck.reason : `Baja entropía para key genérica (${entropy.toFixed(2)})`;
                }
            } else {
                // Cualquier otro tipo, validamos diccionario y entropia basica
                if (dictCheck.hasWords && !contextBonus) {
                    isLikelyFalsePositive = true;
                    falsePositiveReason = dictCheck.reason;
                } else if (entropy < 3.2 && !contextBonus) {
                    isLikelyFalsePositive = true;
                    falsePositiveReason = `Entropía general muy baja (${entropy.toFixed(2)})`;
                }
            }

            // Aplicar penalización estricta por contexto HTML/CSS
            if (contextPenalty && !contextBonus) {
                isLikelyFalsePositive = true;
                falsePositiveReason = `Contexto HTML/CSS detectado (Posible clase o atributo)`;
            }

            // --- FASE 3: Active Validation ---
            let verified: boolean | undefined = undefined;
            if (!isLikelyFalsePositive) {
                const isValid = await ActiveSecretValidator.validate(pattern.type, secretValue);
                if (isValid !== null) verified = isValid;
            }

            intel.exposedSecrets.push({ 
                type: pattern.type, 
                value: secretValue,
                url: chunk.url,
                source: chunk.source,
                isLikelyFalsePositive,
                falsePositiveReason,
                verified
            });

            // Redactamos una parte del valor en consola para seguridad visual
            const safeLog = secretValue.substring(0, 8) + '***';
            console.log(`[ArtifactIntelligence] ${isLikelyFalsePositive ? '⚠️' : '🚨'} ${isLikelyFalsePositive ? 'Posible Falso Positivo' : 'Peligro'}: ${pattern.type} encontrado en el código fuente (${safeLog})`);
          }
        }
      }

      // LinkFinder
      let linkMatch;
      while ((linkMatch = this.LINK_PATTERN.exec(code)) !== null) {
        const endpoint = linkMatch[1];
        if (!foundApis.has(endpoint)) {
          foundApis.add(endpoint);
          intel.hiddenApiEndpoints.push(endpoint);
        }
      }
    }

    if (intel.hiddenApiEndpoints.length > 0) {
      console.log(`[ArtifactIntelligence] 🔍 LinkFinder extrajo ${intel.hiddenApiEndpoints.length} endpoints de API ocultos en el código.`);
    }

    // --- FASE 2.5: Detector y Extractor de Source Maps ---
    // Por cada URL de un chunk JS interceptado, verificamos si existe su versión .map
    for (const jsUrl of jsUrls) {
      if (jsUrl.endsWith('.js')) {
        const sourceMapUrl = `${jsUrl}.map`;
        try {
          // Petición GET con timeout muy corto para intentar leer la propiedad 'sources'
          // En un sistema en producción real pondríamos un límite de tamaño (stream)
          const res = await axios.get(sourceMapUrl, { timeout: 4000, maxContentLength: 5 * 1024 * 1024 }); 
          if (res.status === 200 && res.data && res.data.sources) {
             console.log(`[ArtifactIntelligence] 🔥 CRÍTICO: Source Map expuesto en ${sourceMapUrl} (Revela ${res.data.sources.length} archivos fuente originales)`);
             intel.exposedSourceMaps.push(sourceMapUrl);
             
             // Extraer las rutas de carpetas originales para ver la arquitectura interna (ej: src/controllers, libs/auth)
             const sources: string[] = res.data.sources;
             const internalDirs = new Set(sources.map(s => s.split('/').slice(0, -1).join('/')));
             for (const dir of Array.from(internalDirs)) {
                if (dir.length > 2 && !dir.includes('node_modules')) {
                    intel.hiddenRoutes.push(`(SourceMap Dir) ${dir}`);
                }
             }
          }
        } catch (e) {
          // Si da 404 o timeout, ignoramos. El desarrollador hizo las cosas bien.
        }
      }
    }

    // Limpiar duplicados de endpoints extraídos
    intel.hiddenApiEndpoints = [...new Set(intel.hiddenApiEndpoints)];

    return intel;
  }

  private static calculateEntropy(str: string): number {
    const len = str.length;
    if (len === 0) return 0;
    const frequencies: { [key: string]: number } = {};
    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    for (const key in frequencies) {
      const p = frequencies[key] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  private static hasDictionaryWords(str: string): { hasWords: boolean, reason?: string } {
    // Check for excessive repeating chars (>40%)
    let maxRepeat = 0;
    let currentRepeat = 1;
    for (let i = 1; i < str.length; i++) {
      if (str[i] === str[i-1]) currentRepeat++;
      else {
        if (currentRepeat > maxRepeat) maxRepeat = currentRepeat;
        currentRepeat = 1;
      }
    }
    if (currentRepeat > maxRepeat) maxRepeat = currentRepeat;
    if (str.length > 0 && (maxRepeat / str.length) > 0.4) {
      return { hasWords: true, reason: 'Demasiados caracteres repetidos (>40%)' };
    }

    // Check for camelCase / snake_case that looks like a variable
    if (/^[a-z]{2,}[A-Z][a-z]{2,}([A-Z][a-z]{2,})*$/.test(str) || /^[a-z]{2,}(_[a-z]{2,})+$/.test(str)) {
      return { hasWords: true, reason: 'Patrón de nombre de variable detectado (camelCase/snake_case)' };
    }

    // Check for common Spanish/English programming words
    const commonWords = /(config|overlay|background|commands|focused|element|select|translate|wrapper|transition|function|return|false|true|null|undefined|string|number|boolean|array|object|class|interface|type|window|document|console|default|value|error|warn|info|debug|success|fail|start|stop|init|load|save|read|write|click|hover|change|input|submit|mouse|touch|event|handler|callback|promise|resolve|reject|id|key|name|app|api)/i;
    if (commonWords.test(str)) {
      return { hasWords: true, reason: 'Contiene palabras comunes de código' };
    }

    // Check for simple sequential/keyboard patterns
    if (/123456|abcdef|qwerty|asdfgh/i.test(str)) {
      return { hasWords: true, reason: 'Secuencia de teclado trivial' };
    }

    return { hasWords: false };
  }

  private static isHiddenOrAdminRoute(route: string): boolean {
    const p = route.toLowerCase();
    return p.includes('admin') || p.includes('dashboard') || p.includes('test') || 
           p.includes('internal') || p.includes('staging') || p.includes('debug') ||
           p.includes('manage') || p.includes('config') || p.includes('secret');
  }
}
