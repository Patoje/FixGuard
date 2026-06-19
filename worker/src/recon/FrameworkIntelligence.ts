import type { TechStackItem } from './TechStackItem';

export interface VectorItem {
  id: string;
  name: string;
  cliCommand: string;
}

export interface FrameworkVector {
  framework: string;
  vectors: VectorItem[];
}

export function runFrameworkIntelligence(techStack: TechStackItem[]): FrameworkVector[] {
  const intelligence: FrameworkVector[] = [];
  const stackNames = techStack.map(t => t.name.toLowerCase());

  // Deep Recon, Network & Subdomains (Always on)
  intelligence.push({
    framework: 'Reconocimiento Profundo',
    vectors: [
      { id: 'deep_katana', name: 'Crawling Avanzado JS/DOM', cliCommand: 'katana -u <TARGET> -d 5 -jc -kf' },
      { id: 'deep_gau', name: 'Historial GAU (Wayback/AlienVault)', cliCommand: 'gau <TARGET>' },
      { id: 'deep_trufflehog', name: 'Búsqueda de API Keys (Trufflehog)', cliCommand: 'trufflehog --no-update filesystem <TARGET>' }
    ]
  });

  intelligence.push({
    framework: 'Network & Infrastructure',
    vectors: [
      { id: 'nmap_full', name: 'Escaneo de Puertos Total', cliCommand: 'nmap -sV -sC -Pn -T4 -p- <TARGET>' },
      { id: 'subfinder_enum', name: 'Enumeración de Subdominios', cliCommand: 'subfinder -d <TARGET> -all' }
    ]
  });

  // Si detectamos Next.js explícitamente, o si está en Vercel (que casi siempre implica Next.js),
  // mostramos los vectores de Next.js.
  if (stackNames.includes('next.js') || stackNames.includes('vercel') || stackNames.includes('react')) {
    intelligence.push({
      framework: 'Next.js',
      vectors: [
        { id: 'nextjs_bfla', name: 'Server Actions (BFLA/IDOR)', cliCommand: 'nuclei -t http/exposed-panels/ -t http/misconfiguration/ -u <TARGET>' },
        { id: 'nextjs_middleware', name: 'Middleware bypass', cliCommand: 'curl -H "x-middleware-prefetch: 1" <TARGET>/admin' },
        { id: 'nextjs_api', name: 'API Routes exposure', cliCommand: 'ffuf -s -ac -w ./wordlists/api_wordlist.txt -u <TARGET>/FUZZ' },
        { id: 'nextjs_build_data', name: 'Build Data (_next/data)', cliCommand: 'nuclei -id nextjs-data-leak -u <TARGET>' },
        { id: 'nextjs_static', name: 'Static Assets', cliCommand: 'nuclei -id nextjs-static-leak -u <TARGET>' },
        { id: 'nextjs_isr', name: 'ISR cache poisoning', cliCommand: 'curl -X PURGE <TARGET>' },
        { id: 'nextjs_route_handlers', name: 'Route Handlers', cliCommand: 'nuclei -id nextjs-route-handlers -u <TARGET>' },
        { id: 'nextjs_edge', name: 'Edge Functions mapping', cliCommand: 'nuclei -id nextjs-edge -u <TARGET>' }
      ]
    });
  }

  if (stackNames.includes('react') || stackNames.includes('vue') || stackNames.includes('angular') || stackNames.includes('svelte')) {
    intelligence.push({
      framework: 'SPA Frontend (React/Vue/Angular)',
      vectors: [
        { id: 'spa_sourcemaps', name: 'Source Maps leak', cliCommand: 'nuclei -id react-sourcemaps -u <TARGET>' },
        { id: 'spa_routing', name: 'Client Side Routing enum', cliCommand: 'nuclei -id react-routing -u <TARGET>' },
        { id: 'spa_localstorage', name: 'Local Storage secrets', cliCommand: 'grep -ri "localStorage.setItem" .' },
        { id: 'spa_secrets_scan', name: 'JS Secrets Analyzer', cliCommand: 'nuclei -t exposed-tokens/ -u <TARGET>' },
        { id: 'spa_dom_injection', name: 'DOM Injection Points', cliCommand: 'grep -riE "dangerouslySetInnerHTML|innerHTML|v-html" .' },
        { id: 'dalfox_spa', name: 'XSS Automático (Verificación DOM)', cliCommand: 'dalfox url <TARGET>' }
      ]
    });
  }

  // Identificar Static Sites (ej. no detectamos node, python, php, pero sí html/js)
  const isStatic = !techStack.some(t => ['node.js', 'express', 'django', 'flask', 'laravel', 'php', 'spring'].includes(t.name.toLowerCase()));
  if (isStatic || stackNames.includes('vercel') || stackNames.includes('netlify') || stackNames.includes('github pages')) {
    intelligence.push({
      framework: 'Static & JAMStack',
      vectors: [
        { id: 'static_takeover', name: 'Subdomain Takeover', cliCommand: 'nuclei -t takeovers/ -u <TARGET>' },
        { id: 'static_secrets', name: 'Hardcoded Secrets Scanner', cliCommand: 'nuclei -tags keys,tokens,credentials -u <TARGET>' },
        { id: 'static_cors', name: 'CORS Misconfiguration', cliCommand: 'nuclei -id cors-misconfig -u <TARGET>' },
        { id: 'static_s3', name: 'S3 Bucket Exposure', cliCommand: 'nuclei -id s3-detect -u <TARGET>' }
      ]
    });
  }

  if (stackNames.includes('node.js') || stackNames.includes('express')) {
    intelligence.push({
      framework: 'Node.js / Express',
      vectors: [
        { id: 'express_routing', name: 'Express Route enumeration', cliCommand: 'ffuf -w routes.txt -u <TARGET>/FUZZ' },
        { id: 'express_pollution', name: 'Prototype Pollution', cliCommand: 'nuclei -id prototype-pollution -u <TARGET>' },
        { id: 'express_uncaught', name: 'Uncaught Exceptions DOS', cliCommand: 'curl -H "Content-Type: application/json" -d "{"badjson"}" <TARGET>' },
        { id: 'express_redos', name: 'Regex DOS (ReDoS)', cliCommand: 'nuclei -id redos -u <TARGET>' }
      ]
    });
  }

  if (stackNames.includes('postgres') || stackNames.includes('postgresql') || stackNames.includes('neon')) {
    intelligence.push({
      framework: 'PostgreSQL',
      vectors: [
        { id: 'pg_sqli', name: 'SQL Injection', cliCommand: 'sqlmap -u <TARGET> --batch --dbs' },
        { id: 'pg_blind_sqli', name: 'Blind SQL Injection', cliCommand: 'sqlmap -u <TARGET> --batch --level=5 --risk=3' },
        { id: 'pg_time_sqli', name: 'Time Based SQL Injection', cliCommand: 'sqlmap -u <TARGET> --technique=T --batch' },
        { id: 'pg_conn_str', name: 'Connection String exposure', cliCommand: 'nuclei -id db-connection-string -u <TARGET>' },
        { id: 'pg_role_esc', name: 'Role escalation', cliCommand: 'nuclei -id pg-role-escalation -u <TARGET>' }
      ]
    });
  }

  if (stackNames.includes('clerk')) {
    intelligence.push({
      framework: 'Clerk Auth',
      vectors: [
        { id: 'clerk_session', name: 'Session Token hijacking', cliCommand: 'nuclei -id clerk-session-hijack -u <TARGET>' },
        { id: 'clerk_oauth', name: 'OAuth bypass', cliCommand: 'nuclei -id clerk-oauth-bypass -u <TARGET>' },
        { id: 'clerk_jwt', name: 'JWT validation bypass', cliCommand: 'nuclei -id jwt-none-alg -u <TARGET>' },
        { id: 'clerk_metadata', name: 'User Metadata manipulation', cliCommand: 'curl -X PATCH -d "{"publicMetadata": {"role":"admin"}}" <TARGET>' }
      ]
    });
  }

  if (stackNames.includes('supabase')) {
    intelligence.push({
      framework: 'Supabase',
      vectors: [
        { id: 'supabase_bucket', name: 'Bucket enumeration', cliCommand: 'nuclei -id supabase-bucket-enum -u <TARGET>' },
        { id: 'supabase_realtime', name: 'Realtime socket exposure', cliCommand: 'wscat -c wss://<TARGET>/realtime/v1/websocket' },
        { id: 'supabase_rls', name: 'Row Level Security bypass', cliCommand: 'nuclei -id supabase-rls-bypass -u <TARGET>' },
        { id: 'supabase_edge', name: 'Edge Functions keys leak', cliCommand: 'nuclei -id supabase-edge-keys -u <TARGET>' },
        { id: 'supabase_anon_key', name: 'Anon Key abuse', cliCommand: 'curl -H "apikey: ANON_KEY" <TARGET>/rest/v1/' }
      ]
    });
  }
  if (stackNames.includes('wordpress')) {
    intelligence.push({
      framework: 'WordPress',
      vectors: [
        { id: 'wpscan_full', name: 'WPScan Arsenal Completo', cliCommand: 'wpscan --url <TARGET> --enumerate u,p,t --random-user-agent' }
      ]
    });
  }

  // Authentication & JWT is a core concern, so we add it as an independent framework layer always
  intelligence.push({
    framework: 'JWT & Authentication',
    vectors: [
      { id: 'jwt_tool_scan', name: 'JWT Misconfiguration Scan', cliCommand: 'jwt_tool <TARGET> -M pb' },
      { id: 'jwt_none_alg', name: 'JWT None Algorithm test', cliCommand: 'jwt_tool <TARGET> -X a' },
      { id: 'jwt_weak_secret', name: 'JWT Weak Secret Brute-force', cliCommand: 'jwt_tool <TARGET> -d ./wordlists/jwt_secrets.txt' }
    ]
  });

  return intelligence;
}

export const VECTOR_REGISTRY: Record<string, VectorItem> = {
  // Next.js
  nextjs_bfla: { id: 'nextjs_bfla', name: 'Server Actions (BFLA/IDOR)', cliCommand: 'nuclei -t http/exposed-panels/ -t http/misconfiguration/ -u <TARGET>' },
  nextjs_middleware: { id: 'nextjs_middleware', name: 'Middleware bypass', cliCommand: 'curl -H "x-middleware-prefetch: 1" <TARGET>/admin' },
  nextjs_api: { id: 'nextjs_api', name: 'API Routes exposure', cliCommand: 'ffuf -s -ac -w ./wordlists/api_wordlist.txt -u <TARGET>/FUZZ' },
  nextjs_build_data: { id: 'nextjs_build_data', name: 'Build Data (_next/data)', cliCommand: 'nuclei -id nextjs-data-leak -u <TARGET>' },
  nextjs_static: { id: 'nextjs_static', name: 'Static Assets', cliCommand: 'nuclei -id nextjs-static-leak -u <TARGET>' },
  nextjs_isr: { id: 'nextjs_isr', name: 'ISR cache poisoning', cliCommand: 'curl -X PURGE <TARGET>' },
  nextjs_route_handlers: { id: 'nextjs_route_handlers', name: 'Route Handlers', cliCommand: 'nuclei -id nextjs-route-handlers -u <TARGET>' },
  nextjs_edge: { id: 'nextjs_edge', name: 'Edge Functions mapping', cliCommand: 'nuclei -id nextjs-edge -u <TARGET>' },
  // SPA Frontend
  spa_sourcemaps: { id: 'spa_sourcemaps', name: 'Source Maps leak', cliCommand: 'nuclei -id react-sourcemaps -u <TARGET>' },
  spa_routing: { id: 'spa_routing', name: 'Client Side Routing enum', cliCommand: 'nuclei -id react-routing -u <TARGET>' },
  spa_localstorage: { id: 'spa_localstorage', name: 'Local Storage secrets', cliCommand: 'grep -ri "localStorage.setItem" .' },
  spa_secrets_scan: { id: 'spa_secrets_scan', name: 'JS Secrets Analyzer', cliCommand: 'nuclei -t exposed-tokens/ -u <TARGET>' },
  spa_dom_injection: { id: 'spa_dom_injection', name: 'DOM Injection Points', cliCommand: 'grep -riE "dangerouslySetInnerHTML|innerHTML|v-html" .' },
  dalfox_spa: { id: 'dalfox_spa', name: 'XSS Automático (Verificación DOM)', cliCommand: 'dalfox url <TARGET>' },
  
  // Static & JAMStack
  static_takeover: { id: 'static_takeover', name: 'Subdomain Takeover', cliCommand: 'nuclei -t takeovers/ -u <TARGET>' },
  static_secrets: { id: 'static_secrets', name: 'Hardcoded Secrets Scanner', cliCommand: 'nuclei -tags keys,tokens,credentials -u <TARGET>' },
  static_cors: { id: 'static_cors', name: 'CORS Misconfiguration', cliCommand: 'nuclei -id cors-misconfig -u <TARGET>' },
  static_s3: { id: 'static_s3', name: 'S3 Bucket Exposure', cliCommand: 'nuclei -id s3-detect -u <TARGET>' },
  // Node / Express
  express_routing: { id: 'express_routing', name: 'Express Route enumeration', cliCommand: 'ffuf -s -ac -w ./wordlists/api_wordlist.txt -u <TARGET>/FUZZ' },
  express_pollution: { id: 'express_pollution', name: 'Prototype Pollution', cliCommand: 'nuclei -t http/vulnerabilities/generic/prototype-pollution.yaml -u <TARGET>' },
  express_uncaught: { id: 'express_uncaught', name: 'Uncaught Exceptions DOS', cliCommand: 'curl -H "Content-Type: application/json" -d "{"badjson"}" <TARGET>' },
  express_redos: { id: 'express_redos', name: 'Regex DOS (ReDoS)', cliCommand: 'nuclei -id redos -u <TARGET>' },
  // Postgres
  pg_sqli: { id: 'pg_sqli', name: 'SQL Injection', cliCommand: 'sqlmap -u <TARGET> --batch --dbs' },
  pg_blind_sqli: { id: 'pg_blind_sqli', name: 'Blind SQL Injection', cliCommand: 'sqlmap -u <TARGET> --batch --level=5 --risk=3' },
  pg_time_sqli: { id: 'pg_time_sqli', name: 'Time Based SQL Injection', cliCommand: 'sqlmap -u <TARGET> --technique=T --batch' },
  pg_conn_str: { id: 'pg_conn_str', name: 'Connection String exposure', cliCommand: 'nuclei -id db-connection-string -u <TARGET>' },
  pg_role_esc: { id: 'pg_role_esc', name: 'Role escalation', cliCommand: 'nuclei -id pg-role-escalation -u <TARGET>' },
  // Clerk
  clerk_session: { id: 'clerk_session', name: 'Session Token hijacking', cliCommand: 'nuclei -id clerk-session-hijack -u <TARGET>' },
  clerk_oauth: { id: 'clerk_oauth', name: 'OAuth bypass', cliCommand: 'nuclei -id clerk-oauth-bypass -u <TARGET>' },
  clerk_jwt: { id: 'clerk_jwt', name: 'JWT validation bypass', cliCommand: 'nuclei -id jwt-none-alg -u <TARGET>' },
  clerk_metadata: { id: 'clerk_metadata', name: 'User Metadata manipulation', cliCommand: 'curl -X PATCH -d "{\\"publicMetadata\\": {\\"role\\":\\"admin\\"}}" <TARGET>' },
  // JWT
  jwt_tool_scan: { id: 'jwt_tool_scan', name: 'JWT Misconfiguration Scan', cliCommand: 'jwt_tool <TARGET> -M pb' },
  jwt_none_alg: { id: 'jwt_none_alg', name: 'JWT None Algorithm test', cliCommand: 'jwt_tool <TARGET> -X a' },
  jwt_weak_secret: { id: 'jwt_weak_secret', name: 'JWT Weak Secret Brute-force', cliCommand: 'jwt_tool <TARGET> -d ./wordlists/jwt_secrets.txt' },
  // Supabase
  supabase_bucket: { id: 'supabase_bucket', name: 'Bucket enumeration', cliCommand: 'nuclei -id supabase-bucket-enum -u <TARGET>' },
  supabase_realtime: { id: 'supabase_realtime', name: 'Realtime socket exposure', cliCommand: 'wscat -c wss://<TARGET>/realtime/v1/websocket' },
  supabase_rls: { id: 'supabase_rls', name: 'Row Level Security bypass', cliCommand: 'nuclei -id supabase-rls-bypass -u <TARGET>' },
  supabase_edge: { id: 'supabase_edge', name: 'Edge Functions keys leak', cliCommand: 'nuclei -id supabase-edge-keys -u <TARGET>' },
  supabase_anon_key: { id: 'supabase_anon_key', name: 'Anon Key abuse', cliCommand: 'curl -H "apikey: ANON_KEY" <TARGET>/rest/v1/' },
  // Arsenal
  deep_katana: { id: 'deep_katana', name: 'Crawling Avanzado JS/DOM', cliCommand: 'katana -u <TARGET> -d 5 -jc -kf all' },
  deep_gau: { id: 'deep_gau', name: 'Historial GAU (Wayback/AlienVault)', cliCommand: 'gau <TARGET>' },
  deep_trufflehog: { id: 'deep_trufflehog', name: 'Búsqueda de API Keys (Trufflehog)', cliCommand: 'trufflehog endpoint <TARGET> --no-verification' },
  nmap_full: { id: 'nmap_full', name: 'Escaneo de Puertos Total', cliCommand: 'nmap -sV -sC -Pn -T4 -p- <TARGET>' },
  subfinder_enum: { id: 'subfinder_enum', name: 'Enumeración de Subdominios', cliCommand: 'subfinder -d <TARGET> -all' },
  wpscan_full: { id: 'wpscan_full', name: 'WPScan Arsenal Completo', cliCommand: 'wpscan --url <TARGET> --enumerate u,p,t --random-user-agent' },
  dalfox_react: { id: 'dalfox_react', name: 'XSS Automático (Verificación DOM)', cliCommand: 'dalfox url <TARGET>' },
  sqlmap: { id: 'sqlmap', name: 'Inyección SQL con SQLMap', cliCommand: 'sqlmap -u <TARGET> --batch --level=3 --risk=2' },
  dalfox: { id: 'dalfox', name: 'Ataque XSS con Dalfox', cliCommand: 'dalfox url <TARGET>' },

  // Arsenal Extendido (Cero Humo)
  amass: { id: 'amass', name: 'Amass (Subdomain Enum)', cliCommand: 'amass enum -d <TARGET>' },
  shodan: { id: 'shodan', name: 'Shodan CLI (Recon)', cliCommand: 'shodan domain <TARGET>' },
  httpx: { id: 'httpx', name: 'HTTPX (Tech Detect)', cliCommand: 'httpx -u <TARGET> -tech-detect -status-code -title' },
  whatweb: { id: 'whatweb', name: 'WhatWeb (Fingerprint)', cliCommand: 'whatweb -v -a 3 <TARGET>' },
  wappalyzer: { id: 'wappalyzer', name: 'Wappalyzer CLI', cliCommand: 'wappalyzer <TARGET>' },
  feroxbuster: { id: 'feroxbuster', name: 'Feroxbuster (Dir Brute)', cliCommand: 'feroxbuster -u <TARGET> --silent' },
  gospider: { id: 'gospider', name: 'GoSpider (Crawling)', cliCommand: 'gospider -s <TARGET> -c 10' },
  trufflehog: { id: 'trufflehog', name: 'TruffleHog (Secretos)', cliCommand: 'trufflehog endpoint <TARGET>' },
  gitleaks: { id: 'gitleaks', name: 'Gitleaks (Git Secrets)', cliCommand: 'gitleaks detect -v --source=.' },
  source_map_explorer: { id: 'source_map_explorer', name: 'Source Map Explorer', cliCommand: 'source-map-explorer <TARGET>' },
  retire: { id: 'retire', name: 'Retire.js (Vuln JS)', cliCommand: 'retire --jspath <TARGET>' },
  shcheck: { id: 'shcheck', name: 'SHCheck (Security Headers)', cliCommand: 'shcheck <TARGET>' },
  commix: { id: 'commix', name: 'Commix (OS Injection)', cliCommand: 'commix --url="<TARGET>" --level=3' },
  nosqlmap: { id: 'nosqlmap', name: 'NoSQLMap (NoSQL Injection)', cliCommand: 'python nosqlmap.py' },
  crlfuzz: { id: 'crlfuzz', name: 'CRLFuzz (CRLF Injection)', cliCommand: 'crlfuzz -u <TARGET>' },
  kxss: { id: 'kxss', name: 'KXSS (XSS Finder)', cliCommand: 'gau <TARGET> | kxss' }
};
