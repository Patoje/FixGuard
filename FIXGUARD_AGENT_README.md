# FixGuard — Guía Completa para el Agente de Desarrollo

> Este documento consolida todas las decisiones de arquitectura, roadmap por fases, arsenal de herramientas, pipelines de ataque y prioridades discutidas. Está pensado para ser pasado directamente al agente que va a implementar cada fase.

---

## 0. Contexto del Proyecto

FixGuard es una plataforma DAST (Dynamic Application Security Testing) y orquestador de ataques basado en contexto. La filosofía central es **"Reconocimiento Inteligente Primero"**: analizar profundamente el target antes de atacar, usando la inteligencia recolectada para lanzar ataques dirigidos y precisos.

**Prioridad de diseño: precisión por encima de velocidad.** Es preferible tardar 20 segundos más y obtener resultados exactos que ser rápido con falsos positivos.

**Dos mundos que debe cubrir:**
- **Legacy**: PHP, ASP clásico, JSP, HTML estático, jQuery, WordPress, Joomla — sitios que no se han migrado por el costo.
- **SPA moderno**: Next.js, React, Vue, Nuxt, Remix, SvelteKit, Angular, Vite apps.

**Arquitectura actual**: Web (Next.js) + Worker (Node.js) + PostgreSQL como bus asíncrono. Esta arquitectura es correcta y no debe cambiarse.

---

## 1. Roadmap por Fases

### Fase 1 — Limpieza y base sólida (semanas 1–3)

**ELIMINAR los siguientes archivos — son código muerto que genera confusión:**
- `worker/src/scanner/sqli.ts`
- `worker/src/scanner/xss.ts`
- `worker/src/scanner/cors.ts`
- `worker/src/scanner/graphql.ts`
- `worker/src/scanner/websockets.ts`
- Código de `Interactive Replayer` en `targetedOrchestrator.ts` (función `runCustomAttackReplayer`)
- El path de "Escaneo Agresivo" masivo en `index.ts` que referencia los módulos viejos

**UNIFICAR el scanner path:**
- Un solo entry point en `index.ts` para todos los escaneos
- Todo pasa por `targetedOrchestrator.ts` — sin excepciones
- Eliminar cualquier lógica de fallback a los módulos viejos

**CONSTRUIR: Issue Manager**
- Nueva tabla en PostgreSQL: `findings`
- Campos: `id`, `scan_id`, `fingerprint` (hash único del finding), `title`, `severity` (critical/high/medium/low/info), `status` (open/accepted/fixed/false_positive), `endpoint`, `method`, `request_raw`, `response_raw`, `payload_used`, `cwe_id`, `owasp_category`, `tool_source`, `created_at`, `updated_at`
- Lógica de deduplicación: antes de insertar un finding, calcular el fingerprint (hash de endpoint + tipo de vulnerabilidad + parámetro afectado). Si ya existe con ese fingerprint, no duplicar — solo actualizar `last_seen`
- Estados: `Open` → `Accepted` → `Fixed`. También `False Positive`
- Este Issue Manager es el prerequisito de todo lo demás

**CONSTRUIR: Instalador con CLI tools empaquetadas**
- El worker debe poder distribuirse como binario/instalador
- Empaquetar dentro del instalador: `nuclei`, `ffuf`, `katana`, `sqlmap`, `nmap`, `subfinder`
- Las herramientas nuevas (ver Fase 2) también van en el instalador
- Worker corre como proceso de fondo al iniciar el sistema (system service / tray icon)
- El usuario abre `localhost:3000` — no necesita instalar nada más

---

### Fase 2 — Completar el loop ofensivo (semanas 4–8)

**CONSTRUIR: Session Manager**

El 80% de las apps modernas requieren autenticación. Sin esto, solo se escanea la superficie pública.

Implementar soporte para:
- Cookies de sesión (captura manual + replay automático)
- JWT Bearer con auto-refresh: detectar cuando el token expira (401), re-autenticar automáticamente con las credenciales guardadas, continuar el scan
- OAuth 2.0 flow básico (code flow)
- Grabación de secuencias de login: el usuario hace el login una vez en la UI, FixGuard graba la secuencia y la reproduce en cada request del scan

Almacenamiento: las credenciales van cifradas en la BD, nunca en texto plano.

**CONSTRUIR: Attack Executor**

Los Smart Vectors actuales (BOLA, MassAssignment, WorkflowBypass) solo recomiendan — no ejecutan. Esto debe cambiar.

El Attack Executor es un HTTP client interno que:
1. Recibe un Smart Vector del motor de lógica
2. Ejecuta el request HTTP con el payload
3. Captura la respuesta completa (status, headers, body, tiempo de respuesta)
4. Compara con la respuesta baseline (el request legítimo)
5. Clasifica automáticamente: si el status cambia de 403 a 200, si aparecen campos nuevos en el response, si el tiempo de respuesta difiere significativamente → finding confirmado
6. Guarda el resultado en el Issue Manager con request/response completo como evidencia

**MEJORAR: Context → CLI bridge**

El recon debe alimentar directamente los parámetros de las herramientas de ataque:
- `sqlmap` debe recibir `-p [params]` con los parámetros extraídos por el JS Knowledge Extractor, no escanear todo a ciegas
- `ffuf` debe recibir un wordlist generado dinámicamente con los términos del Attack Surface Mapper (nombres de entidades, endpoints descubiertos, términos del diccionario de negocio) — no SecLists genérico
- `dalfox` debe recibir las URLs con parámetros ya identificados por el recon

**CONSTRUIR: Report Exporter**

Cada finding exportable con:
- Request HTTP completo (headers + body)
- Response HTTP completo
- Payload exacto usado
- Severidad con justificación
- Referencia CWE y categoría OWASP
- Recomendación de remediación
- Formatos: PDF y HTML

---

### Fase 3 — Diferenciación real vs Burp/ZAP (semanas 9–16)

**MEJORAR: Next.js / React Engine — la ventaja competitiva principal**

Ampliar el Server Actions Engine para cubrir:
- Remix actions (`action` functions)
- SvelteKit form actions (`+page.server.ts`)
- tRPC endpoints (detectar `_trpc` en URLs)
- Nuxt server routes (`/api/` en Nuxt 3)

Agregar detección de React2Shell (CVE-2025-55182 / CVE-2025-66478):
- Cuando el Tech Stack Profiler detecta Next.js, ejecutar automáticamente el check
- Método: POST con header `Next-Action: x` + payload Flight construido que ejecuta `41*271`
- Si la respuesta contiene `X-Action-Redirect: /login?a=11111` → target vulnerable
- Versiones afectadas: Next.js < 15.0.5, 15.1.9, 15.2.6, 15.3.6 y React 19.0–19.2.0

**MEJORAR: JS Knowledge Extractor**

Agregar capacidades de parsing:
- **Sourcemaps**: si existe `[bundle].js.map`, descargarlo y reconstruir el árbol de archivos originales con nombres de módulos internos
- **Webpack chunks**: parsear `webpackChunkName` comments para mapear módulos
- **Vite manifest**: leer `/.vite/manifest.json` o `/asset-manifest.json` para el mapa completo de chunks
- **React Router v6**: extraer rutas de `createBrowserRouter` y `createRoutesFromElements`
- **window.__NEXT_DATA__**: parsear el objeto JSON inyectado por Next.js en el HTML — contiene estado inicial, endpoints, a veces tokens
- **String literal clustering**: buscar todos los strings que empiezan con `/api/` dentro del bundle con regex — encontrás 20-200 endpoints que el crawler jamás ve

**MEJORAR: Business Logic Engine**

Conectar los tres motores al Attack Executor:
- `BolaExploiter`: ejecutar automáticamente el cambio de IDs y verificar si la respuesta contiene datos de otro usuario
- `MassAssignmentExploiter`: enviar los campos protegidos inferidos y verificar si el server los acepta
- `WorkflowBypassExploiter`: saltar pasos intermedios y verificar si el flujo avanza igual

**CONSTRUIR: Scan Diffing**

- Comparar dos scans del mismo target en el tiempo
- Mostrar: findings nuevos, findings cerrados (ya no aparecen), regresiones (volvió a aparecer algo que estaba fixed)
- Crítico para uso continuo / SaaS

---

### Fase 4 — Distribución y escala (semanas 17+)

- **Plugin/Extension API**: custom modules en formato YAML (como nuclei templates). La comunidad construye encima.
- **Team / Workspace**: compartir findings, asignar issues, comentarios, roles.
- **Scheduled scans**: cron jobs para re-escanear targets periódicamente y notificar findings nuevos.
- **Módulo SAST**: el código ya existe en `api/sast`. Retomarlo para DAST + SAST en un solo panel.

---

## 2. Arsenal de Herramientas CLI

### Criterio general
- Todas las herramientas deben ir empaquetadas en el instalador
- El worker detecta si están disponibles al iniciar y las descarga/instala si faltan
- Cada herramienta tiene un parser dedicado en `worker/src/parsers/[tool].ts` que convierte el output en findings del Issue Manager

---

### Reconocimiento Pasivo

| Herramienta | Estado | Acción |
|---|---|---|
| `subfinder` | Mantener | Ya integrado. Combinar output con `httpx` para filtrar subdominios vivos |
| `gau` | **Agregar** | Reemplaza `waybackurls`. Cubre Wayback + CommonCrawl + OTX + URLScan en un comando |
| `waybackurls` | **Eliminar** | Subconjunto de `gau`. Remover del orchestrator |
| `amass` | **Agregar** | Enumeración más profunda que subfinder. OSINT + DNS brute + certificate transparency |
| `shodan CLI` | **Agregar** | Para legacy: infraestructura expuesta sin tocar el target. Requiere API key del usuario |
| GitHub dorking | **Agregar** | Buscar repos públicos del target con secretos y endpoints hardcodeados. Usar `gh` CLI o API |

---

### Fingerprinting y Detección de Tecnología

| Herramienta | Estado | Acción |
|---|---|---|
| `httpx` | **Agregar** | Probe masivo antes de atacar. Flags: `-tech-detect -status-code -title -cdn -waf` |
| `whatweb` | **Agregar** | Fingerprint profundo de CMS, versiones exactas de librerías. Mejor que httpx para legacy |
| `wappalyzer CLI` | **Agregar** | Detección de stack frontend: bundlers, frameworks JS, auth providers. Para SPAs |
| `nmap` | Mejorar uso | Cambiar a: `nmap -sV --script=vuln,http-headers,ssl-enum-ciphers` |
| Tech Stack Profiler (propio) | Mejorar | Agregar firmas para Vite, Astro, Remix, SvelteKit, Nuxt, tRPC |

---

### Crawling y Discovery de Superficie

| Herramienta | Estado | Acción |
|---|---|---|
| `katana` | Mejorar uso | Cambiar flags a: `katana -jc -kf all -fx -xhr -d 5`. Los flags `-jc` y `-xhr` son críticos para SPAs |
| `ffuf` | Mejorar uso | Siempre usar wordlist contextual generado por el recon, no SecLists genérico |
| `feroxbuster` | **Agregar** | Recursión automática. Descubre `/api/v1/users/profile` sin configuración extra. Para legacy |
| `gospider` | **Agregar** | Crawl con soporte JS básico. Extrae links de sourcemaps y comentarios HTML |
| `nuclei -t exposures` | **Agregar** | Detecta `.git` expuesto, `.env` visible, backup files, debug endpoints |

---

### Análisis de JavaScript y Bundles

| Herramienta | Estado | Acción |
|---|---|---|
| JS Knowledge Extractor (propio) | Mejorar | Ver mejoras detalladas en Fase 3 |
| `trufflehog` | **Agregar** | Killer feature: verifica si el secreto encontrado está ACTIVO haciendo una llamada real a la API del servicio |
| `gitleaks` | **Agregar** | F1-score más alto del mercado open source (60%). Para repos públicos del target |
| `source-map-explorer` | **Agregar** | Reconstruye árbol de archivos desde sourcemaps. Revela nombres de módulos internos |
| `retire.js CLI` | **Agregar** | Detecta librerías JS con CVEs conocidos dentro del bundle (jQuery 1.x, lodash vulnerable, etc.) |

---

### SSL / TLS / Security Headers

| Herramienta | Estado | Acción |
|---|---|---|
| `testssl.sh` | **Agregar** | Más preciso que nuclei para TLS: BEAST, POODLE, SWEET32, Heartbleed, weak ciphers |
| `nuclei -t ssl` | Mantener | Checks rápidos de cert expirado, HSTS, subdomain takeover via SSL |
| `shcheck` | **Agregar** | Audita security headers: CSP, HSTS, X-Frame-Options, Permissions-Policy con score |

---

### Inyecciones y Fuzzing de Parámetros

| Herramienta | Estado | Acción |
|---|---|---|
| `sqlmap` | Mejorar uso | Flags: `sqlmap -p [params_del_recon] --level=3 --risk=2 --technique=BEUSTQ --batch` |
| `dalfox` | **Agregar** | **Reemplaza `xsstrike`**. Verificación AST del DOM real: cero falsos positivos en XSS. Detecta reflected, stored y DOM-based |
| `xsstrike` | **Eliminar** | Sin verificación DOM. Genera falsos positivos. Remover del orchestrator |
| `commix` | **Agregar** | Command injection automatizado. OS injection en params que ejecutan comandos del server. Para legacy |
| `nosqlmap` | **Agregar** | Equivalente de sqlmap para MongoDB/NoSQL. Crítico para SPAs con Firebase o MongoDB |
| `crlfuzz` | **Agregar** | CRLF injection automatizado. Headers mal sanitizados como `Location`, `Set-Cookie` |
| `kxss` | **Agregar** | Detección rápida de parámetros que reflejan input sin encodear. Filtro previo a dalfox |

---

### Lógica de Negocio y Autorización

Estas son las capacidades propias de FixGuard — el diferenciador principal vs Burp/ZAP.

| Módulo | Estado | Acción |
|---|---|---|
| BOLA Exploiter | Mejorar | Conectar al Attack Executor para ejecutar y verificar automáticamente |
| MassAssignment Exploiter | Mejorar | Inferir campos desde modelos JS + ejecutar el ataque automáticamente |
| WorkflowBypass Exploiter | Mejorar | Detectar y saltar pasos de checkout, confirmación, verificación de email |
| Server Actions Engine | Mejorar | Ampliar a Remix, SvelteKit, tRPC, Nuxt. Agregar detección CVE-2025-55182 |
| Autorize (concepto propio) | **Agregar** | Replay automático de requests con token de otro usuario. Verifica BOLA sistemáticamente |

---

### APIs, GraphQL y WebSockets

| Herramienta | Estado | Acción |
|---|---|---|
| `graphw00f` | **Agregar** | Fingerprint del engine GraphQL (Apollo, Hasura, Yoga). Cada uno tiene vulns distintas |
| `clairvoyance` | **Agregar** | Reconstruye schema GraphQL aunque la introspección esté deshabilitada |
| `graphql-cop` | **Agregar** | Audita misconfigs GraphQL: introspection on, batching, field suggestions, DoS via queries |
| `wscat` / ws-harness | **Agregar** | Fuzzing de WebSocket messages. Para SPAs con chat, live data o notificaciones |
| `jwt-tool` | **Agregar** | Ataca JWTs: `alg:none`, RS256→HS256, weak secrets, `kid` injection, `jku`/`x5u` manipulation |

---

### Cloud, Infraestructura y Misconfigs

| Herramienta | Estado | Acción |
|---|---|---|
| `nuclei -t cloud` | Mantener | Templates para S3, Firebase, GCS buckets públicos, metadata endpoints |
| `s3scanner` | **Agregar** | Enumera y verifica permisos en S3 buckets relacionados al dominio target |
| `firebaseEnum` | **Agregar** | Detecta Firebase DBs del target y verifica si tienen reglas abiertas (read sin auth) |
| `nuclei -t takeovers` | Mantener | Subdomain takeover via CNAME huérfanos. Alta precisión |

---

## 3. Pipelines de Ataque

### Pipeline Legacy (PHP, jQuery, HTML estático, WordPress, etc.)

```
Fase 0: Detección de contexto
  httpx → headers, cookies, HTML fingerprint
  whatweb → versiones exactas de CMS/frameworks
  → Tech Stack Profiler → confirma: legacy detectado

Fase 1: Recon pasivo
  gau [domain] → historial de URLs (Wayback + CommonCrawl + OTX + URLScan)
  subfinder + amass → subdominios
  nmap -sV --script=vuln,http-headers → puertos y servicios
  shodan CLI → infraestructura expuesta sin tocar el target

Fase 2: Discovery de superficie
  ffuf -w [wordlist_contextual] -u [target]/FUZZ → paths y archivos
  feroxbuster -u [target] → recursión automática
  nuclei -t exposures → .git expuesto, .env, backup files, debug endpoints
  gospider → links ocultos en comentarios HTML y sourcemaps

Fase 3: Análisis de parámetros
  Extraer todos los forms y sus inputs del HTML
  Extraer query params de todas las URLs recolectadas
  Construir lista de parámetros para ataques dirigidos
  nuclei -t misconfig → misconfigs conocidas del stack detectado

Fase 4: Ataques dirigidos (paralelo)
  SQLi:        sqlmap -u [target] -p [params] --level=3 --risk=2 --technique=BEUSTQ --batch
  XSS:         kxss → filtra params reflectivos → dalfox pipe --silence
  Command inj: commix -u [target] --level=3
  Headers:     crlfuzz -u [target]
  Secretos:    gitleaks (si hay repo público) + nuclei -t token-spray
  TLS:         testssl.sh [domain] + shcheck [domain]
  CVEs:        nuclei -t cves -t misconfig -update-templates

Fase 5: Correlación y reporte
  Issue Manager → deduplicación → findings con evidencia completa → export PDF/HTML
```

**Wordlists para legacy:**
- `SecLists/Discovery/Web-Content/raft-large-directories.txt`
- `SecLists/Discovery/Web-Content/raft-large-files.txt`
- `bo0om/fuzz.txt` — backup files y configs expuestos
- Wordlist contextual generado por el recon (términos propios del target)

---

### Pipeline SPA Moderno (Next.js, React, Vue, Nuxt, Remix, SvelteKit)

```
Fase 0: Detección de contexto
  httpx → headers especiales: x-powered-by, x-vercel-id, server
  Buscar en HTML: window.__NEXT_DATA__, React root div, vue-app, ng-version
  Buscar headers: Vary con RSC values → confirma Next.js App Router
  wappalyzer CLI → stack frontend completo
  → Tech Stack Profiler → confirma: SPA moderno + framework específico

Fase 1: Extracción de bundles JS
  katana -u [target] -jc -kf all -fx -xhr -d 5
  → Descarga todos los .js bundles del target
  → JS Knowledge Extractor:
    - Parsea bundle buscando strings /api/...
    - Extrae rutas de React Router / Vue Router / Next.js App Router
    - Parsea window.__NEXT_DATA__ del HTML inicial
    - Busca sourcemaps (.js.map) y los descarga si están expuestos
    - Lee /.vite/manifest.json o /asset-manifest.json si existen
    - Extrae variables de entorno expuestas (NEXT_PUBLIC_*, VITE_*)

Fase 2: Análisis semántico
  Correlacionar todos los endpoints encontrados
  Inferir modelos de datos (campos que aparecen en requests/responses JS)
  Identificar patrones de autenticación (JWT, session, OAuth)
  Detectar integraciones de terceros (AWS keys, Firebase config, Stripe keys)
  trufflehog → verificar si los secretos encontrados están activos
  retire.js → librerías con CVEs en el bundle

Fase 3: Crawling con DOM rendering
  katana headless → ejecutar JS y seguir event listeners
  gau [domain] → historial de endpoints API
  Capturar headers Next-Action en todos los requests POST
  graphw00f → detectar si hay GraphQL y fingerprinting del engine

Fase 4: Generación de Smart Vectors (motores propios)
  BolaExploiter → rutas con params dinámicos (/api/users/:id) → vector IDOR
  MassAssignmentExploiter → campos protegidos inferidos → vector privilege injection
  WorkflowBypassExploiter → flujos multi-paso detectados → vector de salto de pasos
  Server Actions Engine → Next-Action endpoints → vector BFLA

Fase 5: Ataques dirigidos (paralelo)
  BOLA/IDOR:    Attack Executor → cambio de IDs → comparar respuestas
  MassAssign:   Attack Executor → inyectar campos isAdmin/role → verificar aceptación
  XSS DOM:      dalfox -u [endpoints] --deep-domxss
  JWT:          jwt-tool → alg:none, RS256→HS256, weak secret bruteforce
  NoSQLi:       nosqlmap (si stack usa MongoDB/Firebase)
  GraphQL:      graphql-cop → misconfigs + clairvoyance → schema completo
  CVE Next.js:  nuclei -t cves + Check React2Shell (ver sección especial abajo)
  Secrets:      trufflehog (verificación activa de credenciales)
  TLS/Headers:  testssl.sh + shcheck

Fase 6: Correlación y reporte
  Issue Manager → deduplicación → findings con evidencia completa → export PDF/HTML
```

**Wordlists para SPAs:**
- `assetnote/httparchive_apiroutes_*.txt` — rutas de APIs reales de internet
- `assetnote/httparchive_js_*.txt` — archivos JS comunes
- `SecLists/Discovery/Web-Content/api/objects.txt`
- Wordlist contextual generado por JS Knowledge Extractor (específico para ese target)

---

## 4. Detección Especial: React2Shell (CVE-2025-55182)

### Qué es
Bug de deserialización en el protocolo Flight de React Server Components. Permite RCE unauthenticado con un solo HTTP request. CVSS 10.0 — el máximo posible. Afecta cualquier Next.js con App Router en configuración default.

**Versiones afectadas:**
- Next.js: todas las versiones anteriores a `15.0.5`, `15.1.9`, `15.2.6`, `15.3.6`, `16.0.7`
- React: `19.0.0` a `19.2.0` con cualquiera de: `react-server-dom-webpack`, `react-server-dom-parcel`, `react-server-dom-turbopack`

**Por qué importa para FixGuard:**
- React es usado por ~40% de todos los desarrolladores
- Next.js está en ~18-20% de la web
- La mayoría de scanners comerciales no tienen este check automatizado todavía
- Ya hay explotación activa en el mundo real (grupos chinos, mineros de criptomonedas)

### Cómo implementar el check

Cuando el Tech Stack Profiler detecta Next.js, ejecutar:

```
POST / HTTP/1.1
Host: [target]
Next-Action: x
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="1"

[payload_flight_construido]
------boundary--
```

**Indicador de vulnerabilidad:** Si la respuesta contiene el header `X-Action-Redirect: /login?a=11111`, el servidor ejecutó el cálculo `41*271=11111` → vulnerable.

**Indicador alternativo (safe-check):** Status 500 con un error digest específico en el body, sin ejecutar código.

Referencia para el payload exacto: `github.com/assetnote/react2shell-scanner`
Template de nuclei: buscar `cve-2025-55182` en nuclei-templates después de `nuclei -update-templates`

---

## 5. Wordlists — Fuentes y Comandos de Descarga

### Assetnote (principal para SPAs y APIs modernas)
```bash
# Descargar todos
wget -r --no-parent -R "index.html*" https://wordlists-cdn.assetnote.io/data/

# Descargar solo los más importantes
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2024_05_28.txt
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_js_2024_05_28.txt
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_php_2024_05_28.txt
```
Web: `https://wordlists.assetnote.io/`

### SecLists (base general)
```bash
git clone https://github.com/danielmiessler/SecLists
```
Los más útiles:
- `Discovery/Web-Content/raft-large-directories.txt`
- `Discovery/Web-Content/raft-large-files.txt`
- `Discovery/Web-Content/api/`
- `Fuzzing/` — para parámetros

### bo0om/fuzz.txt (legacy — backup y configs)
```bash
wget https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt
```

### Trickest wordlists (subdominios de bug bounty real)
```bash
git clone https://github.com/trickest/wordlists
```

### Wordlist contextual (generado por FixGuard — el más valioso)
El JS Knowledge Extractor debe generar automáticamente un wordlist por target con:
- Todos los path segments encontrados en el bundle
- Nombres de entidades del modelo de datos (user, order, product, payment…)
- Nombres de métodos API detectados
- Términos del diccionario de negocio del Attack Surface Mapper

Este wordlist contextual tiene la mayor tasa de acierto porque está construido con términos que provienen del código real de ese target específico.

---

## 6. Entornos de Prueba

Para testear FixGuard antes de usarlo en targets reales. Todos vía Docker.

### Legacy — DVWA
```bash
docker run -p 80:80 vulnerables/web-dvwa
# Acceder: http://localhost/
# Cubre: SQLi, XSS, CSRF, File Inclusion, Command Injection en PHP
```

### SPA moderno — OWASP Juice Shop
```bash
docker run -p 3000:3000 bkimminich/juice-shop
# Acceder: http://localhost:3000/
# Scoreboard: http://localhost:3000/#/score-board
# Cubre: JWT attacks, XSS, SQLi, broken auth, lógica de negocio, REST API
# Escrito en Node.js + Angular — SPA real
```

### APIs REST — VAmPI
```bash
docker run -p 5000:5000 erev0s/vampi:latest
# Acceder: http://localhost:5000/
# Cubre: BOLA/IDOR, Mass Assignment, broken auth, injection — perfecto para testear Attack Executor
```

### Node.js vulnerable — NodeGoat
```bash
git clone https://github.com/OWASP/NodeGoat
cd NodeGoat && docker-compose up
# Acceder: http://localhost:4000/
# Cubre: OWASP Top 10 en Node.js/Express
```

### React2Shell — Next.js vulnerable local
```bash
# Crear app con versión vulnerable
npx create-next-app@14.2.0 vulnerable-app --app
cd vulnerable-app && npm run build && npm start
# Correr el check de CVE-2025-55182 contra localhost:3000
# Referencia del scanner: github.com/assetnote/react2shell-scanner
```

**Orden de testing recomendado:**
1. DVWA → validar pipeline legacy completo
2. Juice Shop → validar pipeline SPA + Smart Vectors
3. VAmPI → validar Attack Executor (BOLA + MassAssignment)
4. Next.js vulnerable → validar detección de React2Shell

---

## 7. Métricas de Éxito por Fase

### Fase 1 completada cuando:
- [ ] No existe ningún módulo zombie en `worker/src/scanner/`
- [ ] Todos los scans pasan por `targetedOrchestrator.ts` sin excepción
- [ ] Issue Manager operativo con deduplicación funcionando
- [ ] Worker se puede instalar con un solo comando y levanta solo

### Fase 2 completada cuando:
- [ ] Session Manager puede hacer login en Juice Shop y mantener la sesión durante un scan completo
- [ ] Attack Executor ejecuta un vector BOLA en VAmPI y lo clasifica como finding confirmado
- [ ] sqlmap recibe los parámetros del JS Extractor, no los descubre solo
- [ ] Se puede exportar un finding a PDF con request/response completo

### Fase 3 completada cuando:
- [ ] JS Knowledge Extractor extrae rutas desde sourcemaps expuestos
- [ ] CVE-2025-55182 se detecta automáticamente en la Next.js vulnerable local
- [ ] Business Logic Engine ejecuta los tres Smart Vectors automáticamente y los verifica
- [ ] Scan diffing muestra correctamente findings nuevos vs regresiones entre dos scans del mismo target

---

## 8. Notas de Arquitectura Importantes

### Lo que NO cambiar
- La separación web/worker es correcta y necesaria — no colapsar en un solo proceso
- PostgreSQL como bus asíncrono — funciona bien, no migrar
- Drizzle ORM — mantener
- La filosofía de "recon primero, ataque después" — es la ventaja competitiva

### Lo que SÍ cambiar (además de lo ya listado)
- `targetedOrchestrator.ts`: agregar timeout handling por herramienta, rate limiting configurable, y retry logic para requests que fallan por rate limiting del target
- Parsers dedicados: cada herramienta CLI necesita su propio parser que convierta el stdout/stderr en objetos estructurados del Issue Manager. Sin esto, los resultados son texto crudo sin valor.
- El módulo SAST (`api/sast`) existe pero no se prioriza hasta Fase 4. No eliminarlo, solo no tocarlo.

### Módulo SAST (Fase 4)
El código para análisis de caja blanca leyendo directorios locales ya existe. Se retoma en Fase 4 para ofrecer DAST + SAST en un solo panel — diferenciador adicional.

---

*Generado a partir de sesión de análisis y planificación completa de FixGuard.*
*Última actualización: Junio 2026*
