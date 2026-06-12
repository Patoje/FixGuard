# FixGuard - Context-Aware Attack Orchestrator & DAST

## 1. Descripcion General de la Aplicacion

FixGuard es una plataforma avanzada de Pruebas de Seguridad Dinamica de Aplicaciones (DAST) y Orquestacion de Ataques basada en contexto. A diferencia de los escaneres de vulnerabilidades tradicionales que se limitan a lanzar cargas utiles (payloads) predefinidas a ciegas, FixGuard opera bajo una filosofia de "Reconocimiento Inteligente Primero". 

La aplicacion realiza una autopsia completa de la aplicacion objetivo: perfila su tecnologia, reconstruye su arquitectura, extrae logica de negocio a partir de artefactos publicos (como archivos JavaScript compilados), y posteriormente utiliza esta inteligencia recolectada para recomendar y orquestar vectores de ataque dirigidos y especificos contra fallos de logica de negocio y vulnerabilidades tecnicas.

FixGuard NO es un proxy interceptor manual (como Burp Suite o ZAP). Es un orquestador automatizado diseñado para delegar el trabajo pesado de mapeo y escaneo a multiples motores, centralizando los resultados en un panel de inteligencia accionable.

## 2. Arquitectura y Estructura de Carpetas

El proyecto esta estrictamente dividido en dos repositorios/carpetas principales, adoptando una arquitectura Cliente-Servidor (Web + Worker).

### ¿Por que esta separado de esta manera?
La separacion es una necesidad tecnica critica para evadir las restricciones de seguridad inherentes a los navegadores web modernos. 
Una aplicacion web ejecutandose en un navegador (Frontend) esta limitada por politicas de CORS, restricciones de cabeceras HTTP (no puede modificar libremente `Host`, `Origin`, etc.), y es incapaz de gestionar sockets TCP en bruto o ejecutar binarios del sistema operativo.
Al tener un `worker` ejecutandose en un entorno Node.js en el sistema operativo local o en un servidor, FixGuard adquiere capacidades absolutas de red: puede enviar peticiones HTTP malformadas, evadir protecciones, y ejecutar herramientas industriales de hacking por linea de comandos (CLI). La carpeta `web` actua unicamente como el centro de control visual y la capa de presentacion.

### `/web` (Capa de Presentacion y API Gateway)
Desarrollada con Next.js (App Router).
- Responsabilidades: Visualizacion de datos mediante dashboards, manejo de interacciones del usuario, y enrutamiento de solicitudes de ataque hacia la base de datos para que el worker las procese.
- Tecnologias: React, TailwindCSS, Framer Motion, TypeScript, Drizzle ORM (para consultas locales a Postgres).
- Archivos clave: 
  - `src/components/ReconDashboard.tsx`: Renderiza el "Actionable Knowledge Report" (Arbol de arquitectura, Superficie de ataque, etc).
  - `src/components/OffensiveArsenal.tsx`: La "Consola Tactica" desde donde el auditor ordena la ejecucion de vectores de ataque descubiertos.
  - `src/app/api/attack/route.ts`: Endpoint que encola solicitudes de ataque dirigido en la base de datos.

### `/worker` (Cerebro, Motor de OSINT y Orquestador de Ataques)
Desarrollado en Node.js puro con Express (para comandos basicos) y TypeScript.
- Responsabilidades: Procesamiento pesado en segundo plano. Lee trabajos encolados de la base de datos, realiza el reconocimiento pasivo y activo, parsea archivos fuente de la victima, evalua heuristica, y ejecuta herramientas externas de hacking (CLI) capturando su salida.
- Tecnologias: Node.js, Drizzle ORM, child_process (para CLI tools).
- Carpetas clave:
  - `src/recon/`: Contiene todos los motores de inteligencia pasiva y extraccion de contexto (Parsers, Mapeadores, Diccionarios).
  - `src/scanner/`: Contiene rutinas de escaneo y explotadores logicos (BOLA, Mass Assignment).
  - `src/targetedOrchestrator.ts`: El puente de ejecucion que lanza los comandos CLI crudos al sistema operativo.
  - `src/index.ts`: El bucle principal de control (Event Loop) que escucha nuevos escaneos o peticiones de ataques en la base de datos.

### Base de Datos
Utiliza PostgreSQL (mediante Neon Serverless) gestionado con Drizzle ORM.
- Sirve como el bus de comunicacion asincrono entre `web` y `worker`. El Frontend escribe intenciones de escaneo/ataque, y el Worker actualiza las filas con los descubrimientos de inteligencia (`recon_profiles`) y los resultados de vulnerabilidades (`vulnerabilities`).

## 3. Analisis, Mapping y Reconocimiento (Inteligencia Recolectada)

La mayor fortaleza actual de FixGuard reside en su motor de OSINT y Reconocimiento. En lugar de fuerza bruta, realiza un analisis semantico profundo.

### Motores de Inteligencia Activos (`worker/src/recon/`):
- Tech Stack Profiler: Analiza cabeceras HTTP, cookies y estructuras HTML para inferir frameworks (Next.js, React, Supabase, Clerk, Postgres).
- Attack Surface Mapper: Cataloga todos los endpoints descubiertos, asignando un "Business Impact Score" (ej. endpoints `/api/payment` reciben puntaje Critico, endpoints `/api/health` reciben puntaje Bajo). Selecciona proactivamente los "Top 5 Critical Business Assets".
- Architecture Builder: Construye un modelo jerarquico (Frontend -> Backend -> Base de Datos) deduciendo como se comunican las piezas en base a las trazas de red.
- JS Knowledge Extractor & Exposure Intelligence: Descarga los bundles (archivos .js compilados de la victima), los parsea en busca de endpoints ocultos (Hardcoded URLs) y credenciales o configuraciones expuestas en texto plano.
- Motores Específicos (Auth, Cloud, AI): Buscan firmas especificas relacionadas con integraciones de terceros (AWS S3, Firebase, OpenAI API keys).
- Server Actions Engine: Un motor altamente especializado en Next.js para detectar funciones "BFLA" (Broken Function Level Authorization) a traves del encabezado `Next-Action`.
- Correlation Engine: Agrupa los descubrimientos dispersos en un modelo unificado `ReconProfile` que se guarda en la base de datos.

### Explotadores Logicos Pasivos (Generadores de Smart Vectors):
FixGuard posee tres motores (`worker/src/scanner/logic/`) que NO atacan directamente, sino que razonan sobre la superficie descubierta y generan vectores de ataque recomendados para la interfaz del usuario.
- BolaExploiter: Detecta rutas con parametros dinamicos (ej. `/api/users/:id`) y genera el vector para probar si cambiar el ID compromete a otro usuario.
- MassAssignmentExploiter: Detecta metodos mutables (POST/PUT/PATCH) e infiere campos protegidos basados en el diccionario de negocio (ej. `isAdmin`, `role`) para generar el vector de inyeccion de privilegios.
- WorkflowBypassExploiter: Infiera procesos de multiples pasos (ej. `/cart` -> `/checkout` -> `/confirm`) para generar el vector que intenta saltar pasos intermedios.

### ¿Que se le muestra al usuario?
Toda esta informacion se condensa en el **Actionable Knowledge Report (Digital Twin)** en el Frontend. Se visualiza:
- Metricas globales de endpoints y tecnologias.
- Top 5 de Activos Criticos de Negocio.
- Diagramas visuales de la arquitectura reconstruida.
- Mapa de Entidades (Modelos de BD inferidos y sus relaciones).
- Flujos de trabajo de negocio detectados.
- Catalogo completo de endpoints.
- Base de datos de exposicion de datos (Secretos encontrados).

## 4. Herramientas de Ataque y Capacidades Ofensivas

FixGuard actúa como un "Orquestador". Las herramientas de inyeccion heuristica estan delegadas a binarios estandar de la industria instalados a nivel del sistema operativo.

### Herramientas Instaladas e Integradas en el Orquestador (`targetedOrchestrator.ts`):
- `katana` (ProjectDiscovery): Utilizado para crawling profundo de SPAs mediante la resolucion de DOM.
- `waybackurls`: Extrae endpoints historicos almacenados en la Wayback Machine.
- `subfinder`: Enumeracion pasiva de subdominios.
- `nmap`: Escaneo de puertos e identificacion de servicios.
- `ffuf`: Fuzzer de alta velocidad para descubrimiento de rutas y APIs ocultas.
- `nuclei`: Escaner rapido basado en plantillas/firmas (YAML) para deteccion de configuraciones erroneas, CVEs y toma de subdominios (Subdomain Takeover).
- `sqlmap`: Herramienta insignia para explotacion de inyeccion SQL (SQLi).
- `wpscan`: Enumeracion especifica y explotacion de WordPress.
- `xsstrike`: Motor automatizado de mutacion heuristica para Cross-Site Scripting (XSS).

### Metodo de Ejecucion (El Gatillo)
Actualmente, las capacidades ofensivas de FixGuard se ejecutan a traves del panel **Offensive Hub (Arsenal)** en la UI.
1. El motor de Inteligencia (FrameworkIntelligence.ts) cataloga los vectores aplicables basandose en la tecnologia detectada (ej. Si detecta React, ofrece el vector `spa_sourcemaps` que llama a `nuclei -id react-sourcemaps`).
2. El panel Arsenal muestra estas recomendaciones.
3. El usuario hace clic en "Lanzar Modulo".
4. La UI inserta un escaneo de tipo `targeted` con el ID del vector en Postgres.
5. El Worker intercepta la solicitud y llama a `runCliCommand()` para ejecutar el binario (ej. `sqlmap -u target.com`) en la terminal local del servidor.
6. El Worker lee el "stdout/stderr", parsea los resultados (buscando indicadores de vulnerabilidades criticas) y guarda el resultado en la BD.

### Herramientas/Codigos Instalados pero No Usados o Rezagados
- Modulos masivos en `worker/src/scanner/`: Existen varios archivos (`sqli.ts`, `xss.ts`, `cors.ts`, `graphql.ts`, `websockets.ts`, etc.) que pertenecen a una fase antigua de desarrollo. Algunos de ellos hacen peticiones fetch basicas o estan simulados. Actualmente han sido eclipsados por la orquestacion de herramientas CLI reales, pero siguen presentes en el codigo fuente. La ruta logica de "Escaneo Agresivo" masivo en `index.ts` aun hace referencia a estos archivos.
- Interactive Replayer: Fue removido de la UI (OffensiveArsenal.tsx), por lo que el codigo del backend en `targetedOrchestrator.ts` llamado `runCustomAttackReplayer` actualmente no tiene una ruta en uso ni un componente frontend que lo invoque.
- Modulo SAST (`api/sast` en `index.ts` y archivos correspondientes): Existe la logica para un analisis de caja blanca local leyendo directorios, pero no se ha priorizado su uso en la UI actual frente al enfoque DAST.
