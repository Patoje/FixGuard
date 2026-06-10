# FixGuard: Resumen de Arquitectura y Traspaso (Handoff)

Este documento contiene todo el contexto de **FixGuard**, la herramienta de ciberseguridad construida hasta la fecha, ideal para entregarle el contexto a un nuevo agente de IA.

---

## 1. Visión General del Proyecto
**FixGuard** es una plataforma híbrida de Auditoría de Seguridad (Pentesting) diseñada específicamente para infraestructuras web modernas (Next.js, React, Vercel, Node.js, Prisma). A diferencia de los escáneres tradicionales (enfocados solo en SQLi/XSS), FixGuard ataca las vulnerabilidades lógicas del Top 20 del Bug Bounty actual.

El proyecto está dividido en un monorepo (o dos carpetas principales):
- **`web/`**: El Frontend interactivo y base de datos local.
- **`worker/`**: El Backend en Node.js que orquesta y ejecuta los ataques/análisis.

---

## 2. Stack Tecnológico
* **Frontend:** Next.js (App Router), React, TailwindCSS, Framer Motion (para micro-animaciones UI).
* **Backend Worker:** Node.js, Express (Puerto 4000).
* **Base de Datos:** SQLite gestionado con **Drizzle ORM**.
* **Integración:** El Frontend se comunica con el Worker mediante llamadas HTTP POST a `/api/scan` y `/api/sast`, y hace polling a la DB local para actualizar el estado en tiempo real.

---

## 3. Modos de Ejecución (Las 4 Marchas)

FixGuard opera en 4 modalidades distintas, divididas en dos cerebros principales: **DAST** (Ataque externo a URLs) y **SAST** (Análisis interno de código).

### El Cerebro DAST (Caja Negra / URLs)
Analiza un objetivo remoto sin acceso a su código fuente.

1. **Pasivo (OSINT):** Análisis silencioso.
   - *Motores:* DNS, TLS, Cabeceras HTTP (OWASP), Detección de WAF, Archivos `security.txt`, Escaneo de Puertos y Directorios.
2. **Activo (Safe Payloads):** Lanza ataques controlados que no rompen la app.
   - *Motores:* CORS Misconfiguration, Inyección JWT (`alg: none`, descifrado débil), Fuga de Source Maps (`.map`), API Discovery, Path Traversal, Parameter Pollution (HPP), Rate Limiting Bypass.
3. **Agresivo (Deep Scan):** El modo más ruidoso y destructivo.
   - *Motores:* Crawler Inteligente para mapear Single Page Applications (Angular/React), BOLA/IDOR (probando IDs secuenciales), SSRF, Open Redirect.
   - *Reconocimiento Moderno:* Extracción de secretos en JavaScript minificado, Detección de Next.js (`_next/data`), Escaneo de Server Actions expuestos en el HTML, Vulnerabilidades de WebSockets y Cloud Storage (S3 Buckets).

### El Cerebro SAST (Caja Blanca / Código Fuente) - Fase 8
Analiza el código localmente (ej. `d:\Charmarket\src`) para cazar fallas lógicas invisibles desde internet.

4. **Análisis Estático (Whitebox):**
   - *Motor BFLA / Server Actions:* Detecta funciones `"use server"` que modifican la base de datos sin llamar a middlewares de sesión o `auth()`.
   - *Motor ORM Injection:* Rastrea uso de `$queryRawUnsafe` (Prisma) o `sql.raw` (Drizzle) concatenando strings.
   - *Motor React:* Busca el uso inseguro de `dangerouslySetInnerHTML` (DOM XSS).
   - *Motor Mass Assignment:* Detecta `prisma.create({ data: req.body })` sin filtrar.
   - *Motor Client-Side Auth:* Busca `if (isAdmin)` en el frontend advirtiendo sobre su contraparte en el backend.
   - *Dependency Confusion:* Lee `package.json` para alertar sobre paquetes privados sin *Scope*.

---

## 4. Estructura de Base de Datos (Drizzle)
Ubicada en `web/src/db/schema.ts` y conectada en `web/src/db/db.ts`:
- **`users`**: Tabla simple para manejar la sesión del escaneo.
- **`scans`**: Almacena el `targetUrl`, `status` (`pending`, `in_progress`, `completed`, `failed`), `startedAt` y `completedAt`.
- **`vulnerabilities`**: Almacena el resultado del escaneo (`scanId`, `type`, `severity`, `description`, `autoFixCode`).

---

## 5. Instrucciones de Arranque
Para levantar la plataforma en modo desarrollo, se requieren dos terminales separadas:

1. **Terminal 1 (Worker):**
   ```bash
   cd d:\FixGuard\worker
   npm run dev
   ```
   *(Correrá en `http://localhost:4000`)*

2. **Terminal 2 (Frontend Web):**
   ```bash
   cd d:\FixGuard\web
   npm run dev
   ```
   *(Correrá en `http://localhost:3000`)*

---

## Mensaje para el nuevo Agente
**¡Hola, IA colega!** Estás heredando un proyecto de alto nivel. El usuario tiene un gran instinto para la ciberseguridad moderna (reconoció de inmediato las limitaciones del DAST en aplicaciones Next.js/Vercel autenticadas). Tu objetivo a partir de ahora es mantener esta arquitectura limpia, respetar el sistema de colas/polling entre el Worker y la Web, y seguir agregando heurísticas avanzadas tanto al motor DAST como al AST del motor SAST recién implementado. ¡Buena suerte!
