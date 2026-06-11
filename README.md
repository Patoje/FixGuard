# FixGuard: Offensive OSINT & Exploitation Framework

FixGuard ha evolucionado de ser un simple escáner de vulnerabilidades a un **Framework Ofensivo Personal de Grado Militar**. Su objetivo principal no es solo auditar pasivamente, sino descubrir, mapear y atacar de forma agresiva cualquier objetivo (Web, API o Infraestructura) sin restricciones de servidor ni "frenos" éticos forzados, diseñado para uso personal en auditorías de caja negra completas.

## 🏗️ Arquitectura del Sistema

El sistema está dividido en dos grandes bloques que se comunican de forma fluida:

1. **Control Center (Frontend - Next.js):**
   - Un panel de control moderno, reactivo y de estética premium.
   - Perfilado visual de tecnologías detectadas (Tech Stack).
   - Mapa de la Superficie de Ataque y Vectores de Inteligencia.
   - Botones de acción directa para lanzar comandos destructivos sin tocar la terminal.

2. **Orquestador (Backend Worker - Node.js):**
   - El motor de ejecución pesado (`http://localhost:4000`).
   - Se encarga del escaneo inicial agresivo (Headers, JWT, Source Maps).
   - Administra y ejecuta las herramientas CLI instaladas localmente en el sistema anfitrión.
   - Interpreta la salida estándar (`stdout`) de las herramientas y guarda las vulnerabilidades en una base de datos SQLite persistente.

---

## ⚔️ El Arsenal (Herramientas Integradas)

FixGuard no reinventa la rueda, actúa como un director de orquesta para las herramientas más mortíferas de la industria:

*   **Reconocimiento y Fuzzing de Directorios:** `FFuf`
*   **Escáner de Plantillas y Misconfigs:** `Nuclei`
*   **Explotación de Bases de Datos:** `SQLMap`
*   **Escaneo Completo de Puertos:** `Nmap`
*   **Crawling Headless Avanzado (JS/DOM):** `Katana` (ProjectDiscovery)
*   **Scraping Histórico de Archivos Ocultos:** `Waybackurls`
*   **Enumeración Masiva de Subdominios:** `Subfinder`
*   **Fuzzing y Mutación XSS:** `XSStrike`
*   **Auditoría Específica de CMS:** `WPScan` (Preparado para detección)

---

## 📜 Historial de Desarrollo (Lo que hemos logrado)

1.  **Motor de Perfilamiento Tecnológico:** Desarrollamos un escáner capaz de leer cabeceras (Headers) y código fuente para inferir con alta confianza si el objetivo usa `Next.js`, `React`, `Vercel`, `Cloudflare`, `Supabase`, `WordPress`, etc.
2.  **Inteligencia de Framework:** Basado en el perfilamiento, FixGuard recomienda vectores de ataque específicos (ej. si es Next.js, buscará `_next/data` leaks o Server Actions; si es Postgres, lanzará inyecciones ciegas).
3.  **Bypass de WAF (Vercel):** Implementamos filtros inteligentes para evitar que herramientas como FFuf se confundan con páginas de error "Catch-All" o Firewalls que bloquean escaneos masivos.
4.  **Integración del Arsenal Pesado:** Creamos scripts de instalación automáticos en Go (`install_arsenal.sh`) e integramos Nmap, Katana, y Waybackurls directamente en el registro de comandos de FixGuard, haciéndolos invocables desde la UI.

---

## 🚀 ROADMAP OFENSIVO: La "Cadena de Matanza" (Kill Chain)

El objetivo a corto/mediano plazo es convertir a FixGuard en un sistema de **encadenamiento automático de exploits**. Actualmente, descubre y lanza comandos, pero el output es texto muerto. El futuro es volverlo interactivo y autónomo.

### Fase 1: Transparencia de Inteligencia Cruda (Próximo Paso Inmediato)
*   **El Problema:** Actualmente Katana o Subfinder retornan un texto como "Se descubrieron 10 endpoints". Esto es inútil para un atacante.
*   **La Solución:** Refactorizar el analizador (`targetedOrchestrator.ts`) usando Expresiones Regulares (Regex) para extraer cada URL, parámetro o subdominio exacto descubierto por las herramientas CLI.
*   **UI:** Mostrar la lista exacta de rutas ocultas descubiertas directamente en la interfaz del Dashboard.

### Fase 2: Módulo de Encadenamiento (Chaining Pivot)
*   **El Problema:** Tienes la URL descubierta, pero copiarla y pegarla en otra herramienta es lento.
*   **La Solución:** Cada URL descubierta por Katana/Wayback que contenga parámetros GET (ej. `?id=5`) se renderizará en la interfaz junto a "Botones de Acción Rápida".
*   **Flujo:** FixGuard descubre `api.target.com/user?id=1` -> La UI muestra un botón **[Lanzar SQLMap a este parámetro]** o **[Lanzar XSStrike]**. Un clic encadena el descubrimiento con la explotación.

### Fase 3: Auto-PWN (Modo Dios Invasivo)
*   **La Cima de la Montaña:** Un botón de "Explotación Total Automática".
*   FixGuard tomará el dominio base. Lanzará `Subfinder` -> Lanzará `Katana` en todos los subdominios -> Filtrará las miles de URLs resultantes buscando parámetros -> Lanzará inyectores invisibles a esos parámetros de forma concurrente -> Si logra romper la base de datos, extraerá las tablas y las mostrará en pantalla. **Sin frenos, sin confirmaciones manuales.**

---

## ⚙️ Instalación del Entorno

1. Instalar dependencias de Node en ambas carpetas (`web` y `worker`): `npm install`
2. Instalar el armamento CLI (Mac/Linux):
```bash
cd worker
./install_arsenal.sh
source ~/.zshrc # (o el equivalente de tu terminal para cargar Go)
```
3. Levantar los servidores:
```bash
# Terminal 1
cd worker && npm run dev
# Terminal 2
cd web && npm run dev
```
