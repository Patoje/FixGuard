# FixGuard - Sistema de Análisis de Seguridad Web

FixGuard es una plataforma de seguridad web que combina técnicas de reconocimiento pasivo y activo para identificar vulnerabilidades en aplicaciones web. Utiliza motores inteligentes de reconocimiento para construir un perfil detallado de la arquitectura de una aplicación y luego aplica técnicas de ataque dirigidas basadas en la información recopilada.

## Arquitectura

El sistema está dividido en dos partes principales:

- **Frontend (web)**: Interfaz de usuario desarrollada con Next.js 16 que permite a los usuarios iniciar escaneos y visualizar resultados
- **Backend (worker)**: Motor de análisis desarrollado con Node.js/Express que ejecuta los escaneos y motores de inteligencia

## Motores Pasivos

Los motores pasivos son módulos que recopilan información sobre la aplicación objetivo sin interactuar directamente con ella de forma agresiva. Estos motores forman la base del proceso de inteligencia (OSINT) y reconocimiento de superficie de ataque. Los principales motores pasivos incluyen:

### 1. TechStackProfiler
Analiza las tecnologías utilizadas en la aplicación mediante:
- Análisis de headers HTTP
- Análisis de cookies
- Análisis de HTML
- Análisis de scripts referenciados
- Análisis de DNS
- Análisis dinámico con Playwright

### 2. Motores de Análisis de Superficie de Ataque
- **AttackSurfaceMapper**: Mapea la superficie de ataque de la aplicación
- **FrameworkIntelligence**: Analiza frameworks específicos (Next.js, etc.)
- **ArchitectureBuilder**: Construye un árbol de arquitectura

### 3. Motores de Análisis de Código y Comunicación
- **JsKnowledgeExtractor**: Extrae conocimiento de archivos JS
- **AuthIntelligenceEngine**: Analiza mecanismos de autenticación
- **CloudIntelligenceEngine**: Analiza servicios en la nube
- **ServerActionsEngine**: Analiza acciones del servidor (Next.js)
- **CommunicationIntelligenceEngine**: Analiza comunicaciones (WebSocket, GraphQL)
- **SubdomainIntelligenceEngine**: Descubre subdominios
- **ArtifactIntelligenceEngine**: Analiza artefactos de desarrollo
- **ParameterIntelligenceEngine**: Analiza parámetros sensibles
- **AIFingerprintEngine**: Detecta tecnologías de IA
- **EntityRelationshipEngine**: Analiza relaciones entre entidades
- **WorkflowReconstructionEngine**: Reconstuye flujos de trabajo
- **CorrelationEngine**: Correlaciona hallazgos para auditoría inteligente

### 4. Motores de Detección de Exposición
- **ExposureIntelligenceEngine**: Enriquece la superficie de ataque con inteligencia
- **SourceMapAnalyzer**: Analiza mapas de origen para encontrar rutas ocultas
- **BreachAnalyzer**: Busca credenciales comprometidas
- **TruffleHogScanner**: Busca secretos en repositorios públicos

### 5. Motores de Descubrimiento Pasivo
- **runSubfinderScan**: Descubre subdominios
- **runHttpxScan**: Verifica hosts vivos
- **runGauScan**: Descubre endpoints usando herramientas como GAU
- **runJsReconScan**: Analiza archivos JS en busca de endpoints

## Ataques Agresivos

Los ataques agresivos se realizan después de la fase de reconocimiento pasivo y están dirigidos específicamente a las vulnerabilidades identificadas. Los principales tipos de ataques incluyen:

### 1. Motores de Ataque Dirigido
- **BolaExploiter**: Genera vectores de ataque para BOLA (Broken Object Level Authorization)
- **MassAssignmentExploiter**: Genera vectores para explotar asignaciones masivas
- **WorkflowBypassExploiter**: Genera vectores para evadir flujos de trabajo
- **React2ShellVector**: Vector específico para explotar vulnerabilidades en Next.js (CVE-2025-55182)

### 2. Motores de Ataque Activo
- **runCrawler**: Realiza crawling inteligente de la aplicación
- **runSsrfScan**: Prueba ataques de Server-Side Request Forgery
- **runBolaScan**: Busca vulnerabilidades de autorización a nivel de objeto
- **runRedirectScan**: Prueba redirecciones abiertas
- **runServerActionsScan**: Prueba vulnerabilidades en acciones del servidor

### 3. Motor de Ejecución de Ataques
- **AttackExecutor**: Ejecuta vectores de ataque inteligentes y compara resultados con una línea base para detectar diferencias significativas que indiquen una vulnerabilidad

## Refinamiento del Ataque con Información Recopilada

La información recopilada por los motores pasivos se utiliza para refinar y dirigir los ataques agresivos de varias maneras:

### 1. Personalización de Vectores de Ataque
Los motores pasivos identifican tecnologías específicas, frameworks y patrones de desarrollo que permiten generar vectores de ataque personalizados. Por ejemplo, si se detecta Next.js, se pueden lanzar vectores específicos como React2Shell que aprovechan vulnerabilidades conocidas en ese framework.

### 2. Priorización de Endpoints
La información recopilada ayuda a priorizar qué endpoints deben ser atacados primero. Los endpoints críticos identificados durante la fase pasiva reciben mayor prioridad en la fase activa.

### 3. Adaptación de Payloads
Según las tecnologías detectadas (bases de datos, lenguajes de backend, frameworks), los payloads se adaptan para ser más efectivos contra el stack tecnológico específico del objetivo.

### 4. Detección de Flujos de Negocio
El análisis de flujos de negocio y relaciones entre entidades permite generar ataques que simulan comportamientos reales de usuarios, aumentando la probabilidad de detectar vulnerabilidades de lógica de negocio.

### 5. Evaluación Inteligente de Resultados
El [AttackExecutor](file:///d:/FixGuard/worker/src/scanner/AttackExecutor.ts#L13-L137) utiliza la información de contexto para evaluar inteligentemente los resultados de los ataques, comparando respuestas con una línea base y detectando cambios sutiles que indican éxito del ataque (como elevación de privilegios o bypass de autorización).

## Flujo de Trabajo

1. **Reconocimiento Pasivo**: Los motores pasivos recopilan información sobre la aplicación objetivo
2. **Análisis de Inteligencia**: La información se correlaciona y se construye un perfil de recon
3. **Generación de Vectores Inteligentes**: Se crean vectores de ataque basados en la información recopilada
4. **Ataque Dirigido**: Los vectores se ejecutan contra los endpoints relevantes
5. **Evaluación de Resultados**: Se comparan las respuestas para determinar éxito del ataque
6. **Reporte de Hallazgos**: Se registran las vulnerabilidades detectadas

## Componentes Clave

- **SessionManager**: Gestiona sesiones de usuario para ataques que requieren autenticación
- **IssueManager**: Registra y gestiona los hallazgos de vulnerabilidades
- **SessionHeartbeat**: Mantiene sesiones activas durante escaneos prolongados
- **PipelineSelector**: Detecta el tipo de pipeline de CI/CD para personalizar los ataques

## Tecnologías

- Frontend: Next.js 16, React 19, TypeScript
- Backend: Node.js, Express, TypeScript
- Base de datos: Neon Database (PostgreSQL serverless)
- ORM: Drizzle ORM
- Motor de análisis: Playwright, Wappalyzer, Cheerio
- Herramientas de seguridad: TruffleHog, Nuclei (referenciado)

FixGuard representa un enfoque moderno y dirigido por inteligencia para la identificación de vulnerabilidades, donde la fase de reconocimiento pasivo alimenta directamente la efectividad de los ataques activos, reduciendo falsos positivos y aumentando la probabilidad de descubrir vulnerabilidades reales.