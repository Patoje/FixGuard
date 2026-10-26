# Análisis estratégico: profundidad y calidad del reconocimiento en FixGuard V2

**Tipo de documento**: análisis para discutir, NO una ADR ni una decisión tomada. No se modificó ningún archivo de código, no se corrió ningún escaneo contra un target, no se creó ni modificó ningún test. Todo lo marcado **VERIFICADO** fue leído directamente del código fuente (archivo:línea citado). Todo lo marcado **SOSPECHADO** es una inferencia razonable sin confirmar contra el código o contra una corrida real.

**Metodología**: 4 investigaciones de solo-lectura en paralelo sobre el código real (no la documentación primero): motores de recon y sus límites, clasificación de evidencia/findings, orquestación e inteligencia, y qué ya estaba documentado en `docs/` sobre estos temas. Las citas de archivo:línea de este documento vienen de esas lecturas directas.

---

## 0. El hallazgo que condiciona todo lo demás — RESUELTO (2026-10-25, Hito 2)

**Resolución**: no es un bug — es `ADR-005` (`docs/DECISIONS.md:92-113`), una decisión de producto ya documentada y vigente. Se le preguntó al usuario si revertirla (todo pasa por aprobación humana) o mantenerla y cerrar sus agujeros internos; eligió **mantener ADR-005**. El agujero real cerrado: de los 24 `detectionKind` elegibles, 7 no tenían ningún gate de completitud (`jwt_algorithm_confusion`, `sql_error_oracle`, `subdomain_takeover`, `session_fixation`, `cors_idor_compound`, `cross_finding_chain`, `dependency_vulnerability`) y promovían apenas eran elegibles por categoría, sin chequear que la evidencia estuviera completa. Ver `docs/DECISIONS.md` ADR-005 Addendum para el detalle de los 7 gates nuevos y la tabla de equivalencia de los 3 vocabularios epistémicos (segunda mitad de este hito). Verificado con 15 casos nuevos en `smoke:v2:finding-auto-promotion` + `typecheck:v2`, ambos en 0.

El texto original del hallazgo queda abajo, sin editar, como registro de lo que se encontró antes de resolverlo:

Antes de entrar en las 5 áreas pedidas, un hallazgo que no es sobre profundidad de recon sino sobre **confianza en el sistema de clasificación**, y que contamina cualquier conclusión de "0 hallazgos" si no se resuelve primero.

Existen **dos módulos distintos, con nombre de archivo casi idéntico, en carpetas distintas**, con comportamiento opuesto:

- `worker/src/v2/finding-candidate-promotion/FindingAutoPromotionPolicy.ts` — gatea estrictamente por `humanReviewDecision.decision === 'approve_evidence'`. Este es el único que el audit R5 (`docs/decisions/R5-detector-confirmation-audit.md`) revisó, y su conclusión ("ningún detector auto-crea un Finding sin aprobación humana explícita") es **correcta para este módulo**.
- `worker/src/v2/finding-auto-promotion/FindingAutoPromotionPolicy.ts` — **fuera del alcance que R5 declaró explícitamente** (`R5-detector-confirmation-audit.md:3`, limitado a `worker/src/v2/detection/`). Su propio comentario de cabecera dice: *"Human authorization remains required for AttackPlan execute. Confirmed/observed vulnerability signals with attack value auto-promote to Finding."* (líneas 1-8). La función `evaluateFindingAutoPromotion` (líneas 512-560) toma 24 tipos de draft listados en `AUTO_PROMOTE_ELIGIBLE` (líneas 42-67) — incluyendo `information_disclosure`, `session_fixation`, `subdomain_takeover`, `weak_tls_configuration`, `dependency_vulnerability`, `blind_ssrf`/`blind_xss` — y, si pasan un filtro de ruido por tipo (`evaluateSignalGate`), devuelve `decision: 'auto_promote'`. **No hay ningún chequeo de `humanReviewDecision` en toda la función.**

Se trazó el call site real: `applyFindingAutoPromotion` (`FindingAutoPromotionService.ts:743`) se llama en vivo desde `OrchestratedAssessmentApplicationService.ts:6540` y `:6845`, sobre el mismo array `pendingEvidenceDrafts` que llena `runReadDetectionPass` — el paso **100% automático** del pipeline, sin humano en el loop, invocado en `OrchestratedAssessmentApplicationService.ts:5954`. `ReadDetectionPass.ts` nunca pasa `humanReviewDecision` a ningún detector (confirmado por grep: cero ocurrencias). El filtro de ruido para `information_disclosure` solo bloquea `framework_version`/`server_banner`; para `stack_trace` o `internal_path` no hay caso en el filtro → `auto_promote` incondicional. `session_fixation`, `subdomain_takeover` y `dependency_vulnerability` **no tienen ningún caso** en el filtro de ruido (caen al `default: return null`) → auto-promoción incondicional, sin filtro alguno, apenas son elegibles.

**Esto es una decisión de producto documentada en el propio código, no un bug accidental** — pero está en tensión directa con la regla literal de AGENTS.md: *"Never assign automatic severities... or automated remediation recipes without human authorization and real target validation."* Y tiene una consecuencia práctica inmediata para este proyecto: el "0 hallazgos" que viste en las 3 corridas reales de hoy **no prueba que todo pasa por revisión humana** — prueba que, en esas corridas puntuales, ningún draft de esos 24 tipos elegibles llegó a dispararse. No se puede saber si eso es "no había nada" o "el filtro de ruido lo bloqueó correctamente" solo leyendo código (esto mismo lo señaló la investigación, sin inventar un resultado que no se corrió).

**No es un hallazgo de profundidad de recon** — es un hallazgo de gobernanza de datos que toca directamente tu pedido de "cómo clasificamos y presentamos lo descubierto" (área 1). Lo marco en 0 porque cualquier medición de "mejoramos la calidad/cantidad de hallazgos" en las fases siguientes necesita primero saber si lo que se mide pasó por humano o no.

---

## 1. Calidad de la información

### 1.1 Qué es cada cosa — VERIFICADO, y es más riguroso de lo que esperaba

El sistema sí distingue observación de hipótesis de evidencia de finding, con tipos reales, no solo convención:

- **Observación cruda**: 33 interfaces `*Metadata` en `worker/src/v2/core/Evidence.ts:1-507`, una por detector, cada una con campos realmente observados (código de status, hash de body, lista de headers) — no texto libre.
- **Finding**: `Evidence.ts:548-559` — `{id, type, severity, confidence, metadata, verificationState}`.
- **VerificationState**: `core/VerificationStateContracts.ts:6-17` — cadena de 5 estados, **solo hacia adelante**: `observed_anomaly → suspected_vulnerability → validated_vulnerability → exploitability_confirmed → impact_confirmed`. `advanceState` no permite saltar más de un escalón; `refuteState` solo puede bajar de categoría. Esto es la disciplina OBSERVED/INFERRED/VALIDATED/CONFIRMED de AGENTS.md **aplicada en código**, no solo en prosa.
- **Hipótesis**: `SecurityHypothesis` (`HypothesisSchedulerContracts.ts:109-150`) con `epistemicStatus: 'INFERRED'|'OBSERVED'|'RECOMMENDED'`.
- **Grafo de superficie**: `AttackSurfaceContracts.ts:24` define un **tercer** vocabulario epistémico: `'OBSERVED'|'INFERRED'|'VERIFIED'|'REFUTED'|'INCONCLUSIVE'` (5 valores, distintos de los otros dos).

**Problema real que esto expone** (síntesis mía, no de un fork — se desprende de comparar los 3 hallazgos anteriores): hay **tres vocabularios de "qué tan seguro estoy"** en el sistema — el de 5 estados de `VerificationState`, el de 3 valores de `SecurityHypothesis.epistemicStatus`, y el de 5 valores de `AttackSurfaceContracts.EpistemicStatus` — sin una tabla de equivalencia documentada entre ellos. No es necesariamente un error, pero si en el futuro alguien quiere mostrarte "qué tan confiable es este dato" en una sola pantalla, hoy tendría que traducir a mano entre tres sistemas distintos.

### 1.2 Deduplicación — VERIFICADO: estrecha, no semántica

`grep` de "dedup"/"canonicaliz" en todo `src/v2` da solo dos resultados reales:
- `AttackPlanGeneratorService.ts:72-78` — dedup por **colisión exacta de planId** dentro de un mismo batch de generación.
- `AttackSurfaceGraphBuilder.ts:537-540` — dedup de nodos por hash (`stableId`, sha256 truncado) dentro de la construcción de **un** grafo.

**No existe dedup semántico entre motores ni entre corridas.** Si Naabu+Httpx y Playwright descubren el mismo endpoint por rutas distintas, y cada uno dispara un draft de evidencia relacionado, ambos se convierten en Findings/drafts independientes con ids distintos — confirmado ausente, no solo "no encontrado".

Además, el dedup de URLs en la fase de crawling (`CompositeActiveReconOrchestratorService`) es **match de string exacto** contra un `Set` (`knownUrlInventory`) — no canonicaliza query params. `/x?a=1&b=2` y `/x?b=2&a=1` cuentan como dos endpoints distintos. Esto infla conteos sin agregar superficie real — es un problema de calidad, no de profundidad.

### 1.3 Relaciones entre entidades — VERIFICADO: el grafo es bueno, el "correlacionador" es débil

`AttackSurfaceGraphBuilder.ts` (803 líneas) es un modelo real y bastante rico: nodos (dominio, app, subdominio, IP, puerto, servicio, endpoint, parámetro, identidad, sesión, vulnerabilidad, `service_boundary` — agrupación por prefijo de path) y 14 tipos de arista (`hosts`, `resolves_to`, `reachable_from`, `exposes`, `serves`, `accepts`, `requires_auth`, `authenticated_by`, `has_vulnerability`, `enables_attack`, `observed_as_accessible_by`, `groups`, etc. — `AttackSurfaceContracts.ts:47-63`). El dedup de nodos es por hash de contenido: el mismo endpoint descubierto por recon Y por extracción estática de código colapsa en un solo nodo.

**No modelado**: parámetros con el mismo nombre compartidos entre distintos endpoints; versión de tecnología detectada vinculada a un CVE conocido; una arista distinta para "comparte boundary de autenticación" (hoy solo existe `requires_auth`, que es por-endpoint, no agregada).

`CrossFindingChainCorrelator.ts`, en cambio, es **más débil de lo que su nombre sugiere**: hace un producto cartesiano de categorías (`PRIMARY_ACCESS_VECTORS` × `SECONDARY_DISCLOSURE_VECTORS`, líneas 39-69) agrupando por `finding.metadata.kind`/`finding.type` únicamente — empareja **todo** primario con **todo** secundario sin chequear si comparten endpoint, origen o parámetro. Un CORS en `/login` y un disclosure sin relación en `/sitemap.xml` se encadenan como "ruta de ataque compuesta" sin ningún contexto compartido real. Cuando un humano aprueba (`approve_evidence`), el Finding resultante recibe `severity: 'critical'`, `confidence: 1.0`, `compoundImpactScore: 0.95` **hardcodeado** (líneas 185-189) — no derivado de los datos reales emparejados.

> **IMPLEMENTADO (2026-10-26, Hito/R10)**: el correlacionador ya exige que ambos `target` normalicen (`normalizeOriginFromUrl`, mismo patrón que `CorsIdorChainCorrelator`) a un origen no-nulo e igual antes de formar el par — un CORS en `/login` y un disclosure en otro origen ya no se encadenan. `FindingAutoPromotionPolicy`'s gate `cross_finding_chain` exige además que ese `sharedOrigin` sobreviva y sea un origen normalizado válido (`reasonCode: 'cross_finding_chain_shared_origin_missing'` si no). **Límite explícito, sin resolver**: mismo origen no prueba relación causal ni explotable — es la precondición mínima verificable con los datos que estos findings traen, nada más. El `severity: 'critical'`/`confidence: 1.0` hardcodeado mencionado arriba **sigue sin cambiar y sin validarse** por este hito. Ver Milestone R10 en `docs/ROADMAP.md`.

### 1.4 Confianza / reducción de falsos positivos — VERIFICADO, categorizado

De los ~30 detectores bajo `worker/src/v2/detection/`:

- **Fuertes (diferencial/canary real)**: Idor, CorsMisconfiguration, CredentialedCors, ParameterReflection, AuthBoundaryDifferential (vía `ResponseComparatorService`); OpenRedirect (inyecta una URL canario y verifica que el header `Location` la contenga literalmente — `OpenRedirectDetectionService.ts:64`); BlindSsrf/BlindXss (callback OOB real). R5 los llama "entre los más rigurosos" — congelados por ADR-013 por política de producto, no por debilidad de señal.
- **Sólidos, de un solo hecho objetivo**: SecurityHeader, InformationDisclosure, SourcemapExposure, ManifestExposure, GraphQLSurface, TlsConfigurationAnalysis, ParameterIntegrity.
- **Sólidos, diferencial de status/header**: ApiVersioningSprawl, CmsPluginVulnerability, DependencyConfusion, WordPressSurface, HttpMethodManipulation, SessionFixation, NextServerActionDifferential (corregido el 25/10).
- **Heurística débil, todavía viva**: AuthBypassDetectionService — similitud de texto ≥0.85 entre body autenticado y anónimo, no prueba estructural. Congelado, no alcanzable en producción hoy según R5.
- **Corregido recientemente**: JwtAlgorithmConfusion ahora exige un probe de control (firma corrupta rechazada) antes de confiar en un bypass `alg:none`.
- **Retirados de verdad** (no solo etiquetados): ObjectMappingAnomaly, StateTransitionAnomaly — borrados el 25/10.
- **Gap nuevo, no cubierto por R5**: `SqlErrorOracleDetectionService.ts:255` — un solo canario inyectado + match de firma de error, **sin control negativo** que confirme que un parámetro benigno/sin modificar no dispara la misma firma de error (ej. una página 500 genérica). R5 no lo marcó porque su tabla no llegó a este detector específico.

---

## 2. Profundidad del reconocimiento

Pipeline real: `CompositeActiveReconOrchestratorService.ts` (2698 líneas), **5 etapas secuenciales fijas**, hosts procesados en serie dentro de cada etapa, con `AdapterPreflightPipeline` + `TargetExecutionCoordinator` (rate limit/circuit breaker) como gates.

**Etapa 1 — Dominio/zona**: Subfinder + crt.sh (passive CT-log), Dnsx resuelve cada host único. **No hay bruteforce activo de subdominios** (sin wordlist) — solo agregación de fuentes pasivas.

**Etapa 2 — Puertos**: Naabu únicamente, `rate: 100` hardcodeado (`:777`). **No hay nmap en ningún lugar de `src/v2`** (grep confirmado — "nmap" solo aparece en nombres de archivos de smoke tests, nunca en un adapter real). Sin fingerprinting de versión de servicio (`-sV`), sin scripts NSE, sin UDP.

**Etapa 3 — HTTP/TLS**: Httpx + Tlsx, más un frontier de crawling adaptativo (`PriorityReconFrontierService`) que extrae links/rutas de HTML y hace BFS. Límites reales y concretos: presupuesto de 150 requests por assessment (líneas 1113-1116); profundidad configurada en 3 pero **el código fuerza un tope real de 2 saltos** — hay un comentario explícito ("no third hop") y la lógica en líneas 1296-1299/1332 lo hace cumplir sin importar el valor de config; máximo 500 rutas por salto 1 y por salto 2; corte por saturación tras 10 duplicados. Maneja challenges/CAPTCHA (403/503/429) con reintento vía browser, tope de 3 continuaciones por assessment.

> **IMPLEMENTADO (2026-10-26, Hito/R10)**: el tope de 2 saltos no se tocó (sigue hardcodeado), pero ahora deja señal. `ReconHealthSignals` tiene `crawlTruncatedByDepthCap`/`depthCappedPagesNotMinedCount`, contados solo cuando el body **efectivo** (el de la página real post-challenge-resuelto, nunca el HTML del challenge/interstitial en sí) es no vacío y el gate de profundidad lo bloqueó — a lo sumo un conteo por URL del frontier, nunca por un challenge sin resolver. `ReconHealthClassificationService` agrega `crawl_depth_cap_reached` a `reasonCodes` (sin status nuevo), y el texto de advertencia ya no afirma "todas las rutas alcanzables descubiertas" cuando esto ocurrió. Nunca sugiere subir `crawlMaxDepth` — el gate hardcodeado lo ignoraría igual. Ver Milestone R10 en `docs/ROADMAP.md`.

**Etapa 4 — Crawling/parámetros**: Katana (depth 3) + Gau en paralelo — **Gau ya cubre URLs históricas/wayback** (fuente `archive_legacy`), no falta un adapter separado de wayback. Ffuf+Arjun (fuzzing de contenido/parámetros) solo contra **máximo 3 URLs raíz por assessment** (`MAX_LEGACY_FUZZ_ROOTS = 3`) — no contra todo el inventario de endpoints descubiertos. Arjun tiene un timeout tope de 45s sin importar config. Jsluice (minería de JS) tope de 16 archivos/assessment en 2 pasadas; extracción de sourcemaps tope de 4 archivos — para una SPA con decenas de chunks, la mayoría nunca se analiza.

**PlaywrightSpaAdapter**: ejecuta JS real (Chromium headless), espera hidratación (5s fijo + 2s de networkidle best-effort), captura XHR/fetch en vuelo pasivamente, y después hace **extracción estática del DOM** post-carga (`querySelectorAll('a[href]')`, forms+inputs, `script[src]`). **Confirmado: sin click, sin scroll, sin navegación multi-paso, sin submit de formularios** (grep de `.click(` da cero resultados). Tope de 5 páginas por assessment, 40 rutas y 40 URLs de red por página.

**Etapa 5 — Secretos**: Trufflehog sobre JS/bodies recolectados.

**Auth/sesión diferencial**: `AuthDifferentialMatrixService.ts` compara anónimo vs autenticado para el **mismo** endpoint, pero necesita que la sesión ya venga dada desde afuera. **FixGuard no puede loguearse solo.** La única vía autenticada es BYOT (Bring-Your-Own-Token): el operador provee cookies/Bearer/`FG_ACCESS_TOKEN`, opcionalmente cosechados de una sesión Playwright/CDP ya autenticada manualmente.

**GraphQL**: una sola query de introspección para detectar si está habilitada (finding de disclosure) — **no camina el schema** para generar más hipótesis de endpoints/mutaciones.

**Confirmado ausente del código** (grepeado, no solo "no documentado"): fingerprinting de versión de servicio tipo nmap; identificación dedicada de WAF/CDN (solo heurística básica de headers); enumeración de buckets cloud (S3/GCS/Azure); descubrimiento/testing de websockets; bruteforce de subdominios; recorrido completo de schema GraphQL.

---

## 3. Amplitud de cobertura — qué falta vs. qué mejorar

Comparando el inventario verificado (sección 2) contra técnicas DAST conocidas, y relacionando cada una con una carencia concreta ya identificada arriba — no es una lista genérica:

| Técnica | Por qué importa acá específicamente | Esfuerzo | Mejora motor existente o agrega uno nuevo |
|---|---|---|---|
| nmap real (`-sV` + NSE opcional) | Naabu dice "puerto abierto". Nada en todo el sistema vincula versión de software→CVE conocido (confirmado ausente en el grafo, sección 1.3). Sin esto, un puerto abierto con software vulnerable y un puerto abierto con software parchado se ven idénticos. | Medio | Agrega uno nuevo, complementa Naabu |
| Identificación real de WAF/CDN | Hoy solo heurística de headers. Un bloqueo de WAF y "no hay vulnerabilidad" se ven igual en los resultados — justo el riesgo que ya se documentó en Proposal E y que probablemente se materializó hoy en las corridas contra firma-nu/negocios-inmobiliarios (ver el mensaje anterior de esta sesión). | Medio | Mejora la lectura de motores existentes |
| GraphQL schema walk | Hoy, si la introspección está habilitada, se reporta como disclosure y se para ahí — se desaprovecha la oportunidad de generar más hipótesis reales. | Medio | Mejora motor existente |
| Login/crawling autenticado propio | Hoy 100% dependiente de BYOT externo — la superficie post-login de cualquier app real queda invisible salvo que el operador haga todo el trabajo afuera. Es la limitación estructural más grande para "visión completa de cómo funciona la aplicación", que es tu pedido explícito. | Alto | Agrega capacidad nueva |
| Canonicalización de query-params en dedup | Hoy inflando conteos de "endpoints" sin agregar superficie real (sección 1.2) — mejora calidad antes que cantidad. | Bajo | Mejora motor existente |
| Bruteforce de subdominios (wordlist) | Las fuentes pasivas (Subfinder+crt.sh) no ven subdominios no indexados (staging, admin, interno). | Bajo-medio | Agrega uno nuevo |
| Interacción real en Playwright (click/scroll/submit) | Hoy solo DOM estático post-carga — contenido que aparece solo tras interacción (tabs, acordeones, "cargar más") nunca se descubre. | Alto | Mejora motor existente, cambio de comportamiento grande |
| Enumeración de buckets cloud (S3/GCS/Azure) | Clase de misconfiguración real y común en DAST, cobertura cero hoy. Valor concreto en estos 3 targets específicos: incierto sin probarlo (son apps chicas en Vercel, no necesariamente usan buckets propios). | Bajo-medio | Agrega uno nuevo |
| Descubrimiento/testing de websockets | SPAs modernas (como tus 3 targets) frecuentemente usan websockets/SSE — cobertura cero hoy. | Medio | Agrega uno nuevo |

**Nota explícita pedida**: ninguna de estas se descarta por "agresiva" o "ruidosa" — se evalúa solo por qué carencia concreta cierra. Las marcadas "agrega uno nuevo" son estrictamente más tráfico/ruido; dijiste que eso es aceptable si suma información real, así que el criterio de inclusión aquí fue "¿qué evidencia produce", no "¿es intrusiva".

---

## 4. Orquestación e inteligencia

**El loop canónico** (`InvestigationRuntimeCoordinator.ts`, documentado en su propio docstring): DISCOVERY → HYPOTHESIS → SCHEDULE → JIT PLAN → AUTHORIZE → EXECUTE → COMPARE → FEEDBACK → RESCHEDULE. El dedup de hipótesis existe pero es angosto: clave = `capability + normalizedRoutePattern` (`stableHypothesisId`, línea 513) — dos fuentes de descubrimiento distintas que llegan a la misma capability+ruta sí colapsan en una hipótesis; nada más amplio que eso.

**Hallazgo real de redundancia, VERIFICADO**: existen **dos schedulers de hipótesis independientes, no reconciliados**:
- `HypothesisSchedulerService.ts` (472 líneas) — basado en reglas, orientado al dossier, con heurísticas conscientes de stack (ej. despriorizar spray de superficie SPA en Vercel+Next) y los únicos 2 contadores de "gap de superficie" que existen en todo el sistema (`unclassifiedEndpointCount`, `unknownAuthRequirementEndpointCount`).
- `InvestigationHypothesisScheduler.ts` (847 líneas), función `scheduleNextInvestigation` — alimenta solo el loop de lectura en vivo, con su propio scoring.

No comparten lógica de scoring ni estado, y nada en el código los valida entre sí. No es un error de cableado — ambos tienen llamadores reales confirmados — pero es una fuente de inconsistencia: un tipo de hipótesis agregado a uno no es automáticamente visible para el otro.

**El dato de cobertura ya existe, el cálculo no**: `AttackSurfaceGraphBuilder` ya agrupa endpoints por `service_boundary` (prefijo de path). Un grep de "coverage"/"unexplored" en todo `src/v2` da **cero resultados reales** (solo un comentario suelto). Nada calcula, por ejemplo, "`/admin` tiene 12 endpoints, solo 3 fueron probados" — aunque el grafo ya tiene la agrupación necesaria para hacerlo. Es una mejora estructuralmente barata: el dato está, falta la función que lo recorra.

> **IMPLEMENTADO (2026-10-25, Hito 3), corregido 2026-10-25**: `OrchestratedAssessmentApplicationService.getPlanningActivitySummary()` (renombrado desde `getCoverageSummary` tras la auditoría — el nombre original implicaba cobertura de investigación/ejecución real que el sistema no puede demostrar) cierra la medición de "zonas menos planificadas". Mide actividad de planificación (`plannedEndpoints` vs `actionableEndpoints`, excluyendo `rejected`/`superseded` solo de este último), nunca investigación o ejecución real — no existe un registro de ejecución persistente para demostrar eso. Ver Milestone R9 en `docs/ROADMAP.md`.

**La secuencia de recon es fija, no adaptativa**: las 5 etapas de `CompositeActiveReconOrchestratorService` siempre corren salvo que el *llamador* las salte explícitamente (`config.skipStages`) — no hay ramificación interna tipo "encontré un endpoint GraphQL en la etapa 3 → disparo un probe GraphQL más profundo dentro de esta misma pasada". Toda la adaptividad real del sistema vive río abajo, dentro del loop de hipótesis, que reacciona a superficie ya descubierta pero **no puede disparar una nueva etapa de recon** — solo puede pedir `AttackPlan`s ya registrables sobre lo que ya se encontró.

---

## 5. Evaluación real — cómo medir sin inventar resultados

Hoy no existe ninguna metodología de medición de cobertura/profundidad en el código ni en la documentación (confirmado por grep y por revisión de ROADMAP/implementation_plan). Propuesta concreta, usando solo datos que el sistema ya puede producir:

1. **Cobertura por boundary** (requiere la mejora de la sección 4): una vez calculada, da un número honesto de "cuánto de lo que encontramos realmente probamos" por corrida — comparable antes/después sin inventar nada.
2. **Tasa de saturación de topes**: instrumentar cuántas veces una corrida real pega contra un cap (150 requests, 2 saltos, 5 páginas de Playwright, 3 raíces de fuzzing, 16 archivos JS). Hoy esto es invisible — "llegamos al tope y paramos" y "no había más superficie real" se ven idénticos en la salida. Bajar la tasa de saturación tras subir los caps es la prueba real de que se profundizó, no solo que se generó más ruido.
3. **Precisión de detectores débiles contra fixtures etiquetados**: para los heurísticos marcados en la sección 1.4 (AuthBypass, SqlErrorOracle sin control negativo), correrlos contra un par de fixtures de laboratorio conocido-limpio/conocido-vulnerable (no contra un target real) para sacar una tasa de falsos positivos real en vez de asumida.
4. **Protocolo antes/después**: correr los mismos 3 targets autorizados con cada cambio, y no reportar "mejoró" solo por un aumento de conteo — samplear a mano un subconjunto de lo nuevo para confirmar que es señal real y no solo ruido adicional. Es exactamente la disciplina que se aplicó hoy con los resultados de CORS/open-redirect: "0 confirmados" en `inmobiliaria-cornejo-web-rho` fue un resultado confiable porque se verificó que cada probe corrió de verdad; en los otros 2 targets no se pudo concluir nada porque el recon volvió degradado, y eso se reportó explícitamente en vez de asumir "están limpios".
5. **Pre-login vs post-login** (si se implementa la Estrategia 2 de la sección 7): medir endpoints nuevos descubiertos después de loguearse en el mismo target. Si no agrega superficie relevante, esa inversión no valió la pena ahí — resultado que se mide, no se asume de antemano.

---

## 6. Limitaciones encontradas — verificadas vs. sospechadas

**VERIFICADAS (leídas directo del código, archivo:línea citado arriba)**:
- Auto-promoción de 24 tipos de finding sin revisión humana, fuera del alcance del audit R5 (sección 0).
- Tope real de crawl de 2 saltos (no 3), 150 requests/assessment, fuzzing solo en 3 URLs raíz, Playwright sin interacción real, sin nmap, sin bruteforce de subdominios, sin login propio. *(El tope en sí sigue igual; desde R10 queda observable — ver sección 2.)*
- Dedup solo por match exacto (URL completa o planId/nodo) — sin canonicalización semántica.
- `CrossFindingChainCorrelator` hace producto cartesiano por categoría, no correlación estructural, y hardcodea severidad/confianza del resultado combinado. *(Desde R10, el emparejamiento exige mismo origen normalizado — la severidad/confianza hardcodeada sigue sin cambiar; ver sección 1.3.)*
- Dos schedulers de hipótesis no reconciliados.
- Cero métrica de cobertura, aunque el dato para calcularla ya existe en el grafo.
- Pipeline de recon fijo, sin ramificación adaptativa interna.
- `SqlErrorOracleDetectionService` sin control negativo (gap no cubierto por R5).

**SOSPECHADAS (inferencia razonable, no confirmada)**:
- Que el recon degradado de hoy en firma-nu/negocios-inmobiliarios se debió a rate-limiting de Cloudflare/Vercel tras las corridas repetidas — es la explicación más probable dado el patrón, pero no se verificó con un código de status real.
- Que remover `wappalyzer` (Proposal C, ya implementada) redujo señal real de fingerprinting de tecnología — no se comparó antes/después directamente.
- Que los 24 tipos elegibles para auto-promoción se disparan con frecuencia no trivial contra targets reales — no distinguible solo leyendo código, requeriría una corrida real (fuera de alcance de este análisis, que explícitamente no ejecutó escaneos).
- Que agregar login propio (Estrategia 2, sección 7) de hecho revelaría superficie significativa en estos 3 targets puntuales — es la hipótesis de mayor apalancamiento teórico, pero no probada en estas apps específicas.

---

## 7. Estrategias posibles (no son pasos secuenciales obligatorios — son caminos alternativos)

**Estrategia A — Profundizar lo existente (bajo riesgo, incremental)**: subir los topes de crawl/fuzzing ahora que aceptás más tráfico/ruido, canonicalizar el dedup de query-params, cerrar o documentar explícitamente el gap de auto-promoción, calcular cobertura por boundary. No agrega motores nuevos. Rápido, bajo riesgo — pero no toca la limitación estructural más grande (autenticación).

**Estrategia B — Cerrar el gap de autenticación**: construir una capacidad de login real (el operador da credenciales de prueba + un flujo de login, FixGuard lo ejecuta vía Playwright y mantiene la sesión durante todo el recon), en vez de depender 100% de BYOT externo. Es el cambio de mayor apalancamiento teórico — la superficie post-login de casi cualquier app real hoy es invisible. Coincide exactamente con tu pedido de "visión lo más completa posible de cómo funcionan sus aplicaciones". Riesgo: maneja credenciales (las reglas de manejo seguro de este entorno aplican con fuerza acá), mayor complejidad de implementación.

**Estrategia C — Ampliar motores con foco en clasificación, no solo descubrimiento**: agregar nmap (versión→CVE), identificación de WAF, GraphQL schema walk — herramientas que no necesariamente descubren más URLs, pero convierten "puerto 443 abierto" en "nginx 1.18, con CVE conocido". Ataca directo tu pedido de calidad de información, no solo cantidad.

**Estrategia D — Arreglar la inteligencia antes de sumar motores**: reconciliar los 2 schedulers, calcular cobertura real, arreglar el correlacionador de cadenas y el gap de auto-promoción, antes de agregar cualquier motor nuevo — para que lo que se agregue después entre a un sistema que ya deduplica/correlaciona bien, en vez de sumar más ruido a una capa de inteligencia con huecos ya conocidos.

Estas no son mutuamente excluyentes — se pueden combinar y secuenciar.

---

## 8. Mejoras ordenadas por impacto / esfuerzo / dependencias

| # | Mejora | Impacto | Esfuerzo | Depende de | Estrategia |
|---|---|---|---|---|---|
| 1 | Cerrar o documentar explícitamente el gap de auto-promoción sin revisión humana | Crítico (gobernanza/confianza) | Bajo | — | A/D |
| 2 | Calcular cobertura por `service_boundary` desde el grafo ya existente | Alto | Bajo | — | D — **IMPLEMENTADO 2026-10-25 (Hito 3/R9)** |
| 3 | Subir topes de crawl/fuzzing/Playwright (ya soportado por config) | Medio-alto | Bajo | — | A |
| 4 | Canonicalizar query-params en dedup de URLs | Medio | Bajo | — | A |
| 5 | Reconciliar los 2 schedulers de hipótesis (o documentar y testear por qué coexisten) | Medio | Medio | — | D |
| 6 | Arreglar `CrossFindingChainCorrelator` (chequear contexto compartido real, no hardcodear severidad) | Medio | Medio | — | D |
| 7 | nmap real (versión de servicio + NSE opcional) | Medio-alto | Medio | — | C |
| 8 | Identificación real de WAF/CDN | Medio | Medio | — | C |
| 9 | GraphQL schema walk cuando introspección está habilitada | Medio | Medio | — | C |
| 10 | Login/crawling autenticado propio | Alto | Alto | Decisión sobre manejo de credenciales | B |
| 11 | Interacción real en Playwright (click/scroll/submit) | Medio | Alto | — | A/C |
| 12 | Bruteforce de subdominios, enumeración de buckets cloud, websockets | Bajo-medio cada una | Bajo-medio cada una | — | C |

---

## 9. Recomendación y criterios de éxito

**Orden sugerido**: Fase 0 (ítem 1, gobernanza) → Fase 1 (ítems 2-4, barato y ya soportado por config, debería mostrar sustancialmente más superficie real en los 3 targets actuales sin tocar arquitectura) → Fase 2 (ítem 10, el cambio de mayor apalancamiento, pero el más caro y sensible) → Fase 3 (ítems 7-9, calidad de clasificación sobre lo ya encontrado) → Fase 4 (ítems 11-12, evaluar solo si las fases anteriores no alcanzan).

**Por qué este orden**: el ítem 1 contamina cualquier medición si no se resuelve primero. Los ítems 2-4 son baratos, no requieren decisión arquitectónica nueva, y dan la métrica de cobertura que hace falta para juzgar honestamente todo lo que viene después. El ítem 10 es el que más cambiaría "cuánto vemos de verdad" de una aplicación real — pero es la pieza más grande y la única que toca manejo de credenciales, así que no es la primera.

**Criterios concretos para saber si mejoró de verdad** (ya detallados en la sección 5, resumidos):
- Re-correr los mismos 3 targets autorizados antes/después de cada fase.
- Comparar cobertura por boundary (nueva métrica) y tasa de saturación de topes — bajar esta última es la prueba de que se profundizó, no solo que se generó más tráfico.
- Para el login propio: medir endpoints nuevos post-login vs pre-login en el mismo target — sin asumir de antemano que va a valer la pena.
- Para nmap/WAF/GraphQL: medir cuántos hallazgos existentes ganan contexto verificado adicional, no cuántos hallazgos nuevos aparecen.
- Ningún número se reporta como mejora sin un diff real contra los mismos targets — la misma disciplina aplicada hoy al confirmar (y descartar) el "0 vulnerabilidades" en los 3 targets reales.

---

## 10. Addendum (mismo día) — diagnóstico forense de la degradación: causa raíz confirmada

**Qué se investigó**: no se corrió ningún escaneo nuevo. Se inspeccionaron directamente los registros ya persistidos en `.dev_cache/orchestrated_assessments.json` (17 assessments reales, de las 5 corridas de hoy) y se cruzó contra `ChallengeClassifierService.ts` y la lógica de reintento en `CompositeActiveReconOrchestratorService.ts:891-960`. Esto corrige y reemplaza la hipótesis "sospechada" de la sección 6 original de este documento, que atribuía la degradación a rate-limiting sin evidencia suficiente — eso fue un error, aquí está la causa real con cifras exactas.

### Hallazgo verificado — no es rate-limiting, es un challenge de verificación JS

Comparando `stage_3_web_tls` y `stage_4_crawling_parameters` entre corridas sanas y degradadas del mismo dominio:

| Corrida | Dominio | warnings de stage 3 | observationsCount stage 4 | planes totales |
|---|---|---|---|---|
| p2bjsh (degradada) | firma-nu | `Edge challenge detected ... js_browser_verification_challenge` (×4) + `Challenge continuation budget exhausted (limit 3)` | 12 | 6 |
| 8z5u77 (sana) | firma-nu | `Crawl frontier exhausted: all reachable in-scope HTML routes discovered` | 172 | 96 |
| hbmkj8 (degradada) | firma-nu | mismo patrón de challenge que p2bjsh | 12 | 6 |
| 31zc82 (degradada) | negocios-inmobiliarios | mismo patrón de challenge | 12 | 6 |
| rilfqd (sana) | negocios-inmobiliarios | `Crawl frontier reached duplicate saturation` (sin challenge) | 262 | 58 |
| 7jgw09 / gdmlhf / cylzce (las 3 corridas muestreadas) | inmobiliaria-cornejo | `Crawl frontier exhausted` (sin challenge, ninguna vez) | 64 (idéntico en las 3) | 26 |

**Mecanismo verificado en código**: `ChallengeClassifierService.ts:82-98` clasifica `js_browser_verification_challenge` solo cuando el status es 403 o 503 **y** el body contiene una marca explícita de challenge (`vercel security checkpoint`, `cf-browser-verification`, `just a moment`, `challenge-platform`, `turnstile`, etc. — `ChallengeClassifierService.ts:25-26`). Es un chequeo específico, no una heurística laxa — descarta que sea un falso positivo del propio clasificador sobre una SPA que carga lento. Cuando se detecta, `CompositeActiveReconOrchestratorService.ts:942-960` intenta resolverlo con un navegador Playwright real (`ChallengeBrowserContinuationService.evaluateAndProgress`), con un presupuesto fijo de 3 intentos (`maxChallengeContinuations = 3`, línea 893). En las corridas degradadas, los 3 intentos se agotan sin pasar el challenge → todo lo que depende de contenido real (jsluice, extracción DOM de Playwright, extracción de links HTML, robots/sitemap) se queda en casi cero, porque lo único que se llegó a servir fue la página de verificación, no la app real.

**Por qué `inmobiliaria-cornejo-web-rho` nunca se degrada**: en ninguna de las 3 corridas muestreadas devolvió jamás un 403/503 con marca de challenge — simple ausencia del disparador, confirmado, no una ventaja estructural del motor de FixGuard.

### Incertidumbres que quedan abiertas (no verificables con los datos disponibles)

- **Por qué es intermitente para el mismo dominio**: `firma-nu` se degradó en la corrida 1 y 5, pero estuvo sana en la 2 y 3 (varias horas después, mismo día). No es un patrón de empeoramiento acumulativo (eso descarta rate-limiting clásico como causa única) ni de corrupción de caché persistente (si lo fuera, no se habría recuperado). La causa de la intermitencia — si Vercel/Cloudflare aplica el challenge de forma muestreada, por reputación de IP, por carga, o si varía algo en el fingerprint del navegador stealth de FixGuard entre corridas — **no se puede determinar con los datos guardados** (no se persistió el cuerpo crudo de la respuesta de challenge).
- **Qué vendor exacto**: el regex de clasificación matchea tanto firmas de Vercel como de Cloudflare en un solo chequeo — no se puede saber cuál de los dos disparó sin el cuerpo crudo.
- **Si subir el presupuesto de 3 a N reintentos ayudaría**: no hay logging por intento (qué falló específicamente en cada uno de los 3 intentos — timeout, challenge todavía presente tras capturar cookies, error de navegación). Sin eso, cualquier cambio al número 3 es una apuesta, no una decisión informada.

### Relación con las mejoras ya propuestas en este documento

- **Corrige la sección 6**: la entrada "sospechada" de rate-limiting queda reemplazada por este hallazgo verificado.
- **El ítem 3 de la tabla de mejoras (sección 8, "subir topes de crawl/fuzzing") no resuelve esto** — el bloqueo ocurre en `stage_3`, antes de que cualquier tope (150 requests, 2 saltos, 3 raíces de fuzzing) llegue a importar. Subir límites no atraviesa un challenge; es exactamente la distinción que pediste priorizar: la causa a atacar es lo que impide investigar más, no el techo que ya tiene lo que sí se investiga.
- **Conecta con el ítem 2 (cobertura por boundary) y con la sección 1 (calidad de clasificación)**: hoy "6 planes" y "96 planes" son números sin contexto — nada distingue "la app es chica" de "la corrida se cortó por un bloqueo de borde". Eso es exactamente lo que la propuesta de abajo soluciona.

### Propuesta: clasificar automáticamente la salud de la corrida

Agregar un campo `reconHealthStatus` al registro del assessment, calculado **solo con datos que ya se loguean hoy** (los `warnings` de cada stage + `observationsCount`) — no requiere ninguna llamada de red nueva:
- `complete`: ninguna stage con warning de challenge/WAF/rate-limit, y el frontier terminó por agotamiento natural ("all reachable routes discovered" o "duplicate saturation"), no por tope.
- `degraded_blocked`: hay un warning de `browser_challenge`/`waf_confirmed`/`rate_limited` en algún stage — y debe decir CUÁL, con el stage y el host exactos (ya están en los datos).
- `degraded_unexplained`: el conteo de observaciones cae muy por debajo de lo esperable para ese dominio sin ningún warning de bloqueo — esto es distinto del caso anterior porque señala un posible bug propio de FixGuard, no un bloqueo externo, y hoy esos dos casos son indistinguibles en la salida.
- `insufficiently_explored`: el frontier se cortó por tope de configuración (budget/profundidad/páginas de Playwright), no por agotamiento natural ni por bloqueo — usa la "tasa de saturación de topes" ya propuesta en la sección 5.

### Propuesta: medir superficie descubierta vs. efectivamente investigada

Guardar, junto al warning de bloqueo, un corte antes/después: cuántas rutas se habían descubierto hasta el momento exacto del challenge, versus cuántas se sumaron después. Así un reporte puede decir "se descubrieron 12 rutas antes del bloqueo, 0 después — cobertura probablemente incompleta" en vez de solo mostrar un número final sin contexto. Esto se combina directamente con la métrica de cobertura por `service_boundary` ya propuesta en la sección 8.

### Próximo hito recomendado

No es "subir el presupuesto de reintentos de 3 a un número mayor" — eso sería adivinar. El próximo paso de menor esfuerzo y mayor valor informativo es instrumentar `ChallengeBrowserContinuationService` para loguear, por cada uno de los 3 intentos, qué pasó específicamente (timeout, challenge todavía presente después de capturar cookies, error de navegación). Esto no ejecuta ningún escaneo nuevo por sí mismo — es logging — pero es lo único que convertiría las incertidumbres de arriba en hechos verificables la próxima vez que se corra contra un target real, y es prerequisito honesto antes de decidir si vale la pena invertir en un `reconHealthStatus` más elaborado o en mejorar el perfil stealth de Playwright.

> **Estado (2026-10-26), tras R7/R8/R9/R10**: esta instrumentación por-intento de `ChallengeBrowserContinuationService` **sigue sin implementarse**. Ninguno de los hitos completados hasta ahora la cubre — R7 clasifica salud de corrida a nivel de host (`unresolvedChallengeHosts`/`resolvedChallengeHosts`), no a nivel de intento individual; R8 cerró gates de auto-promoción; R9 midió actividad de planificación; R10 agregó observabilidad de tope de profundidad y el requisito de mismo-origen en correlación — ninguno toca `ChallengeBrowserContinuationService` ni loguea qué pasó en cada uno de los 3 intentos. Sigue siendo el próximo hito de investigación recomendado, tal como se propuso arriba: no se recomienda subir el número de reintentos antes de tener esa evidencia por-intento.

### Hito 1 — IMPLEMENTADO (2026-10-25)

El `reconHealthStatus` propuesto arriba ya está implementado — ver Milestone R7 en `docs/ROADMAP.md`. Resumen de lo que cambió realmente:

- `CompositeActiveReconOrchestratorService.ts` ahora registra el caso que antes se perdía en silencio: cuando `ChallengeBrowserContinuationService.evaluateAndProgress()` devuelve `state: 'failed'` o `'expired'` (lo que pasaba en las corridas degradadas de hoy), se loguea `reasonCode`/`operatorMessage` y se marca el host en `unresolvedChallengeHosts`. También se cubrió el caso sin `sessionSanctuary` (antes silenciosamente no intentaba nada) y la rama `waiting_for_operator` que faltaba en el frontier de crawl (el segundo call site solo tenía la rama de éxito).
- Nuevo `ReconHealthClassificationService` (contrato `fixguard-recon-health/v0`) clasifica cada corrida en `complete` / `degraded_blocked` / `insufficiently_explored` / `degraded_unexplained`, usando solo las señales reales (`unresolvedChallengeHosts`, `resolvedChallengeHosts`, `crawlStoppedByBudgetCap`) — nunca un baseline inventado. Un host que falla y luego se resuelve en un reintento no cuenta como bloqueado.
- El campo `reconHealthStatus` queda expuesto en `OrchestratedAssessmentRecord`, `getStatus()` y `getSummary()` — retrocompatible (opcional, ausente en registros viejos).
- **Deliberadamente no tocado**: `maxChallengeContinuations` sigue en 3, ningún tope de crawl/Playwright cambió, no se agregó ningún motor nuevo.
- Verificado: `npm run smoke:v2:recon-health-observability` (6 casos) y `npm run typecheck:v2`, ambos en 0.
- Pendiente de verificación en vivo: la próxima corrida real contra `firma-nu.vercel.app`/`negocios-inmobiliarios.vercel.app` debería mostrar `reconHealthStatus.status === 'degraded_blocked'` con `edge_challenge_unresolved:<host>` si el challenge intermitente vuelve a aparecer — no se forzó esa corrida como parte de este hito (quedó fuera de alcance ejecutar escaneos).
