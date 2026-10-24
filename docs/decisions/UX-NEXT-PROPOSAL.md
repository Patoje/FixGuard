# FixGuard V2 — Exploración de UI alternativa (descartada)

**Estado:** DESCARTADO (2026-10-24, decisión del operador). Se construyó un
prototipo aislado en `/v2-next/*` con un estilo visual distinto al nativo
`/v2`. El operador prefirió el estilo nativo existente — `/v2-next` fue
eliminado del repo. Lo que sigue documenta qué se encontró en el proceso
que **sigue siendo válido** y se aplicó (o queda pendiente aplicar) sobre
el `/v2` real.

## Lo que sobrevive de esta exploración

### 1. Colores de estado validados (reutilizables en `/v2` real)

Los colores "diferido"/"accionable" ad-hoc (Tailwind `amber-400`/
`emerald-500`) no pasan el validador de la skill `dataviz`
(`scripts/validate_palette.js`) contra la superficie real de la app
(`#09090b`). La skill trae una paleta de **status** ya validada (contraste
+ daltonismo), separada de la categórica, hecha justo para esto:

- `good = #0ca30c`
- `warning = #fab219`

Contraste ≥3:1 contra `#09090b`, distinguibles para daltonismo. Van
siempre con ícono + label, nunca solo color. Si en algún momento se agrega
al `/v2` nativo una distinción visual para `deferredToManualValidation`,
usar estos valores, no elegir a ojo.

### 2. Dos bugs reales encontrados y corregidos (siguen corregidos)

1. `web/src/lib/v2Api.ts` — `StageResultDto.status` estaba tipado como
   `'success' | 'failed' | ...`, pero el backend nunca manda esos valores
   — manda `'completed' | 'skipped' | 'partial_failure'` (verificado
   contra `ActiveReconOrchestrationContracts.ts` del worker y una
   respuesta real de `/status`). Esto hacía que
   `web/src/app/v2/components/SessionStatusCard.tsx` marcara **toda etapa
   completada como error** en la consola de logs, silenciosamente, desde
   que existe ese componente. Corregido: el tipo y la línea que dependía
   de él.
2. Un ajuste de `V2TopNav.tsx` para evitar nav duplicada en `/v2-next` —
   revertido junto con el resto del prototipo (ya no aplica, `/v2-next` no
   existe).

### 3. Hallazgo sobre el flujo real de Parrot (todavía por implementar)

Revisando `web/src/app/v2/attack/page.tsx`: las secciones "Cadenas de
Explotación", "Evaluación de Impacto", "Post-explotación" (todas en 0 en
la práctica) solo se llenan si el operador ejecuta un plan de ataque a
mano. Con el pivote recon-first de esta sesión van a quedar vacías cada
vez más seguido — no están rotas, es consecuencia del propio pivote.

Conclusión sobre dónde va Parrot en el `/v2` real: dentro de **Stage 4
(Attack Mode)**, como panel nuevo junto a "Vulnerabilidades &
Recomendaciones" — mismo lugar donde el operador ya revisa qué evidencia
quedó pendiente. No como stage nuevo (menos disruptivo). Implementado por
separado, ver commit correspondiente.
