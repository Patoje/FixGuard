import type { AuthorizableBlastRadiusClass } from "@/lib/v2AttackApi";

/** Human-facing Spanish labels for blast-radius enums (API values unchanged). */
export interface BlastRadiusMeta {
  readonly label: string;
  readonly hint: string;
  readonly technicalDetail: string;
  readonly writeRisk: boolean;
  readonly category: "read" | "access" | "write";
}

/** Human-facing Spanish labels for blast-radius enums (API values unchanged). */
export const BLAST_RADIUS_LABELS: Record<AuthorizableBlastRadiusClass, BlastRadiusMeta> = {
  read_public: {
    label: "Lectura pública",
    hint: "Solo recursos abiertos sin sesión.",
    technicalDetail:
      "Envía peticiones HTTP GET/HEAD anónimas sin cookies ni tokens. Verifica qué endpoints, rutas o assets son públicos sin requerir credenciales.",
    writeRisk: false,
    category: "read",
  },
  read_authenticated: {
    label: "Lectura con sesión",
    hint: "Lee con credenciales o sesión ya autorizada.",
    technicalDetail:
      "Utiliza cookies o headers de sesión autorizados (BYOT) para consultar perfiles, dashboards y recursos regulares a los que el usuario legítimo tiene acceso.",
    writeRisk: false,
    category: "read",
  },
  read_escalated: {
    label: "Lectura elevada (Recomendado para confirmar datos)",
    hint: "Confirma acceso a datos que no deberían ser públicos (p. ej. RLS / IDOR).",
    technicalDetail:
      "Prueba si se pueden leer registros de otros usuarios, colecciones restringidas o tablas privadas (ej. bypass de RLS en Supabase o IDOR horizontal) sin modificar nada en la base de datos.",
    writeRisk: false,
    category: "read",
  },
  sensitive_data_access: {
    label: "Acceso a datos sensibles",
    hint: "Puede exponer información confidencial; solo lectura.",
    technicalDetail:
      "Verifica si las respuestas contienen información confidencial (credenciales, JWTs, hashes, claves de API o datos personales PII) expuestas en endpoints o respuestas JSON.",
    writeRisk: false,
    category: "access",
  },
  credential_use: {
    label: "Uso y reuso de credenciales",
    hint: "Reutiliza tokens/claves observadas en otro host o servicio.",
    technicalDetail:
      "Toma claves de API o tokens descubiertos durante el análisis y prueba si son válidos en otros endpoints, microservicios o subdominios del target autorizado.",
    writeRisk: false,
    category: "access",
  },
  privilege_escalation: {
    label: "Escalada de privilegios",
    hint: "Prueba si se pueden obtener permisos mayores o administrativos.",
    technicalDetail:
      "Prueba si un usuario estándar puede invocar rutas de administración (/admin, /api/users, Server Actions privilegiadas) manipulando claims del token o parámetros de rol.",
    writeRisk: false,
    category: "access",
  },
  lateral_movement: {
    label: "Movimiento lateral",
    hint: "Evalúa alcance hacia otros hosts del mismo perímetro.",
    technicalDetail:
      "Comprueba si la sesión o permisos obtenidos permiten interactuar con otros microservicios, bases de datos o subdominios vinculados dentro del perímetro autorizado.",
    writeRisk: false,
    category: "access",
  },
  state_change_benign: {
    label: "Puede modificar datos (Controlado)",
    hint: "Escrituras mínimas de prueba; riesgo de cambio de estado.",
    technicalDetail:
      "Envía mutaciones controladas (POST/PUT/PATCH) diseñadas para crear un registro temporal inocuo o actualizar un campo de prueba. Confirma falta de control de escritura sin destruir datos.",
    writeRisk: true,
    category: "write",
  },
  state_change_impact: {
    label: "Puede modificar datos (Peligroso / Alto impacto)",
    hint: "Escrituras con impacto real en el objetivo.",
    technicalDetail:
      "Permite mutaciones reales o eliminaciones en el servidor objetivo para demostrar impacto crítico en la integridad o disponibilidad. Requiere máxima precaución.",
    writeRisk: true,
    category: "write",
  },
};

export function blastRadiusLabel(c: AuthorizableBlastRadiusClass): string {
  return BLAST_RADIUS_LABELS[c]?.label ?? c;
}
