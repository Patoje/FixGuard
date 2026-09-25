import type { AuthorizableBlastRadiusClass } from "@/lib/v2AttackApi";

/** Human-facing Spanish labels for blast-radius enums (API values unchanged). */
export const BLAST_RADIUS_LABELS: Record<
  AuthorizableBlastRadiusClass,
  { label: string; hint: string; writeRisk: boolean }
> = {
  read_public: {
    label: "Lectura pública",
    hint: "Solo recursos abiertos sin sesión.",
    writeRisk: false,
  },
  read_authenticated: {
    label: "Lectura con sesión",
    hint: "Lee con credenciales o sesión ya autorizada.",
    writeRisk: false,
  },
  read_escalated: {
    label: "Lectura elevada (recomendado para confirmar datos)",
    hint: "Confirma acceso a datos que no deberían ser públicos (p. ej. RLS).",
    writeRisk: false,
  },
  sensitive_data_access: {
    label: "Acceso a datos sensibles",
    hint: "Puede exponer información confidencial; solo lectura.",
    writeRisk: false,
  },
  credential_use: {
    label: "Uso de credenciales",
    hint: "Reutiliza tokens/claves observadas en otro host.",
    writeRisk: false,
  },
  privilege_escalation: {
    label: "Escalada de privilegios",
    hint: "Prueba si se pueden obtener permisos mayores.",
    writeRisk: false,
  },
  lateral_movement: {
    label: "Movimiento lateral",
    hint: "Evalúa alcance hacia otros hosts del mismo alcance.",
    writeRisk: false,
  },
  state_change_benign: {
    label: "Puede modificar datos (controlado)",
    hint: "Escrituras mínimas de prueba; riesgo de cambio de estado.",
    writeRisk: true,
  },
  state_change_impact: {
    label: "Puede modificar datos (peligroso)",
    hint: "Escrituras con impacto real en el objetivo.",
    writeRisk: true,
  },
};

export function blastRadiusLabel(c: AuthorizableBlastRadiusClass): string {
  return BLAST_RADIUS_LABELS[c]?.label ?? c;
}
