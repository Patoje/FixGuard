import { SastFinding, SastRule } from '../index';

export const checkClientAuth: SastRule = (filePath, content) => {
  const findings: SastFinding[] = [];
  
  // Solo componentes cliente (React)
  if (!filePath.endsWith('.tsx') && !filePath.endsWith('.jsx')) return findings;
  if (!content.includes('"use client"') && !content.includes("'use client'")) return findings;

  // Buscar condicionales de roles en el UI
  const clientAuthPattern = /if\s*\(\s*(?:isAdmin|role\s*===\s*['"]admin['"]|user\.isAdmin)\s*\)/g;
  
  if (clientAuthPattern.test(content)) {
    findings.push({
      type: 'CLIENT_SIDE_AUTHORIZATION',
      severity: 'LOW',
      description: `Vulnerabilidad BAJA (Informativa). Se detectó Client-Side Authorization. El frontend usa variables como 'isAdmin' para ocultar/mostrar secciones de la UI. Recuerda que un atacante puede modificar el JS en su navegador para saltarse este 'if'. Asegúrate de que los botones o datos que muestras aquí tengan verificación en el backend (Server Actions / API).`,
      file: filePath
    });
  }

  return findings;
};
