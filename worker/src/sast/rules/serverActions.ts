import type { SastFinding, SastRule } from '../index';

export const checkServerActions: SastRule = (filePath, content) => {
  const findings: SastFinding[] = [];
  
  if (!filePath.endsWith('.ts') && !filePath.endsWith('.tsx')) return findings;

  // Si el archivo declara "use server" o tiene export async function ...
  if (content.includes('"use server"') || content.includes("'use server'")) {
    // Buscar funciones que modifican base de datos (db.update, db.delete, db.insert, prisma.*.update)
    const dbMutationPattern = /(?:db|prisma)\.(?:[a-zA-Z0-9_]+)\.(?:update|delete|insert|create)/g;
    
    if (dbMutationPattern.test(content)) {
      // Verificar si hay alguna llamada a autorización (auth(), getSession(), session.user.isAdmin)
      const authValidationPattern = /(?:auth\(\)|getSession\(\)|verifyToken|isAdmin\s*===?\s*true|role\s*===?\s*['"]admin['"])/g;
      
      if (!authValidationPattern.test(content)) {
        findings.push({
          type: 'BROKEN_FUNCTION_LEVEL_AUTHORIZATION',
          severity: 'CRITICAL',
          description: `Vulnerabilidad CRÍTICA (BFLA/IDOR). Este archivo define Server Actions ("use server") y modifica la base de datos, pero NO se encontró ninguna validación de sesión (ej. auth() o verificación de roles). Cualquier usuario externo puede llamar a esta función por POST enviando el ID correcto.`,
          file: filePath
        });
      }
    }
  }

  return findings;
};
