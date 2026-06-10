import type { SastFinding, SastRule } from '../index';

export const checkOrmInjection: SastRule = (filePath, content) => {
  const findings: SastFinding[] = [];
  
  if (!filePath.endsWith('.ts') && !filePath.endsWith('.js')) return findings;

  // Detección de Raw SQL injection en Prisma y Drizzle
  // Busca usos de sql`...${userInput}...` o $queryRawUnsafe(`...${userInput}...`)
  const prismaRawInjection = /\$(?:query|execute)RawUnsafe\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`\s*\)/g;
  
  // Drizzle permite sql`...` de forma segura por defecto (usa prepared statements paramétricos).
  // La vulnerabilidad solo ocurre si usan sql.raw() con variables.
  const drizzleRawInjection = /sql\.raw\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`\s*\)/g;

  if (prismaRawInjection.test(content) || drizzleRawInjection.test(content)) {
    findings.push({
      type: 'RAW_SQL_INJECTION',
      severity: 'CRITICAL',
      description: `Vulnerabilidad CRÍTICA. Se detectó una Inyección SQL Cruda (Raw Query Injection). Estás utilizando funciones como '$queryRawUnsafe' (Prisma) o 'sql.raw' (Drizzle) e interpolando variables dinámicas directamente en el string. Esto anula la protección del ORM y expone la base de datos a SQLi clásico. Utiliza '$queryRaw' (Prisma) o 'sql' (Drizzle) con tagged templates para que parametricen la consulta.`,
      file: filePath
    });
  }

  return findings;
};
