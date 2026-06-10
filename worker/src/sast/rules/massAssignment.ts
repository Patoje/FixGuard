import type { SastFinding, SastRule } from '../index';

export const checkMassAssignment: SastRule = (filePath, content) => {
  const findings: SastFinding[] = [];
  
  if (!filePath.endsWith('.ts') && !filePath.endsWith('.js')) return findings;

  // Detección de prisma.*.create({ data: req.body }) o db.insert().values(req.body)
  const massAssignmentPrisma = /prisma\.[a-zA-Z0-9_]+\.(?:create|update)\s*\(\s*\{\s*data\s*:\s*(?:req\.body|body|payload)\s*\}\s*\)/g;
  const massAssignmentDrizzle = /db\.insert\s*\([^)]+\)\s*\.values\s*\(\s*(?:req\.body|body|payload)\s*\)/g;

  if (massAssignmentPrisma.test(content) || massAssignmentDrizzle.test(content)) {
    findings.push({
      type: 'MASS_ASSIGNMENT',
      severity: 'HIGH',
      description: `Vulnerabilidad ALTA. Se detectó una Asignación Masiva ('Mass Assignment'). El código está insertando el objeto completo (ej. req.body) directamente a la base de datos sin filtrar. Un atacante podría incluir campos ocultos como {"isAdmin": true} y ganar privilegios. Siempre desestructura o filtra el input antes de hacer inserts.`,
      file: filePath
    });
  }

  return findings;
};
