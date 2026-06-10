import fs from 'fs';
import path from 'path';

export interface SastFinding {
  type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  file: string;
  line?: number;
}

export type SastRule = (filePath: string, fileContent: string) => SastFinding[];

// Helper para recorrer directorios recursivamente
export function walkDir(dir: string, callback: (filePath: string) => void) {
  if (!fs.existsSync(dir)) return;
  
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const filePath = path.join(dir, file);
    
    // Ignorar node_modules, .git, .next, dist
    if (filePath.includes('node_modules') || filePath.includes('.git') || filePath.includes('.next') || filePath.includes('dist')) {
      continue;
    }
    
    const stat = fs.statSync(filePath);
    if (stat.isDirectory()) {
      walkDir(filePath, callback);
    } else {
      callback(filePath);
    }
  }
}

// Orquestador Principal
import { checkServerActions } from './rules/serverActions';
import { checkClientAuth } from './rules/clientAuth';
import { checkMassAssignment } from './rules/massAssignment';
import { checkOrmInjection } from './rules/ormInjection';
import { checkDomXss } from './rules/domXss';
import { checkDependencyConfusion } from './rules/dependencyConfusion';

const RULES: SastRule[] = [
  checkServerActions,
  checkClientAuth,
  checkMassAssignment,
  checkOrmInjection,
  checkDomXss,
  checkDependencyConfusion
];

export async function runSastScan(targetDir: string): Promise<SastFinding[]> {
  const allFindings: SastFinding[] = [];
  
  if (!fs.existsSync(targetDir)) {
    throw new Error(`El directorio ${targetDir} no existe.`);
  }

  walkDir(targetDir, (filePath) => {
    // Solo analizamos código fuente y JSONs
    if (!filePath.endsWith('.ts') && !filePath.endsWith('.tsx') && !filePath.endsWith('.js') && !filePath.endsWith('.jsx') && !filePath.endsWith('.json')) {
      return;
    }

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      
      for (const rule of RULES) {
        const findings = rule(filePath, content);
        if (findings && findings.length > 0) {
          allFindings.push(...findings);
        }
      }
    } catch (e) {
      console.error(`Error leyendo ${filePath}`, e);
    }
  });

  return allFindings;
}
