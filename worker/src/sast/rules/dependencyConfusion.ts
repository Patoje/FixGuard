import { SastFinding, SastRule } from '../index';

export const checkDependencyConfusion: SastRule = (filePath, content) => {
  const findings: SastFinding[] = [];
  
  if (!filePath.endsWith('package.json')) return findings;

  try {
    const pkg = JSON.parse(content);
    const dependencies = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    
    // Nombres sospechosos comunes en repositorios corporativos
    const privateKeywords = ['internal', 'private', 'corp', 'company', 'custom'];

    for (const [depName, version] of Object.entries(dependencies)) {
      // Si el paquete tiene un nombre privado pero no usa Scopes (@empresa/paquete)
      if (!depName.startsWith('@') && privateKeywords.some(kw => depName.toLowerCase().includes(kw))) {
         findings.push({
          type: 'DEPENDENCY_CONFUSION',
          severity: 'MEDIUM',
          description: `Vulnerabilidad MEDIA. Se detectó una posible Dependencia Confusa (Dependency Confusion) en el paquete '${depName}'. El nombre parece indicar que es un paquete interno/privado de la empresa, pero no utiliza Scopes de NPM (@mi-empresa/paquete). Si no has registrado este nombre públicamente, un atacante podría publicar un paquete malicioso con el nombre '${depName}' en NPM, y tu servidor lo descargará accidentalmente durante la instalación.`,
          file: filePath
        });
      }
    }
  } catch (e) {
    // Ignorar JSON inválidos
  }

  return findings;
};
