import type { SastFinding, SastRule } from '../index';

export const checkDomXss: SastRule = (filePath, content) => {
  const findings: SastFinding[] = [];
  
  if (!filePath.endsWith('.tsx') && !filePath.endsWith('.jsx')) return findings;

  const domXssPattern = /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+)\s*\}\}/g;
  let match;

  while ((match = domXssPattern.exec(content)) !== null) {
    const value = match[1].trim();
    // Excluir si están usando librerías conocidas de sanitización (DOMPurify, sanitize-html)
    if (!value.includes('DOMPurify') && !value.includes('sanitizeHtml')) {
       findings.push({
        type: 'DOM_XSS',
        severity: 'HIGH',
        description: `Vulnerabilidad ALTA. Se detectó el uso peligroso de 'dangerouslySetInnerHTML' sin una librería de sanitización visible. React protege del XSS por defecto, pero esta función desactiva esa protección. Si el contenido de '${value}' proviene del usuario, un atacante puede ejecutar código malicioso en el navegador. Envuelve el valor con 'DOMPurify.sanitize(${value})'.`,
        file: filePath
      });
    }
  }

  return findings;
};
