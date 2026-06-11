import type { TechStackItem } from '../TechStackItem';

export class JsAnalyzer {
  static analyze(jsContent: string, url: string): TechStackItem[] {
    const findings: TechStackItem[] = [];

    const add = (name: string, category: TechStackItem['category'], confidence: number, evidence: string, role: string, version?: string) => {
      findings.push({ name, category, confidence, evidence: [evidence], role, version });
    };

    // jQuery Version matching in URL
    if (url.includes('jquery')) {
      const vMatch = url.match(/jquery[-.]([0-9.]+)\.js/i);
      add('jQuery', 'Frontend Framework', 99, 'jQuery filename', 'Librería DOM', vMatch ? vMatch[1] : undefined);
    }

    // Search inside the JS Code itself
    if (jsContent.includes('React.createElement') || jsContent.includes('__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED')) {
      add('React', 'Frontend Framework', 95, 'React internal signatures', 'Librería de UI');
    }

    if (jsContent.includes('supabase.co')) {
      add('Supabase', 'Database', 95, 'Supabase URL in JS', 'BaaS / DB');
    }

    if (jsContent.includes('@clerk/clerk-js')) {
      add('Clerk', 'Authentication', 95, 'Clerk SDK code found', 'Gestión de identidad');
    }

    return findings;
  }
}
