import type { TechStackItem } from './TechStackItem';

export class TechStackCorrelationEngine {
  static correlate(allFindings: TechStackItem[]): TechStackItem[] {
    const merged = new Map<string, TechStackItem>();

    for (const finding of allFindings) {
      if (!merged.has(finding.name)) {
        merged.set(finding.name, { ...finding });
      } else {
        const existing = merged.get(finding.name)!;
        
        // Sumar confianza con un límite de 100
        existing.confidence = Math.min(100, existing.confidence + finding.confidence);
        
        // Si no tenía versión y el nuevo sí tiene, la asignamos
        if (!existing.version && finding.version) {
          existing.version = finding.version;
        }
        // Si el nuevo tiene una versión más específica (más larga o diferente formato), podríamos reemplazarla
        else if (existing.version && finding.version && finding.version.length > existing.version.length) {
          existing.version = finding.version;
        }

        // Merge de evidencias únicas
        for (const ev of finding.evidence) {
          if (!existing.evidence.includes(ev)) {
            existing.evidence.push(ev);
          }
        }
      }
    }

    return Array.from(merged.values()).sort((a, b) => b.confidence - a.confidence);
  }
}
