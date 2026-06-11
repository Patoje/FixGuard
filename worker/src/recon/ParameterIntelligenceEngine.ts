import type { AttackSurfaceItem } from './AttackSurfaceMapper';

export interface ParameterIntelligence {
  totalParameters: number;
  topParameters: Array<{ name: string; frequency: number }>;
  allParameters: string[];
}

export class ParameterIntelligenceEngine {
  static analyze(attackSurface: AttackSurfaceItem[]): ParameterIntelligence {
    const paramCounts: Record<string, number> = {};

    for (const item of attackSurface) {
      if (item.params && item.params.length > 0) {
        for (const param of item.params) {
          if (param === 'id_path_param') continue; // Ignoramos el genérico del path
          paramCounts[param] = (paramCounts[param] || 0) + 1;
        }
      }
    }

    const allParameters = Object.keys(paramCounts);
    
    const topParameters = allParameters
      .map(name => ({ name, frequency: paramCounts[name] }))
      .sort((a, b) => b.frequency - a.frequency)
      .slice(0, 20); // Tomamos los 20 más usados para no saturar

    return {
      totalParameters: allParameters.length,
      topParameters,
      allParameters
    };
  }
}
