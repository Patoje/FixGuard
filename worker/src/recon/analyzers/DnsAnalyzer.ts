import type { TechStackItem } from '../TechStackItem';

export class DnsAnalyzer {
  // En un caso real haría consultas MX y TXT con el módulo dns de Node
  // Por ahora simulamos que no descubrió nada nuevo que no se vea en cabeceras
  static async analyze(domain: string): Promise<TechStackItem[]> {
    return [];
  }
}
