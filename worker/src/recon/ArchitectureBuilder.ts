import type { TechStackItem } from './TechStackProfiler';

export interface ArchitectureNode {
  name: string;
  children?: ArchitectureNode[];
}

import type { AttackSurfaceItem } from './AttackSurfaceMapper';
import type { BusinessDictionary } from './parsers/JsKnowledgeExtractor';

export function buildArchitectureTree(
  domain: string, 
  techStack: TechStackItem[],
  attackSurface: AttackSurfaceItem[],
  businessDict: BusinessDictionary
): ArchitectureNode {
  const root: ArchitectureNode = {
    name: domain,
    children: []
  };

  const categories = {
    'Frontend': techStack.filter(t => t.category === 'Frontend Framework'),
    'Backend': techStack.filter(t => t.category === 'Backend Framework'),
    'Database': techStack.filter(t => t.category === 'Database'),
    'Authentication': techStack.filter(t => t.category === 'Authentication'),
    'Infrastructure': techStack.filter(t => t.category === 'Hosting / Infrastructure'),
    'External Services': techStack.filter(t => t.category === 'External Services')
  };

  for (const [catName, items] of Object.entries(categories)) {
    if (items.length > 0) {
      root.children!.push({
        name: catName,
        children: items.map(i => ({ name: i.name }))
      });
    }
  }

  // --- MÓDULO 1: RELATIONSHIP GRAPH ENGINE ---
  // Inferir y mapear relaciones desde Business Dictionary y Attack Surface
  const apiNodes: ArchitectureNode[] = [];
  
  if (businessDict.entities.length > 0) {
    const businessNode: ArchitectureNode = {
      name: 'Business Logic (Entities)',
      children: businessDict.entities.slice(0, 5).map(e => ({ name: e.charAt(0).toUpperCase() + e.slice(1) }))
    };
    root.children!.push(businessNode);
  }

  const apiEndpoints = attackSurface.filter(s => s.type === 'REST API' || s.type === 'GraphQL Endpoint' || s.path.includes('/api/'));
  if (apiEndpoints.length > 0) {
    // Agrupar por prefijo de API
    const uniqueApis = Array.from(new Set(apiEndpoints.map(e => e.path.split('/').slice(0, 3).join('/')))).slice(0, 5);
    apiNodes.push(...uniqueApis.map(api => ({ name: api })));
    
    root.children!.push({
      name: 'API Gateway',
      children: apiNodes
    });
  }

  // Si no hay categorías
  if (root.children!.length === 0) {
    root.children!.push({ name: 'Static HTML/CSS' });
  }

  return root;
}
