import type { TechStackItem } from './TechStackProfiler';

export interface ArchitectureNode {
  name: string;
  children?: ArchitectureNode[];
}

export function buildArchitectureTree(domain: string, techStack: TechStackItem[]): ArchitectureNode {
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

  // Si no hay categorías (sitio estático básico)
  if (root.children!.length === 0) {
    root.children!.push({ name: 'Static HTML/CSS' });
  }

  return root;
}
