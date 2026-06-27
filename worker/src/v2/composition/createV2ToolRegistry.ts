import { LocalToolRegistry } from '../core/ToolRegistry';
import { SubfinderAdapter } from '../adapters/SubfinderAdapter';
import { SubfinderJsonParser } from '../parsers/SubfinderJsonParser';
import { HttpxAdapter } from '../adapters/HttpxAdapter';
import { HttpxJsonParser } from '../parsers/HttpxJsonParser';

export function createV2ToolRegistry(): LocalToolRegistry {
  const registry = new LocalToolRegistry();

  registry.register({
    capability: 'subdomain_discovery',
    adapter: new SubfinderAdapter(),
    parser: new SubfinderJsonParser(),
    priority: 10,
    requirements: { binary: 'subfinder' },
    metadata: { 
      name: 'subfinder', 
      version: 'latest', 
      description: 'Subdomain enumeration' 
    }
  });

  registry.register({
    capability: 'http_probe',
    adapter: new HttpxAdapter(),
    parser: new HttpxJsonParser(),
    priority: 10,
    requirements: { binary: 'httpx' },
    metadata: { 
      name: 'httpx', 
      version: 'latest', 
      description: 'Fast HTTP prober' 
    }
  });

  return registry;
}
