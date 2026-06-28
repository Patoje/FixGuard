import { CapabilityRegistry } from './CapabilityRegistry';

export function createDefaultCapabilityRegistry(): CapabilityRegistry {
  const registry = new CapabilityRegistry();

  registry.register({
    id: 'subdomain_discovery',
    name: 'Subdomain Discovery',
    description: 'Finds subdomains passively',
    category: 'recon',
    riskLevel: 'info',
    requiresApproval: false,
    inputSchema: { type: 'object' },
    outputKind: 'subdomain_list',
    evidenceKind: 'discovery',
    allowedTargetKinds: ['domain']
  });

  registry.register({
    id: 'http_probe',
    name: 'HTTP Probe',
    description: 'Probes HTTP ports passively',
    category: 'http',
    riskLevel: 'info',
    requiresApproval: false,
    inputSchema: { type: 'object' },
    outputKind: 'http_probe_results',
    evidenceKind: 'discovery',
    allowedTargetKinds: ['host', 'subdomain']
  });

  return registry;
}
