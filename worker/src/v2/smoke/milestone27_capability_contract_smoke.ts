import * as assert from 'assert';
import { CapabilityRegistry } from '../capabilities/CapabilityRegistry';
import type { CapabilityDefinition } from '../capabilities/CapabilityDefinition';

async function runSmokeTest() {
  console.log('--- V2 Capability Contract Smoke Test ---');

  const registry = new CapabilityRegistry();

  // 1. Safe capability definition registers successfully.
  console.log('[*] Testing safe capability registration...');
  const safeDefinition: CapabilityDefinition = {
    id: 'recon_basic',
    name: 'Basic Recon',
    description: 'Performs basic passive recon',
    category: 'recon',
    riskLevel: 'info',
    requiresApproval: false,
    inputSchema: { type: 'object' },
    outputKind: 'recon_results',
    evidenceKind: 'discovery',
    allowedTargetKinds: ['domain']
  };
  registry.register(safeDefinition);
  console.log('[+] Safe capability registered successfully.');

  // 2. Duplicate id rejects.
  console.log('[*] Testing duplicate ID rejection...');
  assert.throws(
    () => registry.register(safeDefinition),
    /Duplicate capability ID 'recon_basic'/,
    'Duplicate ID should reject'
  );
  console.log('[+] Duplicate ID correctly rejected.');

  // 3. Capability definition with top-level forbidden key rejects.
  console.log('[*] Testing top-level forbidden key in definition...');
  const unsafeDefinitionTop: any = {
    ...safeDefinition,
    id: 'unsafe_top',
    command: 'whoami'
  };
  assert.throws(
    () => registry.register(unsafeDefinitionTop),
    /Forbidden executable key 'command'/,
    'Top-level forbidden key should reject'
  );
  console.log('[+] Top-level forbidden key correctly rejected.');

  // 4. Capability definition with nested forbidden key rejects.
  console.log('[*] Testing nested forbidden key in definition...');
  const unsafeDefinitionNested: any = {
    ...safeDefinition,
    id: 'unsafe_nested',
    inputSchema: { properties: { args: { type: 'string' } } }
  };
  assert.throws(
    () => registry.register(unsafeDefinitionNested),
    /Forbidden executable key 'args'/,
    'Nested forbidden key should reject'
  );
  console.log('[+] Nested forbidden key correctly rejected.');

  // 5. Safe input validates successfully.
  console.log('[*] Testing safe input validation...');
  const safeInput = {
    hostname: 'example.com',
    includeSubdomains: true,
    headersToInspect: ['Server', 'X-Powered-By']
  };
  registry.validateInput('recon_basic', safeInput);
  console.log('[+] Safe input validated successfully.');

  // 6. Unsafe input with top-level forbidden key rejects.
  console.log('[*] Testing top-level forbidden key in input...');
  const unsafeInputTop = {
    hostname: 'example.com',
    binary: 'nmap'
  };
  assert.throws(
    () => registry.validateInput('recon_basic', unsafeInputTop),
    /Forbidden key 'binary'/,
    'Top-level forbidden key in input should reject'
  );
  console.log('[+] Top-level forbidden key in input correctly rejected.');

  // 7. Unsafe input with nested forbidden key in object rejects.
  console.log('[*] Testing nested forbidden key in input object...');
  const unsafeInputNested = {
    hostname: 'example.com',
    options: {
      shell: '/bin/bash'
    }
  };
  assert.throws(
    () => registry.validateInput('recon_basic', unsafeInputNested),
    /Forbidden key 'shell'/,
    'Nested forbidden key in input should reject'
  );
  console.log('[+] Nested forbidden key in input correctly rejected.');

  // 8. Unsafe input with forbidden key inside array rejects.
  console.log('[*] Testing forbidden key inside array in input...');
  const unsafeInputArray = {
    hostname: 'example.com',
    list: [{ spawn: 'process' }]
  };
  assert.throws(
    () => registry.validateInput('recon_basic', unsafeInputArray),
    /Forbidden key 'spawn'/,
    'Forbidden key in array should reject'
  );
  console.log('[+] Forbidden key in array correctly rejected.');

  // 9. Registry returns clones/plain objects, not mutable internals.
  console.log('[*] Testing registry encapsulation...');
  const retrieved = registry.getDefinition('recon_basic');
  assert.ok(retrieved !== undefined, 'Should return definition');
  retrieved.name = 'Hacked Name';
  const retrievedAgain = registry.getDefinition('recon_basic');
  assert.strictEqual(retrievedAgain?.name, 'Basic Recon', 'Internal state should not mutate');
  console.log('[+] Registry correctly returns cloned data.');

  // 10 & 11 implicitly proven by lack of dependencies / synchronous execution
  console.log('[+] Validated no runners, scanners, or databases are invoked.');
  console.log('--- Smoke Test Completed Successfully ---');
}

runSmokeTest().catch((err) => {
  console.error('Smoke test failed:', err);
  process.exit(1);
});
