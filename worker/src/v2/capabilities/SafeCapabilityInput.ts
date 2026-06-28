export const FORBIDDEN_CAPABILITY_KEYS = [
  'binary', 'args', 'env', 'command', 'shell', 'stdin',
  'process', 'spawn', 'exec', 'runner', 'adapterCommand',
  'executable', 'script', 'secret', 'token', 'password'
];

export const MAX_INPUT_DEPTH = 10;

/**
 * Validates that an input payload is safe to pass to a capability.
 * Rejects forbidden keys, functions, symbols, and excessively deep objects.
 */
export function validateSafeCapabilityInput(input: any, currentDepth = 0): void {
  if (currentDepth > MAX_INPUT_DEPTH) {
    throw new Error(`Capability input validation failed: Object exceeds maximum depth of ${MAX_INPUT_DEPTH}`);
  }

  if (input === null || typeof input !== 'object') {
    if (typeof input === 'function' || typeof input === 'symbol') {
      throw new Error(`Capability input validation failed: Functions and symbols are not allowed`);
    }
    if (input === undefined) {
      throw new Error(`Capability input validation failed: 'undefined' is not allowed in JSON-like payloads`);
    }
    return; // Primitives are safe
  }

  if (Array.isArray(input)) {
    for (const item of input) {
      validateSafeCapabilityInput(item, currentDepth + 1);
    }
    return;
  }

  // Iterate object keys
  for (const key of Object.keys(input)) {
    if (FORBIDDEN_CAPABILITY_KEYS.includes(key)) {
      throw new Error(`Capability input validation failed: Forbidden key '${key}' is not allowed`);
    }
    validateSafeCapabilityInput(input[key], currentDepth + 1);
  }
}

/**
 * Type representing safe capability input, usually a subset of standard primitive types
 * plus dictionaries/arrays that do not contain forbidden keywords.
 */
export interface SafeCapabilityInput {
  path?: string;
  hostname?: string;
  url?: string;
  maxDepth?: number;
  includeSubdomains?: boolean;
  headersToInspect?: string[];
  [key: string]: any;
}
