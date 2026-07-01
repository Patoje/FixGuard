import type { ActiveReconOriginRunResult } from './ActiveReconOriginRunContracts.js';
import type {
  PersistedActiveReconRunRecord,
  PersistedActiveReconRunItem,
  PersistedActiveReconRunError,
} from './ActiveReconOriginRunPersistenceContracts.js';
import type { ActiveReconRunRepository } from './ActiveReconOriginRunRepository.js';

const UNSAFE_KEYS = [
  '"targetUrl"',
  '"raw"',
  '"headers"',
  '"body"',
  '"request"',
  '"response"',
  '"payload"',
  '"cookie"',
  '"authorization"',
  '"password"',
  '"api_key"',
  '"apikey"',
  '"secret"',
  '"token"',
  '"severity"',
  '"impact"',
  '"exploit"',
  '"finding":true',
  '"evidence":true',
  '"riskClaim":true',
  '"vulnerability":true',
];

const ALLOWED_ERROR_CODES = [
  'authorization_not_confirmed',
  'invalid_origin',
  'origin_out_of_scope',
  'unsupported_probe',
  'empty_probe_set',
  'planning_failed',
  'runner_failed',
  'adapter_missing',
  'adapter_failed',
  'policy_blocked',
  'policy_candidate',
  'persistence_validation_failed'
] as const;

function validateError(e: any): PersistedActiveReconRunError {
  if (!e || typeof e.code !== 'string' || !(ALLOWED_ERROR_CODES as readonly string[]).includes(e.code)) {
    throw new Error('Invalid error code.');
  }
  if (typeof e.message !== 'string') {
    throw new Error('Invalid error message.');
  }
  return {
    code: e.code as typeof ALLOWED_ERROR_CODES[number],
    message: e.message
  };
}

export async function persistActiveReconOriginRunResult(
  result: ActiveReconOriginRunResult,
  repository: ActiveReconRunRepository
): Promise<PersistedActiveReconRunRecord> {
  if (
    result.classification?.finding !== false ||
    result.classification?.evidence !== false ||
    result.classification?.vulnerability !== false ||
    result.classification?.riskClaim !== false
  ) {
    throw new Error('Unsafe active recon classification claim.');
  }

  const now = new Date().toISOString();

  const items: PersistedActiveReconRunItem[] = result.probes.map(p => {
    // strict cast to safe values
    const error: PersistedActiveReconRunError | undefined = p.error
      ? validateError(p.error)
      : undefined;

    return {
      itemVersion: 'active-recon-document-probe-item/v0',
      family: p.family as 'document',
      safeProbeIndex: p.safeProbeIndex,
      safeKind: p.safeKind,
      status: p.status === 'planned' ? 'failed' : p.status, // planned without resolving must fail
      target: {
        normalizedOrigin: p.target.normalizedOrigin,
        safeDisplayUrl: p.target.safeDisplayUrl,
      },
      observations: p.observations,
      error,
    };
  });

  const record: PersistedActiveReconRunRecord = {
    recordVersion: 'active-recon-origin-run-record/v0',
    recordKind: 'active-recon.origin-run',
    runId: result.runId,
    subject: {
      kind: 'origin',
      normalizedOrigin: result.normalizedOrigin,
    },
    status: result.status,
    counts: {
      requested: result.requestedProbeCount,
      planned: result.plannedProbeCount,
      completed: result.completedProbeCount,
      blocked: result.blockedProbeCount,
      candidate: result.candidateProbeCount,
      failed: result.failedProbeCount,
    },
    items,
    observations: result.observations,
    runErrors: (result.runErrors || []).map(validateError),
    classification: {
      finding: false,
      evidence: false,
      vulnerability: false,
      riskClaim: false,
    },
    provenance: {
      sourceBoundary: 'M39',
      sourceContractVersion: 'active-recon-origin-run/v0',
      persistedBy: 'M40',
    },
    createdAt: now,
    updatedAt: now,
  };

  validatePersistedActiveReconRunRecord(record);

  return repository.saveRun(record);
}

export function validatePersistedActiveReconRunRecord(record: PersistedActiveReconRunRecord): void {
  // Stringify candidate and validate
  const serialized = JSON.stringify(record);

  for (const key of UNSAFE_KEYS) {
    // Only check case-insensitive presence for broad catch, but exact string for true-flags.
    if (key.includes(':true')) {
      if (serialized.includes(key)) {
        throw new Error('Persistence validation failed: contains true classification claim');
      }
    } else {
      if (serialized.toLowerCase().includes(key.toLowerCase().replace(/"/g, ''))) {
        // Wait, the prompt string matching should probably check exactly what was asked.
        // Let's use simple includes.
        // Actually, if we lower-case everything, we might falsely trigger on safe values.
        // But the prompt says "Reject if serialized candidate contains unsafe keys/claims such as: targetUrl...".
      }
    }
  }

  // Exact check based on the prompt instructions
  const exactUnsafeKeys = [
    'targetUrl',
    'raw',
    'headers',
    'body',
    'request',
    'response',
    'payload',
    'cookie',
    'authorization',
    'password',
    'api_key',
    'apikey',
    'secret',
    'token',
    'severity',
    'impact',
    'exploit',
  ];

  for (const key of exactUnsafeKeys) {
    if (serialized.includes(`"${key}"`)) {
      throw new Error(`Persistence validation failed: contains unsafe key ${key}`);
    }
  }

  const exactTrueClaims = [
    '"finding":true',
    '"evidence":true',
    '"riskClaim":true',
    '"vulnerability":true',
  ];

  for (const claim of exactTrueClaims) {
    if (serialized.includes(claim)) {
      throw new Error(`Persistence validation failed: contains true classification claim`);
    }
  }

  // Structural checks
  if (record.classification.finding !== false) throw new Error('Persistence validation failed: finding is not false');
  if (record.classification.evidence !== false) throw new Error('Persistence validation failed: evidence is not false');
  if (record.classification.vulnerability !== false) throw new Error('Persistence validation failed: vulnerability is not false');
  if (record.classification.riskClaim !== false) throw new Error('Persistence validation failed: riskClaim is not false');
  if (record.recordVersion !== 'active-recon-origin-run-record/v0') throw new Error('Persistence validation failed: invalid recordVersion');
  if (record.recordKind !== 'active-recon.origin-run') throw new Error('Persistence validation failed: invalid recordKind');
  if (record.provenance.sourceBoundary !== 'M39') throw new Error('Persistence validation failed: invalid sourceBoundary');
  if (record.provenance.persistedBy !== 'M40') throw new Error('Persistence validation failed: invalid persistedBy');

  for (const item of record.items) {
    if (item.family !== 'document') throw new Error('Persistence validation failed: unsupported item family');
    if (item.safeKind !== 'http.robots.inspect' && item.safeKind !== 'http.security_txt.inspect' && item.safeKind !== 'unknown') {
      throw new Error('Persistence validation failed: unsupported safeKind');
    }
    // ensure no raw requestId survives inside
    // (caller-provided id from M39 is `requestId` which is dropped by mapping)
  }

  if (serialized.includes('requestId')) {
     throw new Error('Persistence validation failed: contains requestId');
  }
  if (serialized.includes('planId')) {
     throw new Error('Persistence validation failed: contains planId');
  }
  if (serialized.includes('probeId')) {
     throw new Error('Persistence validation failed: contains probeId');
  }

  const DENY_PATTERNS = [
    'SECRET', 'SUPER_SECRET', 'token=', 'api_key=', 'apikey=', 'password=', 'passwd=',
    'authorization:', 'authorization=', 'bearer ', 'cookie:', 'cookie=', 'set-cookie:',
    'x-api-key', 'private_key', 'access_token', 'refresh_token', 'client_secret',
    '?token=', '&token=', '?api_key=', '&api_key=', '?apikey=', '&apikey=', '?password=', '&password='
  ];

  function recursivelyValidateStrings(obj: any) {
    if (typeof obj === 'string') {
      const lower = obj.toLowerCase();
      for (const pattern of DENY_PATTERNS) {
        if (lower.includes(pattern.toLowerCase())) {
          throw new Error('Unsafe string value rejected before persistence.');
        }
      }
    } else if (Array.isArray(obj)) {
      obj.forEach(recursivelyValidateStrings);
    } else if (obj && typeof obj === 'object') {
      for (const key of Object.keys(obj)) {
        recursivelyValidateStrings(obj[key]);
      }
    }
  }

  recursivelyValidateStrings(record);
}
