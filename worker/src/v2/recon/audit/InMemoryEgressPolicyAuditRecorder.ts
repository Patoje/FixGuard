/**
 * InMemoryEgressPolicyAuditRecorder.ts
 *
 * An in-memory, test-only audit recorder for EgressPolicyAuditEvents.
 *
 * Rules:
 *  - No global singleton — must be explicitly instantiated.
 *  - No env/config reads.
 *  - No persistence, no DB client, no runtime integration.
 *  - Stores deep-cloned sanitized event objects.
 *  - Returns deep clones on every read — callers cannot mutate internal state.
 *  - Preserves insertion order.
 *  - Rejects events with forbidden executable/secret fields.
 *  - Does NOT pretend to be production audit storage.
 *
 * This recorder is a future bridge, not production persistence.
 */

import type { EgressPolicyAuditEvent, EgressPolicyAuditRecordResult } from './EgressPolicyAuditContracts';

/**
 * Forbidden top-level field names that must never appear on a recorded event.
 * These correspond to executable payloads, raw requests, and secret values.
 */
const FORBIDDEN_EVENT_FIELDS: ReadonlySet<string> = new Set([
  'capabilityRequest',
  'CapabilityRequest',
  'executionRequest',
  'ExecutionRequest',
  'binary',
  'args',
  'env',
  'shell',
  'command',
  'stdin',
  'executable',
  'runner',
  'adapterCommand',
  'rawUrl',
  'originalUrl',
  'rawRequest',
  'requestBody',
  'responseBody',
  'headers',
  'cookies',
  'authorization',
  'token',
  'password',
  'secret',
  'apiKey',
  'setCookie',
  'scannerOutput',
  'finding',
  'riskScore',
  'severity',
  'impact',
  'exploit',
  'payload',
  'stackTrace',
]);

/**
 * Deep-clone an EgressPolicyAuditEvent using JSON round-trip.
 * Events contain only plain JSON-serializable data, so this is safe and sufficient.
 */
function deepCloneEvent(event: EgressPolicyAuditEvent): EgressPolicyAuditEvent {
  return JSON.parse(JSON.stringify(event)) as EgressPolicyAuditEvent;
}

const FORBIDDEN_EVENT_FIELDS_LOWER = new Set(Array.from(FORBIDDEN_EVENT_FIELDS).map(f => f.toLowerCase()));

/**
 * Verify that a candidate event object does not contain forbidden fields recursively.
 * Returns the first forbidden field found, or null if clean.
 */
function findForbiddenField(obj: unknown, path: string = ''): string | null {
  if (obj === null || typeof obj !== 'object') {
    return null;
  }

  if (Array.isArray(obj)) {
    for (const item of obj) {
      const res = findForbiddenField(item, path);
      if (res !== null) return res;
    }
    return null;
  }

  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase();
    
    if (FORBIDDEN_EVENT_FIELDS_LOWER.has(lowerKey)) {
      const isAllowedClassificationField = path === 'classification' && ['finding', 'evidence', 'vulnerability', 'riskclaim'].includes(lowerKey);
      const isAllowedSafetyField = path === 'safety' && ['containsrawsecret', 'rawrequestpersisted', 'executablepayloadpersisted'].includes(lowerKey);
      
      if (!isAllowedClassificationField && !isAllowedSafetyField) {
        return key;
      }
    }

    const currentPath = path === '' ? key : `${path}.${key}`;
    const res = findForbiddenField(value, currentPath);
    if (res !== null) return res;
  }

  return null;
}

/**
 * Verify that an event's classification and safety literal flags are correct.
 * Returns a description of the violation, or null if clean.
 */
function verifyEventIntegrity(event: EgressPolicyAuditEvent): string | null {
  if (event.eventKind !== 'egress_policy_decision') {
    return `Invalid eventKind: ${String(event.eventKind)}`;
  }
  if (event.eventVersion !== 1) {
    return `Invalid eventVersion: ${String(event.eventVersion)}`;
  }
  if (event.classification.controlPlaneEvent !== true) {
    return 'classification.controlPlaneEvent must be true';
  }
  if (event.classification.finding !== false) {
    return 'classification.finding must be false';
  }
  if (event.classification.evidence !== false) {
    return 'classification.evidence must be false';
  }
  if (event.classification.vulnerability !== false) {
    return 'classification.vulnerability must be false';
  }
  if (event.classification.riskClaim !== false) {
    return 'classification.riskClaim must be false';
  }
  if (event.safety.sensitiveValuesRedacted !== true) {
    return 'safety.sensitiveValuesRedacted must be true';
  }
  if (event.safety.containsRawSecret !== false) {
    return 'safety.containsRawSecret must be false';
  }
  if (event.safety.rawRequestPersisted !== false) {
    return 'safety.rawRequestPersisted must be false';
  }
  if (event.safety.executablePayloadPersisted !== false) {
    return 'safety.executablePayloadPersisted must be false';
  }
  return null;
}

export class InMemoryEgressPolicyAuditRecorder {
  private readonly _events: EgressPolicyAuditEvent[] = [];

  /**
   * Record a sanitized EgressPolicyAuditEvent.
   *
   * Before storing:
   *  1. Checks for forbidden top-level fields.
   *  2. Verifies classification and safety literal flags.
   *  3. Stores a deep clone so internal state cannot be mutated externally.
   *
   * Returns a RecordResult indicating success or the rejection reason.
   */
  record(event: EgressPolicyAuditEvent): EgressPolicyAuditRecordResult {
    // Check for forbidden fields
    const forbiddenField = findForbiddenField(event as unknown as Record<string, unknown>);
    if (forbiddenField !== null) {
      return { recorded: false, reason: `Forbidden field present: ${forbiddenField}` };
    }

    // Verify structural integrity of classification/safety flags
    const integrityError = verifyEventIntegrity(event);
    if (integrityError !== null) {
      return { recorded: false, reason: `Event integrity violation: ${integrityError}` };
    }

    // Store a deep clone to prevent external mutation of stored state
    this._events.push(deepCloneEvent(event));

    return { recorded: true, eventId: event.eventId };
  }

  /**
   * Return all stored events in insertion order, as deep clones.
   * Callers cannot mutate the recorder's internal state through the returned array.
   */
  getEvents(): EgressPolicyAuditEvent[] {
    return this._events.map(deepCloneEvent);
  }

  /**
   * Return the count of stored events.
   */
  get count(): number {
    return this._events.length;
  }

  /**
   * Clear all stored events. Useful for test setup/teardown.
   */
  clear(): void {
    this._events.length = 0;
  }
}
