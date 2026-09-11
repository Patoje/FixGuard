import type {
  EvidenceBoundaryErrorCode,
  ValidationResult,
  FindingPromotionDecision,
  FindingPromotionDecisionStatus,
  BuildFindingCandidateResult,
  BuildSafeReportItemSnapshotResult,
  ObservationRecord,
  IndicatorRecord,
  EvidenceRecord,
  FindingCandidateRecord,
  SafeReportItemSnapshot,
  SafeExcerpt,
  SafeSubject,
  EvidenceBoundaryClassificationFlags,
  SeverityGate,
  FindingCandidateType,
  EvidenceSnapshot
} from './EvidenceBoundaryContracts.js';

import {
  ALLOWED_OBSERVATION_SOURCE_KINDS,
  ALLOWED_OBSERVATION_TYPES,
  ALLOWED_SAFE_EXCERPT_SOURCES,
  ALLOWED_HTTP_METHODS,
  ALLOWED_INDICATOR_TYPES,
  ALLOWED_APPROVAL_LEVELS,
  ALLOWED_COLLECTED_BY,
  ALLOWED_EVIDENCE_TYPES,
  ALLOWED_OOB_PROTOCOLS,
  ALLOWED_EVIDENCE_STRENGTHS,
  ALLOWED_CANDIDATE_TYPES,
  ALLOWED_CANDIDATE_STATUSES,
  ALLOWED_SEVERITY_GATE_STATUSES
} from './EvidenceBoundaryContracts.js';

export function validateAllowedKeys(value: any, allowedKeys: readonly string[]): ValidationResult {
  if (!value || typeof value !== 'object') return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Value must be an object' };
  const keys = Object.keys(value);
  for (const key of keys) {
    if (!allowedKeys.includes(key)) {
      return { isValid: false, errorCode: 'unsafe_content_rejected', message: `Unknown or forbidden property rejected: ${key}` };
    }
  }
  return { isValid: true };
}

export function forbiddenContentScan(str: string): boolean {
  if (!str) return false;
  const lower = str.toLowerCase();
  const forbidden = [
    'authorization', 'authorization:', 'bearer', 'bearer ', 
    'cookie', 'cookie:', 'set-cookie', 'password', 'secret', 'token',
    'api_key', 'apikey', 'access_token', 'refresh_token',
    'raw_request', 'raw request', 'raw_response', 'raw response', 
    'raw_body', 'raw body', 'raw_headers', 'raw headers', 
    'raw payload', 'raw command', 'raw output', 'raw tool output', 
    'stack trace', 'error:',
    'confirmed vulnerability', 'target is vulnerable', 'critical severity'
  ];
  return forbidden.some(f => lower.includes(f));
}

export function validateClassificationFlags(classification: any): ValidationResult {
  const keysVal = validateAllowedKeys(classification, ['createsRealFindings', 'createsPersistedEvidence', 'confirmsVulnerabilities', 'makesRiskClaims', 'makesSeverityClaims', 'makesImpactClaims']);
  if (!keysVal.isValid) return keysVal;

  if (
    classification.createsRealFindings !== false ||
    classification.createsPersistedEvidence !== false ||
    classification.confirmsVulnerabilities !== false ||
    classification.makesRiskClaims !== false ||
    classification.makesSeverityClaims !== false ||
    classification.makesImpactClaims !== false
  ) {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Classification flags must all be false' };
  }
  return { isValid: true };
}

export function validateSafeId(id: string | undefined): ValidationResult {
  if (!id || typeof id !== 'string' || id.length === 0) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'ID is missing or empty' };
  if (id.length > 128) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'ID exceeds max length 128' };
  if (!/^[a-zA-Z0-9_\-.:]+$/.test(id)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'ID contains invalid characters' };
  if (forbiddenContentScan(id)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'ID contains forbidden content' };
  return { isValid: true };
}

export function validateIsoTimestamp(ts: string | undefined): ValidationResult {
  if (!ts || typeof ts !== 'string') return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Timestamp missing' };
  if (isNaN(Date.parse(ts))) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid ISO timestamp' };
  return { isValid: true };
}

export function validateSafeHash(hash: string | undefined): ValidationResult {
  if (!hash || typeof hash !== 'string') return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Hash missing' };
  if (hash.length > 128) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Hash exceeds max length 128' };
  if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(hash)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Hash contains invalid characters' };
  if (forbiddenContentScan(hash)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Hash contains forbidden content' };
  return { isValid: true };
}

export function validateFreeText(text: string | undefined, maxLength: number): ValidationResult {
  if (text === undefined || typeof text !== 'string') return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Text missing or invalid type' };
  if (text.length > maxLength) return { isValid: false, errorCode: 'unsafe_content_rejected', message: `Text exceeds max length ${maxLength}` };
  if (forbiddenContentScan(text)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Text contains forbidden content' };
  return { isValid: true };
}

export function validateSafeExcerpt(excerpt: SafeExcerpt | undefined): ValidationResult {
  if (!excerpt) return { isValid: true };
  const keysVal = validateAllowedKeys(excerpt, ['text', 'source', 'redacted']);
  if (!keysVal.isValid) return keysVal;

  if (excerpt.redacted !== true) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Excerpt must be redacted: true' };
  if (!ALLOWED_SAFE_EXCERPT_SOURCES.includes(excerpt.source)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid excerpt source' };
  return validateFreeText(excerpt.text, 300);
}

export function validateSafeSubject(subject: SafeSubject | undefined): ValidationResult {
  if (!subject) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Subject missing' };
  const keysVal = validateAllowedKeys(subject, ['normalizedOrigin', 'method', 'pathTemplate', 'routeId', 'assetUrlHash']);
  if (!keysVal.isValid) return keysVal;

  if (subject.method !== undefined && !ALLOWED_HTTP_METHODS.includes(subject.method as any)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid HTTP method' };
  if (subject.pathTemplate !== undefined) {
    if (typeof subject.pathTemplate !== 'string') return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'pathTemplate must be string' };
    if (!subject.pathTemplate.startsWith('/')) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Path template must start with /' };
    if (subject.pathTemplate.includes('?') || subject.pathTemplate.includes('#')) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Path template cannot contain query or fragment' };
    const textVal = validateFreeText(subject.pathTemplate, 200);
    if (!textVal.isValid) return textVal;
  }
  if (subject.routeId !== undefined) {
    const idVal = validateSafeId(subject.routeId);
    if (!idVal.isValid) return idVal;
  }
  if (subject.assetUrlHash !== undefined) {
    const hashVal = validateSafeHash(subject.assetUrlHash);
    if (!hashVal.isValid) return hashVal;
  }
  if (subject.normalizedOrigin !== undefined) {
    const textVal = validateFreeText(subject.normalizedOrigin, 200);
    if (!textVal.isValid) return textVal;
  }
  return { isValid: true };
}

export function getSafeClassification(): EvidenceBoundaryClassificationFlags {
  return {
    createsRealFindings: false,
    createsPersistedEvidence: false,
    confirmsVulnerabilities: false,
    makesRiskClaims: false,
    makesSeverityClaims: false,
    makesImpactClaims: false
  };
}

export function validateObservationRecord(record: any): ValidationResult {
  if (!record || record.kind !== 'observation_record') return { isValid: false, errorCode: 'invalid_observation', message: 'Invalid kind' };
  if (record.contractVersion !== "fixguard-evidence-boundary/v0") return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid contractVersion' };
  
  const keysVal = validateAllowedKeys(record, ['contractVersion', 'kind', 'observationId', 'scanId', 'observedAt', 'sourceKind', 'observationType', 'subject', 'provenance', 'safeData', 'classification']);
  if (!keysVal.isValid) return keysVal;

  const classVal = validateClassificationFlags(record.classification);
  if (!classVal.isValid) return { isValid: false, errorCode: 'invalid_observation', message: classVal.message };

  if (!ALLOWED_OBSERVATION_SOURCE_KINDS.includes(record.sourceKind)) return { isValid: false, errorCode: 'invalid_observation', message: 'Invalid sourceKind' };
  if (!ALLOWED_OBSERVATION_TYPES.includes(record.observationType)) return { isValid: false, errorCode: 'invalid_observation', message: 'Invalid observationType' };

  const checks = [
    validateSafeId(record.observationId),
    validateSafeId(record.scanId),
    validateIsoTimestamp(record.observedAt),
    validateSafeSubject(record.subject)
  ];
  const firstFail = checks.find(c => !c.isValid);
  if (firstFail) return { isValid: false, errorCode: 'invalid_observation', message: firstFail.message };

  if (record.provenance) {
    const provKeys = validateAllowedKeys(record.provenance, ['originId', 'description']);
    if (!provKeys.isValid) return provKeys;
    const pVal = validateFreeText(record.provenance.description, 500);
    if (!pVal.isValid) return { isValid: false, errorCode: 'invalid_observation', message: pVal.message };
  }

  if (record.safeData) {
    const sdKeys = validateAllowedKeys(record.safeData, ['statusCode', 'contentLength', 'headerNames', 'bodyHash', 'rawOutputHash', 'safeExcerpt']);
    if (!sdKeys.isValid) return sdKeys;

    if (record.safeData.bodyHash) {
      const bhVal = validateSafeHash(record.safeData.bodyHash);
      if (!bhVal.isValid) return { isValid: false, errorCode: 'invalid_observation', message: bhVal.message };
    }
    if (record.safeData.rawOutputHash) {
      const rhVal = validateSafeHash(record.safeData.rawOutputHash);
      if (!rhVal.isValid) return { isValid: false, errorCode: 'invalid_observation', message: rhVal.message };
    }
    if (record.safeData.safeExcerpt) {
      const eVal = validateSafeExcerpt(record.safeData.safeExcerpt);
      if (!eVal.isValid) return { isValid: false, errorCode: 'invalid_observation', message: eVal.message };
    }
    if (record.safeData.headerNames) {
      if (!Array.isArray(record.safeData.headerNames)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'headerNames must be an array' };
      for (const hn of record.safeData.headerNames) {
        if (typeof hn !== 'string') return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Header name must be string' };
        if (hn.length > 100) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Header name too long' };
        if (forbiddenContentScan(hn)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Header name contains forbidden content' };
      }
    }
  }

  return { isValid: true };
}

export function validateIndicatorRecord(record: any): ValidationResult {
  if (!record || record.kind !== 'indicator_record') return { isValid: false, errorCode: 'invalid_indicator', message: 'Invalid kind' };
  if (record.contractVersion !== "fixguard-evidence-boundary/v0") return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid contractVersion' };

  const keysVal = validateAllowedKeys(record, ['contractVersion', 'kind', 'indicatorId', 'scanId', 'derivedFromObservationIds', 'indicatorType', 'target', 'confidence', 'rationale', 'suggestedValidation', 'requiresHumanApproval', 'approvalLevelRequired', 'classification']);
  if (!keysVal.isValid) return keysVal;

  const classVal = validateClassificationFlags(record.classification);
  if (!classVal.isValid) return { isValid: false, errorCode: 'invalid_indicator', message: classVal.message };

  if (!ALLOWED_INDICATOR_TYPES.includes(record.indicatorType)) return { isValid: false, errorCode: 'invalid_indicator', message: 'Invalid indicatorType' };
  if (!ALLOWED_APPROVAL_LEVELS.includes(record.approvalLevelRequired)) return { isValid: false, errorCode: 'invalid_indicator', message: 'Invalid approvalLevelRequired' };

  const checks = [
    validateSafeId(record.indicatorId),
    validateSafeId(record.scanId),
    validateSafeSubject(record.target),
    validateFreeText(record.rationale, 500),
    validateFreeText(record.suggestedValidation, 500)
  ];
  
  const firstFail = checks.find(c => !c.isValid);
  if (firstFail) return { isValid: false, errorCode: 'invalid_indicator', message: firstFail.message };

  if (!record.derivedFromObservationIds || !Array.isArray(record.derivedFromObservationIds) || record.derivedFromObservationIds.length === 0) {
    return { isValid: false, errorCode: 'invalid_indicator', message: 'Must derive from at least one observation (array required)' };
  }

  for (const obsId of record.derivedFromObservationIds) {
    const val = validateSafeId(obsId);
    if (!val.isValid) return { isValid: false, errorCode: 'invalid_indicator', message: val.message };
  }

  if (record.confidence < 0 || record.confidence > 1 || !isFinite(record.confidence)) {
    return { isValid: false, errorCode: 'invalid_indicator', message: 'Confidence must be between 0 and 1' };
  }

  return { isValid: true };
}

export function validateExecutionLineage(lineage: any): ValidationResult {
  if (!lineage || typeof lineage !== 'object' || Array.isArray(lineage)) {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Execution lineage must be an object' };
  }
  const keysVal = validateAllowedKeys(lineage, [
    'assessmentId', 'scanId', 'authorizationGrantId', 'authorizationDecisionId', 'actorId', 'validationId'
  ]);
  if (!keysVal.isValid) return keysVal;

  const keys = Object.keys(lineage);
  if (keys.length !== 6) {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Execution lineage must contain exactly 6 keys' };
  }

  const checks = [
    validateSafeId(lineage.assessmentId),
    validateSafeId(lineage.scanId),
    validateSafeId(lineage.authorizationGrantId),
    validateSafeId(lineage.authorizationDecisionId),
    validateSafeId(lineage.actorId),
    validateSafeId(lineage.validationId)
  ];

  const firstFail = checks.find(c => !c.isValid);
  if (firstFail) {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: `Invalid lineage field: ${firstFail.message}` };
  }

  return { isValid: true };
}

export function validateEvidenceRecord(record: any): ValidationResult {
  if (!record || record.kind !== 'evidence_record') return { isValid: false, errorCode: 'invalid_evidence', message: 'Invalid kind' };
  if (record.contractVersion !== "fixguard-evidence-boundary/v0") return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid contractVersion' };

  const keysVal = validateAllowedKeys(record, ['contractVersion', 'kind', 'evidenceId', 'scanId', 'indicatorId', 'collectedAt', 'collectedBy', 'evidenceType', 'baseline', 'attackOrValidation', 'difference', 'oobCallback', 'lineage', 'redaction', 'strength', 'classification']);
  if (!keysVal.isValid) return keysVal;

  if (record.lineage !== undefined) {
    const linVal = validateExecutionLineage(record.lineage);
    if (!linVal.isValid) return { isValid: false, errorCode: 'invalid_lineage', message: linVal.message };
    if (record.lineage.scanId !== record.scanId) {
      return { isValid: false, errorCode: 'invalid_lineage', message: 'Lineage scanId must match record scanId' };
    }
  }

  const classVal = validateClassificationFlags(record.classification);
  if (!classVal.isValid) return { isValid: false, errorCode: 'invalid_evidence', message: classVal.message };

  if (!ALLOWED_COLLECTED_BY.includes(record.collectedBy)) return { isValid: false, errorCode: 'invalid_evidence', message: 'Invalid collectedBy' };
  if (!ALLOWED_EVIDENCE_TYPES.includes(record.evidenceType)) return { isValid: false, errorCode: 'invalid_evidence', message: 'Invalid evidenceType' };
  if (!ALLOWED_EVIDENCE_STRENGTHS.includes(record.strength)) return { isValid: false, errorCode: 'invalid_evidence', message: 'Invalid strength' };

  const redKeys = validateAllowedKeys(record.redaction, ['isRedacted', 'redactionMethod']);
  if (!redKeys.isValid) return redKeys;

  if (record.redaction.isRedacted !== true) {
    return { isValid: false, errorCode: 'invalid_evidence', message: 'Evidence must be explicitly redacted' };
  }
  const rmVal = validateFreeText(record.redaction.redactionMethod, 100);
  if (!rmVal.isValid) return { isValid: false, errorCode: 'invalid_evidence', message: 'Invalid redactionMethod: ' + rmVal.message };

  const checks = [
    validateSafeId(record.evidenceId),
    validateSafeId(record.scanId),
    validateSafeId(record.indicatorId),
    validateIsoTimestamp(record.collectedAt)
  ];

  const firstFail = checks.find(c => !c.isValid);
  if (firstFail) return { isValid: false, errorCode: 'invalid_evidence', message: firstFail.message };

  const validateSnapshot = (snap: any): ValidationResult => {
    if (!snap) return { isValid: true };
    const snapKeys = validateAllowedKeys(snap, ['method', 'normalizedUrlHash', 'pathTemplate', 'statusCode', 'contentLength', 'responseTimeMs', 'headerNames', 'bodyHash', 'safeExcerpt', 'payloadDescription', 'payloadHash']);
    if (!snapKeys.isValid) return snapKeys;

    if (snap.method !== undefined && !ALLOWED_HTTP_METHODS.includes(snap.method)) return { isValid: false, errorCode: 'invalid_evidence', message: 'Invalid HTTP method' };
    if (snap.pathTemplate !== undefined) {
      if (typeof snap.pathTemplate !== 'string') return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'pathTemplate must be string' };
      if (!snap.pathTemplate.startsWith('/')) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Path template must start with /' };
      if (snap.pathTemplate.includes('?') || snap.pathTemplate.includes('#')) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Path template cannot contain query/fragment' };
      const val = validateFreeText(snap.pathTemplate, 200);
      if (!val.isValid) return val;
    }
    if (snap.headerNames !== undefined) {
      if (!Array.isArray(snap.headerNames)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'headerNames must be array' };
      for (const hn of snap.headerNames) {
        if (typeof hn !== 'string') return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'headerNames must be strings' };
        if (hn.length > 100) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'headerName too long' };
        if (forbiddenContentScan(hn)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'headerName forbidden content' };
      }
    }
    if (snap.statusCode !== undefined) {
      if (!Number.isInteger(snap.statusCode) || snap.statusCode < 100 || snap.statusCode > 599) return { isValid: false, errorCode: 'invalid_evidence', message: 'Invalid statusCode' };
    }
    if (snap.contentLength !== undefined) {
      if (!Number.isFinite(snap.contentLength) || snap.contentLength < 0) return { isValid: false, errorCode: 'invalid_evidence', message: 'Invalid contentLength' };
    }
    if (snap.responseTimeMs !== undefined) {
      if (!Number.isFinite(snap.responseTimeMs) || snap.responseTimeMs < 0) return { isValid: false, errorCode: 'invalid_evidence', message: 'Invalid responseTimeMs' };
    }
    if (snap.normalizedUrlHash) { const val = validateSafeHash(snap.normalizedUrlHash); if (!val.isValid) return val; }
    if (snap.bodyHash) { const val = validateSafeHash(snap.bodyHash); if (!val.isValid) return val; }
    if (snap.payloadHash) { const val = validateSafeHash(snap.payloadHash); if (!val.isValid) return val; }
    if (snap.payloadDescription) { const val = validateFreeText(snap.payloadDescription, 300); if (!val.isValid) return val; }
    if (snap.safeExcerpt) { const val = validateSafeExcerpt(snap.safeExcerpt); if (!val.isValid) return val; }
    return { isValid: true };
  };

  const snapBaseline = validateSnapshot(record.baseline);
  if (!snapBaseline.isValid) return { isValid: false, errorCode: 'invalid_evidence', message: snapBaseline.message };

  const snapAttack = validateSnapshot(record.attackOrValidation);
  if (!snapAttack.isValid) return { isValid: false, errorCode: 'invalid_evidence', message: snapAttack.message };

  if (record.difference) {
    const diffKeys = validateAllowedKeys(record.difference, ['statusCodeChanged', 'contentLengthDeltaPercent', 'responseTimeDeltaMs', 'newJsonKeys', 'missingJsonKeys', 'redirectChanged', 'authStateChanged', 'errorSignalObserved']);
    if (!diffKeys.isValid) return diffKeys;

    if (record.difference.contentLengthDeltaPercent !== undefined && !Number.isFinite(record.difference.contentLengthDeltaPercent)) return { isValid: false, errorCode: 'invalid_evidence', message: 'Invalid contentLengthDeltaPercent' };
    if (record.difference.responseTimeDeltaMs !== undefined && !Number.isFinite(record.difference.responseTimeDeltaMs)) return { isValid: false, errorCode: 'invalid_evidence', message: 'Invalid responseTimeDeltaMs' };
    if (record.difference.newJsonKeys) {
      if (!Array.isArray(record.difference.newJsonKeys)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'newJsonKeys must be an array' };
      for (const k of record.difference.newJsonKeys) {
        if (typeof k !== 'string' || k.length > 100 || forbiddenContentScan(k)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid newJsonKeys' };
      }
    }
    if (record.difference.missingJsonKeys) {
      if (!Array.isArray(record.difference.missingJsonKeys)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'missingJsonKeys must be an array' };
      for (const k of record.difference.missingJsonKeys) {
        if (typeof k !== 'string' || k.length > 100 || forbiddenContentScan(k)) return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid missingJsonKeys' };
      }
    }
  }

  if (record.oobCallback) {
    const oobKeys = validateAllowedKeys(record.oobCallback, ['correlationId', 'receivedAt', 'protocol', 'sourceIpHash', 'rawCallbackHash']);
    if (!oobKeys.isValid) return oobKeys;

    if (!ALLOWED_OOB_PROTOCOLS.includes(record.oobCallback.protocol)) return { isValid: false, errorCode: 'invalid_evidence', message: 'Invalid OOB protocol' };
    const checksOob = [
      validateSafeId(record.oobCallback.correlationId),
      validateIsoTimestamp(record.oobCallback.receivedAt),
      validateSafeHash(record.oobCallback.sourceIpHash),
      validateSafeHash(record.oobCallback.rawCallbackHash)
    ];
    const failOob = checksOob.find(c => !c.isValid);
    if (failOob) return { isValid: false, errorCode: 'invalid_evidence', message: failOob.message };
  }

  return { isValid: true };
}

export function validateEvidenceSubstance(record: any): ValidationResult {
  const baseVal = validateEvidenceRecord(record);
  if (!baseVal.isValid) {
    return baseVal;
  }

  if (!record.lineage) {
    return {
      isValid: false,
      errorCode: 'insufficient_evidence_substance',
      message: 'Substantive evidence requires execution lineage'
    };
  }

  const lineageVal = validateExecutionLineage(record.lineage);
  if (!lineageVal.isValid) {
    return {
      isValid: false,
      errorCode: 'insufficient_evidence_substance',
      message: `Invalid execution lineage: ${lineageVal.message}`
    };
  }

  if (record.lineage.scanId !== record.scanId) {
    return {
      isValid: false,
      errorCode: 'insufficient_evidence_substance',
      message: 'Lineage scanId must match evidence scanId'
    };
  }

  switch (record.evidenceType) {
    case 'http_difference':
    case 'authorization_difference': {
      if (!record.baseline || typeof record.baseline !== 'object' || Array.isArray(record.baseline)) {
        return {
          isValid: false,
          errorCode: 'insufficient_evidence_substance',
          message: 'HTTP difference evidence must contain baseline snapshot'
        };
      }
      if (!record.attackOrValidation || typeof record.attackOrValidation !== 'object' || Array.isArray(record.attackOrValidation)) {
        return {
          isValid: false,
          errorCode: 'insufficient_evidence_substance',
          message: 'HTTP difference evidence must contain attack/validation snapshot'
        };
      }
      if (!record.difference || typeof record.difference !== 'object' || Array.isArray(record.difference)) {
        return {
          isValid: false,
          errorCode: 'insufficient_evidence_substance',
          message: 'HTTP difference evidence must contain difference object'
        };
      }
      const hasSignal =
        record.difference.statusCodeChanged === true ||
        (typeof record.difference.contentLengthDeltaPercent === 'number' && record.difference.contentLengthDeltaPercent !== 0) ||
        (Array.isArray(record.difference.newJsonKeys) && record.difference.newJsonKeys.length > 0) ||
        (Array.isArray(record.difference.missingJsonKeys) && record.difference.missingJsonKeys.length > 0) ||
        record.difference.authStateChanged === true ||
        record.difference.errorSignalObserved === true ||
        record.difference.redirectChanged === true;

      if (!hasSignal) {
        return {
          isValid: false,
          errorCode: 'insufficient_evidence_substance',
          message: 'HTTP difference evidence must contain at least one active differential signal'
        };
      }
      break;
    }
    case 'time_based_difference': {
      if (!record.baseline || typeof record.baseline !== 'object' || Array.isArray(record.baseline)) {
        return {
          isValid: false,
          errorCode: 'insufficient_evidence_substance',
          message: 'Time-based difference evidence must contain baseline snapshot'
        };
      }
      if (!record.attackOrValidation || typeof record.attackOrValidation !== 'object' || Array.isArray(record.attackOrValidation)) {
        return {
          isValid: false,
          errorCode: 'insufficient_evidence_substance',
          message: 'Time-based difference evidence must contain attack/validation snapshot'
        };
      }
      if (
        !record.difference ||
        typeof record.difference.responseTimeDeltaMs !== 'number' ||
        !Number.isFinite(record.difference.responseTimeDeltaMs) ||
        record.difference.responseTimeDeltaMs <= 0
      ) {
        return {
          isValid: false,
          errorCode: 'insufficient_evidence_substance',
          message: 'Time-based difference evidence requires positive responseTimeDeltaMs in difference'
        };
      }
      break;
    }
    case 'oob_callback': {
      if (!record.oobCallback || typeof record.oobCallback !== 'object' || Array.isArray(record.oobCallback)) {
        return {
          isValid: false,
          errorCode: 'insufficient_evidence_substance',
          message: 'OOB callback evidence requires valid oobCallback payload'
        };
      }
      break;
    }
    case 'configuration_exposure':
    case 'secret_indicator_validated': {
      if (!record.attackOrValidation || typeof record.attackOrValidation !== 'object' || Array.isArray(record.attackOrValidation)) {
        return {
          isValid: false,
          errorCode: 'insufficient_evidence_substance',
          message: 'Configuration exposure evidence requires attackOrValidation snapshot'
        };
      }
      const hasSubstance = !!(record.attackOrValidation.safeExcerpt || record.attackOrValidation.bodyHash);
      if (!hasSubstance) {
        return {
          isValid: false,
          errorCode: 'insufficient_evidence_substance',
          message: 'Configuration exposure evidence requires safeExcerpt or bodyHash in attackOrValidation'
        };
      }
      break;
    }
    case 'manual_review_note': {
      if (
        !record.attackOrValidation ||
        !record.attackOrValidation.safeExcerpt ||
        record.attackOrValidation.safeExcerpt.source !== 'manual_note'
      ) {
        return {
          isValid: false,
          errorCode: 'insufficient_evidence_substance',
          message: 'Manual review note evidence requires attackOrValidation with safeExcerpt from manual_note'
        };
      }
      break;
    }
    default:
      return {
        isValid: false,
        errorCode: 'insufficient_evidence_substance',
        message: `Unsupported evidence type for substance validation: ${record.evidenceType}`
      };
  }

  return { isValid: true };
}

export function validateFindingCandidateRecord(record: any): ValidationResult {
  if (!record || record.kind !== 'finding_candidate_record') return { isValid: false, errorCode: 'invalid_finding_candidate', message: 'Invalid kind' };
  if (record.contractVersion !== "fixguard-evidence-boundary/v0") return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid contractVersion' };

  const keysVal = validateAllowedKeys(record, ['contractVersion', 'kind', 'candidateId', 'scanId', 'derivedFromIndicatorIds', 'evidenceIds', 'candidateType', 'status', 'confidence', 'severityGate', 'rationale', 'classification', 'isRealFinding', 'requiresHumanReview', 'notForExternalDelivery']);
  if (!keysVal.isValid) return keysVal;

  if (record.isRealFinding !== false || record.requiresHumanReview !== true || record.notForExternalDelivery !== true) {
    return { isValid: false, errorCode: 'invalid_finding_candidate', message: 'Invalid safety flags' };
  }

  const classVal = validateClassificationFlags(record.classification);
  if (!classVal.isValid) return { isValid: false, errorCode: 'invalid_finding_candidate', message: classVal.message };

  if (!ALLOWED_CANDIDATE_TYPES.includes(record.candidateType)) return { isValid: false, errorCode: 'invalid_finding_candidate', message: 'Invalid candidateType' };
  if (!ALLOWED_CANDIDATE_STATUSES.includes(record.status)) return { isValid: false, errorCode: 'invalid_finding_candidate', message: 'Invalid status' };

  if (!record.severityGate) return { isValid: false, errorCode: 'invalid_finding_candidate', message: 'Missing severityGate' };
  
  const sgKeys = validateAllowedKeys(record.severityGate, ['status', 'reason']);
  if (!sgKeys.isValid) return sgKeys;

  if (!ALLOWED_SEVERITY_GATE_STATUSES.includes(record.severityGate.status)) return { isValid: false, errorCode: 'invalid_finding_candidate', message: 'Invalid severityGate status' };
  const sgVal = validateFreeText(record.severityGate.reason, 500);
  if (!sgVal.isValid) return { isValid: false, errorCode: 'invalid_finding_candidate', message: sgVal.message };

  const checks = [
    validateSafeId(record.candidateId),
    validateSafeId(record.scanId),
    validateFreeText(record.rationale, 500)
  ];

  const firstFail = checks.find(c => !c.isValid);
  if (firstFail) return { isValid: false, errorCode: 'invalid_finding_candidate', message: firstFail.message };

  if (!Array.isArray(record.derivedFromIndicatorIds) || record.derivedFromIndicatorIds.length === 0) {
    return { isValid: false, errorCode: 'invalid_finding_candidate', message: 'derivedFromIndicatorIds must be non-empty array' };
  }
  for (const id of record.derivedFromIndicatorIds) {
    const val = validateSafeId(id);
    if (!val.isValid) return { isValid: false, errorCode: 'invalid_finding_candidate', message: val.message };
  }

  if (!Array.isArray(record.evidenceIds) || record.evidenceIds.length === 0) {
    return { isValid: false, errorCode: 'invalid_finding_candidate', message: 'evidenceIds must be non-empty array' };
  }
  for (const id of record.evidenceIds) {
    const val = validateSafeId(id);
    if (!val.isValid) return { isValid: false, errorCode: 'invalid_finding_candidate', message: val.message };
  }

  if (record.confidence < 0 || record.confidence > 1 || !isFinite(record.confidence)) {
    return { isValid: false, errorCode: 'invalid_finding_candidate', message: 'Confidence must be between 0 and 1' };
  }

  return { isValid: true };
}

export function validateSafeReportItemSnapshot(record: any): ValidationResult {
  if (!record || record.kind !== 'safe_report_item_snapshot') return { isValid: false, errorCode: 'invalid_report_item', message: 'Invalid kind' };
  if (record.contractVersion !== "fixguard-evidence-boundary/v0") return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid contractVersion' };

  const keysVal = validateAllowedKeys(record, ['contractVersion', 'kind', 'candidateId', 'title', 'summary', 'affectedSubject', 'evidenceSummary', 'recommendationSummary', 'reportReadiness', 'explicitNonClaims', 'classification']);
  if (!keysVal.isValid) return keysVal;

  if (!record.reportReadiness) return { isValid: false, errorCode: 'invalid_report_item', message: 'Missing reportReadiness' };
  const rrKeys = validateAllowedKeys(record.reportReadiness, ['externalDeliveryReady', 'requiresHumanReview', 'notAFinalVulnerabilityReport']);
  if (!rrKeys.isValid) return rrKeys;

  if (record.reportReadiness.externalDeliveryReady !== false || record.reportReadiness.requiresHumanReview !== true || record.reportReadiness.notAFinalVulnerabilityReport !== true) {
    return { isValid: false, errorCode: 'invalid_report_item', message: 'Invalid report readiness flags' };
  }

  if (!record.explicitNonClaims) return { isValid: false, errorCode: 'invalid_report_item', message: 'Missing explicitNonClaims' };
  const encKeys = validateAllowedKeys(record.explicitNonClaims, ['noConfirmedVulnerability', 'noRealFindingCreated', 'noPersistedEvidenceCreated', 'noRiskSeverityOrImpactClaim', 'noRawSensitiveDataIncluded']);
  if (!encKeys.isValid) return encKeys;

  if (record.explicitNonClaims.noConfirmedVulnerability !== true || record.explicitNonClaims.noRealFindingCreated !== true || record.explicitNonClaims.noPersistedEvidenceCreated !== true || record.explicitNonClaims.noRiskSeverityOrImpactClaim !== true || record.explicitNonClaims.noRawSensitiveDataIncluded !== true) {
    return { isValid: false, errorCode: 'invalid_report_item', message: 'Invalid explicit non claims flags' };
  }

  const classVal = validateClassificationFlags(record.classification);
  if (!classVal.isValid) return { isValid: false, errorCode: 'invalid_report_item', message: classVal.message };

  const checks = [
    validateSafeId(record.candidateId),
    validateSafeSubject(record.affectedSubject),
    validateFreeText(record.title, 160),
    validateFreeText(record.summary, 800),
    validateFreeText(record.evidenceSummary, 800),
    validateFreeText(record.recommendationSummary, 800)
  ];

  const firstFail = checks.find(c => !c.isValid);
  if (firstFail) return { isValid: false, errorCode: 'invalid_report_item', message: firstFail.message };

  return { isValid: true };
}

export function evaluateFindingPromotion({
  indicator,
  evidenceRecords
}: {
  indicator: IndicatorRecord;
  evidenceRecords: EvidenceRecord[];
}): FindingPromotionDecision {
  const indVal = validateIndicatorRecord(indicator);
  if (!indVal.isValid) return { status: 'invalid_input', errorCode: 'invalid_indicator', reason: indVal.message };

  if (!evidenceRecords || evidenceRecords.length === 0) {
    return { status: 'needs_more_evidence', errorCode: 'insufficient_evidence', reason: 'No evidence provided' };
  }

  let hasModerateOrStrong = false;
  for (const ev of evidenceRecords) {
    const evVal = validateEvidenceRecord(ev);
    if (!evVal.isValid) return { status: 'invalid_input', errorCode: 'invalid_evidence', reason: evVal.message };
    
    if (ev.scanId !== indicator.scanId) return { status: 'rejected', errorCode: 'cross_scan_evidence_rejected', reason: 'Evidence from different scan' };
    if (ev.indicatorId !== indicator.indicatorId) return { status: 'rejected', errorCode: 'promotion_not_eligible', reason: 'Evidence indicatorId mismatch' };
  }

  if (indicator.indicatorType === 'oob_validation_candidate' || indicator.indicatorType === 'potential_ssrf' || indicator.indicatorType === 'potential_xxe') {
    const matchingEv = evidenceRecords.find(e => e.evidenceType === 'oob_callback' && (e.strength === 'moderate' || e.strength === 'strong'));
    if (!matchingEv) return { status: 'needs_more_evidence', errorCode: 'insufficient_evidence', reason: 'OOB indicator requires moderate/strong OOB callback evidence' };
    hasModerateOrStrong = true;
  } else if (indicator.indicatorType === 'idor_candidate' || indicator.indicatorType === 'bola_candidate' || indicator.indicatorType === 'auth_weakness_candidate') {
    const matchingEv = evidenceRecords.find(e => (e.evidenceType === 'authorization_difference' || (e.evidenceType === 'http_difference' && e.difference?.authStateChanged === true)) && (e.strength === 'moderate' || e.strength === 'strong'));
    if (!matchingEv) return { status: 'needs_more_evidence', errorCode: 'insufficient_evidence', reason: 'Auth indicator requires moderate/strong auth difference evidence' };
    hasModerateOrStrong = true;
  } else if (indicator.indicatorType === 'potential_sqli') {
    const matchingEv = evidenceRecords.find(e => e.evidenceType === 'time_based_difference' && (e.strength === 'moderate' || e.strength === 'strong'));
    if (!matchingEv) return { status: 'needs_more_evidence', errorCode: 'insufficient_evidence', reason: 'SQLi indicator requires moderate/strong time_based_difference evidence' };
    hasModerateOrStrong = true;
  } else {
    // Generic fallback
    const matchingEv = evidenceRecords.find(e => (e.strength === 'moderate' || e.strength === 'strong'));
    if (matchingEv) hasModerateOrStrong = true;
  }

  if (!hasModerateOrStrong) {
    return { status: 'needs_more_evidence', errorCode: 'insufficient_evidence', reason: 'Sufficient moderate/strong matching evidence not found' };
  }

  return { status: 'eligible_for_candidate', reason: 'Evidence is sufficient for promotion' };
}

export function buildFindingCandidateFromPromotion({
  indicator,
  evidenceRecords,
  candidateId,
  now
}: {
  indicator: IndicatorRecord;
  evidenceRecords: EvidenceRecord[];
  candidateId: string;
  now: string;
}): BuildFindingCandidateResult {
  const evalDecision = evaluateFindingPromotion({ indicator, evidenceRecords });
  if (evalDecision.status !== 'eligible_for_candidate') {
    return {
      status: 'failed',
      error: { code: evalDecision.errorCode || 'promotion_not_eligible', message: evalDecision.reason },
      classification: getSafeClassification()
    };
  }

  const tsVal = validateIsoTimestamp(now);
  if (!tsVal.isValid) return { status: 'failed', error: { code: 'unsafe_content_rejected', message: 'Invalid timestamp' }, classification: getSafeClassification() };

  const idVal = validateSafeId(candidateId);
  if (!idVal.isValid) return { status: 'failed', error: { code: 'unsafe_content_rejected', message: 'Invalid candidateId' }, classification: getSafeClassification() };

  const candidateTypeMap: Record<string, FindingCandidateType> = {
    'potential_sqli': 'sqli_candidate',
    'potential_xss': 'xss_candidate',
    'potential_ssrf': 'ssrf_candidate',
    'potential_xxe': 'xxe_candidate',
    'idor_candidate': 'idor_candidate',
    'bola_candidate': 'bola_candidate',
    'mass_assignment_candidate': 'mass_assignment_candidate',
    'auth_weakness_candidate': 'auth_weakness_candidate',
    'secret_exposure_candidate': 'secret_exposure_candidate',
    'cors_candidate': 'cors_candidate',
    'misconfiguration_candidate': 'misconfiguration_candidate',
    'version_exposure_candidate': 'version_exposure_candidate',
    'oob_validation_candidate': 'ssrf_candidate'
  };

  const cType = candidateTypeMap[indicator.indicatorType] || 'misconfiguration_candidate';

  const candidate: FindingCandidateRecord = {
    contractVersion: 'fixguard-evidence-boundary/v0',
    kind: 'finding_candidate_record',
    candidateId,
    scanId: indicator.scanId,
    derivedFromIndicatorIds: [indicator.indicatorId],
    evidenceIds: evidenceRecords.map(e => e.evidenceId),
    candidateType: cType,
    status: 'candidate',
    confidence: indicator.confidence,
    severityGate: {
      status: 'not_assessed',
      reason: 'Severity gate enforced. Review required to assign real severity.'
    },
    rationale: 'Promoted from evidence',
    classification: getSafeClassification(),
    isRealFinding: false,
    requiresHumanReview: true,
    notForExternalDelivery: true
  };

  const finalVal = validateFindingCandidateRecord(candidate);
  if (!finalVal.isValid) return { status: 'failed', error: { code: 'unexpected_evidence_boundary_failure', message: finalVal.message }, classification: getSafeClassification() };

  return { status: 'completed', candidate, classification: getSafeClassification() };
}

export function buildSafeReportItemSnapshot({
  candidate,
  evidenceRecords
}: {
  candidate: FindingCandidateRecord;
  evidenceRecords: EvidenceRecord[];
}): BuildSafeReportItemSnapshotResult {
  const cVal = validateFindingCandidateRecord(candidate);
  if (!cVal.isValid) return { status: 'failed', error: { code: 'invalid_finding_candidate', message: cVal.message }, classification: getSafeClassification() };

  const reportItem: SafeReportItemSnapshot = {
    contractVersion: 'fixguard-evidence-boundary/v0',
    kind: 'safe_report_item_snapshot',
    candidateId: candidate.candidateId,
    title: `Candidate: ${candidate.candidateType}`,
    summary: candidate.rationale,
    affectedSubject: { routeId: 'generic_route' },
    evidenceSummary: `Contains ${evidenceRecords.length} evidence records.`,
    recommendationSummary: 'Requires human validation.',
    reportReadiness: {
      externalDeliveryReady: false,
      requiresHumanReview: true,
      notAFinalVulnerabilityReport: true
    },
    explicitNonClaims: {
      noConfirmedVulnerability: true,
      noRealFindingCreated: true,
      noPersistedEvidenceCreated: true,
      noRiskSeverityOrImpactClaim: true,
      noRawSensitiveDataIncluded: true
    },
    classification: getSafeClassification()
  };

  const finalVal = validateSafeReportItemSnapshot(reportItem);
  if (!finalVal.isValid) return { status: 'failed', error: { code: 'unexpected_evidence_boundary_failure', message: finalVal.message }, classification: getSafeClassification() };

  return { status: 'completed', reportItem, classification: getSafeClassification() };
}
