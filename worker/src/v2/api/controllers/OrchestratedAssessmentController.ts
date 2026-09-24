/**
 * FixGuard V2 — Orchestrated Assessment Controller
 *
 * Presentation controller handling HTTP requests for orchestrated assessments:
 * - POST /api/v2/orchestrated/assessments/start
 * - GET /api/v2/orchestrated/assessments/:assessmentId/summary
 * - GET /api/v2/orchestrated/assessments/:assessmentId/status
 * - GET /api/v2/assessments/:assessmentId/attack-surface (Milestone A2)
 * - GET /api/v2/assessments/:assessmentId/attack-plans (Milestone A3)
 * - POST /api/v2/assessments/:assessmentId/attack-plans/:planId/authorize (Milestone A4)
 * - POST /api/v2/assessments/:assessmentId/attack-plans/:planId/execute (Milestone A5)
 * - GET /api/v2/assessments/:assessmentId/attack-chains (Milestone A6)
 * - GET /api/v2/assessments/:assessmentId/post-exploitation (Milestone A10)
 * - GET /api/v2/assessments/:assessmentId/lateral-movement (Milestone A11)
 * - GET /api/v2/assessments/:assessmentId/impact (Milestone A12/A13)
 * - POST /api/v2/assessments/:assessmentId/lateral-movement/promote-to-authorized-target (A13)
 * - POST /api/v2/assessments/:assessmentId/lateral-movement/evaluate-credential-reuse (A13)
 *
 * Responsibilities:
 * 1) Extract and validate path parameters and request body.
 * 2) Delegate to OrchestratedAssessmentApplicationService / AttackAuthorizationService /
 *    AttackExecutionService.
 * 3) Return appropriate HTTP status codes (202 Accepted, 200 OK, 201 Created).
 */

import type { Request, Response, NextFunction } from 'express';
import type { OrchestratedAssessmentApplicationService } from '../../application/OrchestratedAssessmentApplicationService.js';
import type { AttackAuthorizationService } from '../../attack-authorization/AttackAuthorizationService.js';
import type { AttackExecutionService } from '../../attack-execution/AttackExecutionService.js';
import { ATTACK_AUTHORIZATION_CONTRACT_VERSION } from '../../attack-authorization/AttackAuthorizationContracts.js';
import { ATTACK_EXECUTION_CONTRACT_VERSION } from '../../attack-execution/AttackExecutionContracts.js';
import {
  parseStartOrchestratedAssessmentBody,
  parseReviewEvidenceDraftBody,
  parseGenerateHtmlReportHttpBody,
} from '../validation/ApiRequestValidators.js';
import { isStrictSafeId } from '../../reporting-boundary/DefensiveReportContracts.js';
import { ApiValidationError, UnauthorizedGatewayError } from '../ApiErrors.js';
import { SessionNotFoundError } from '../../storage/StorageErrors.js';
import { TargetExecutionCoordinator } from '../../runtime/TargetExecutionCoordinator.js';
import type { Finding } from '../../core/Evidence.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AttackCapabilityIdentityRef } from '../../attack-execution/AttackExecutionContracts.js';
import { isLateralMovementMechanism } from '../../attack-planning/LateralMovementContracts.js';

function isAuthorizedScopeGrant(value: object): value is AuthorizedScopeGrant {
  return (
    Reflect.get(value, 'contractVersion') === 'fixguard-authorized-scope-policy/v0' &&
    Reflect.get(value, 'kind') === 'authorized_scope_grant' &&
    typeof Reflect.get(value, 'grantId') === 'string' &&
    typeof Reflect.get(value, 'scanId') === 'string' &&
    typeof Reflect.get(value, 'boundaries') === 'object' &&
    Reflect.get(value, 'boundaries') !== null
  );
}

function isFindingArray(value: unknown): value is Finding[] {
  if (!Array.isArray(value)) return false;
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return false;
    if (typeof Reflect.get(item, 'id') !== 'string') return false;
    if (typeof Reflect.get(item, 'verificationState') !== 'string') return false;
  }
  return true;
}

function parseOptionalIdentity(
  value: unknown,
  fieldName: string
): AttackCapabilityIdentityRef | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ApiValidationError(`Field ${fieldName} must be an object when provided`);
  }
  const record = value as Record<string, unknown>;
  for (const k of Object.keys(record)) {
    if (k !== 'identityId' && k !== 'headers') {
      throw new ApiValidationError(`Field ${fieldName} contains unknown or forbidden field`);
    }
  }
  if (typeof record.identityId !== 'string' || record.identityId.trim().length === 0) {
    throw new ApiValidationError(`Field ${fieldName}.identityId must be a non-empty string`);
  }
  let headers: Readonly<Record<string, string>> | undefined;
  if (record.headers !== undefined) {
    if (!record.headers || typeof record.headers !== 'object' || Array.isArray(record.headers)) {
      throw new ApiValidationError(`Field ${fieldName}.headers must be an object when provided`);
    }
    const rawHeaders = record.headers as Record<string, unknown>;
    const normalized: Record<string, string> = {};
    for (const [hk, hv] of Object.entries(rawHeaders)) {
      if (typeof hv !== 'string') {
        throw new ApiValidationError(`Field ${fieldName}.headers values must be strings`);
      }
      normalized[hk] = hv;
    }
    headers = Object.freeze(normalized);
  }
  return {
    identityId: record.identityId,
    ...(headers ? { headers } : {}),
  };
}

export class OrchestratedAssessmentController {
  constructor(
    private readonly service: OrchestratedAssessmentApplicationService,
    private readonly attackAuthorizationService?: AttackAuthorizationService,
    private readonly attackExecutionService?: AttackExecutionService
  ) {}

  public startAssessment = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const command = parseStartOrchestratedAssessmentBody(req.body);
      const result = await this.service.startAssessment(command);
      res.status(202).json(result);
    } catch (err) {
      next(err);
    }
  };

  public getStatus = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const status = await this.service.getStatus(assessmentId);
      res.status(200).json(status);
    } catch (err) {
      next(err);
    }
  };

  public getSummary = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const summary = await this.service.getSummary(assessmentId);
      res.status(200).json(summary);
    } catch (err) {
      next(err);
    }
  };

  public getAttackSurface = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const result = await this.service.getAttackSurface(assessmentId);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };

  public getAttackPlans = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const result = await this.service.getAttackPlans(assessmentId);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };

  /**
   * Operator A/B attack recommendations (deterministic; never auto-execute).
   * Query: findingId?, planId?, investigationId?
   */
  public getAttackRecommendations = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const findingIdRaw = req.query.findingId;
      const planIdRaw = req.query.planId;
      const investigationIdRaw = req.query.investigationId;

      const findingId =
        findingIdRaw === undefined
          ? undefined
          : typeof findingIdRaw === 'string' && isStrictSafeId(findingIdRaw)
            ? findingIdRaw
            : null;
      if (findingId === null) {
        throw new ApiValidationError('Query findingId must satisfy strict identifier format');
      }
      const planId =
        planIdRaw === undefined
          ? undefined
          : typeof planIdRaw === 'string' && isStrictSafeId(planIdRaw)
            ? planIdRaw
            : null;
      if (planId === null) {
        throw new ApiValidationError('Query planId must satisfy strict identifier format');
      }
      const investigationId =
        investigationIdRaw === undefined
          ? undefined
          : typeof investigationIdRaw === 'string' && isStrictSafeId(investigationIdRaw)
            ? investigationIdRaw
            : null;
      if (investigationId === null) {
        throw new ApiValidationError('Query investigationId must satisfy strict identifier format');
      }

      const result = await this.service.getAttackRecommendations({
        assessmentId,
        ...(findingId ? { findingId } : {}),
        ...(planId ? { planId } : {}),
        ...(investigationId ? { investigationId } : {}),
      });
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };

  public getAttackChains = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const result = await this.service.getAttackChains(assessmentId);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };

  public getPostExploitation = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const result = await this.service.getPostExploitation(assessmentId);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };

  public getLateralMovement = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const result = await this.service.getLateralMovement(assessmentId);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };

  public getImpactAssessments = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const result = await this.service.getImpactAssessments(assessmentId);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };

  /**
   * Milestone A13 — promote host to AuthorizedLateralTarget.
   * Exact-key body: hostname, operatorId, scopeGrant [, authorizedAt]. No secrets.
   */
  public promoteLateralTarget = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }
      if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        throw new ApiValidationError('Promote request body must be a non-empty object');
      }
      const body = req.body as Record<string, unknown>;
      const allowedKeys = ['hostname', 'operatorId', 'scopeGrant', 'authorizedAt'];
      for (const k of Object.keys(body)) {
        if (!allowedKeys.includes(k)) {
          throw new ApiValidationError('Promote request contains unknown or forbidden field');
        }
      }
      for (const required of ['hostname', 'operatorId', 'scopeGrant'] as const) {
        if (!(required in body)) {
          throw new ApiValidationError(`Field ${required} is required`);
        }
      }
      if (typeof body.hostname !== 'string' || body.hostname.trim().length === 0) {
        throw new ApiValidationError('Field hostname must be a non-empty string');
      }
      if (typeof body.operatorId !== 'string' || !isStrictSafeId(body.operatorId)) {
        throw new ApiValidationError('Field operatorId must satisfy strict identifier format');
      }
      if (!body.scopeGrant || typeof body.scopeGrant !== 'object' || Array.isArray(body.scopeGrant)) {
        throw new ApiValidationError('Field scopeGrant is required');
      }
      if (!isAuthorizedScopeGrant(body.scopeGrant)) {
        throw new ApiValidationError('Field scopeGrant shape is invalid');
      }
      if (body.authorizedAt !== undefined && typeof body.authorizedAt !== 'string') {
        throw new ApiValidationError('Field authorizedAt must be a string when provided');
      }

      const result = await this.service.promoteLateralTarget({
        assessmentId,
        hostname: body.hostname,
        operatorId: body.operatorId,
        scopeGrant: body.scopeGrant,
        ...(typeof body.authorizedAt === 'string' ? { authorizedAt: body.authorizedAt } : {}),
      });
      res.status(201).json(result);
    } catch (err) {
      next(err);
    }
  };

  /**
   * Milestone A13 — evaluate credential reuse by credentialRefId (vault server-side).
   * Exact-key body; never accepts raw secrets.
   */
  public evaluateCredentialReuse = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      if (!this.attackAuthorizationService) {
        throw new ApiValidationError('Attack authorization service is not configured');
      }

      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }
      if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        throw new ApiValidationError('Credential-reuse request body must be a non-empty object');
      }
      const body = req.body as Record<string, unknown>;
      const allowedKeys = [
        'planId',
        'sourceHost',
        'destinationHost',
        'mechanism',
        'credentialRefId',
        'operatorId',
        'scopeGrant',
        'targetUrl',
        'recordedAt',
      ];
      for (const k of Object.keys(body)) {
        if (!allowedKeys.includes(k)) {
          throw new ApiValidationError(
            'Credential-reuse request contains unknown or forbidden field'
          );
        }
      }
      for (const required of [
        'planId',
        'sourceHost',
        'destinationHost',
        'mechanism',
        'credentialRefId',
        'operatorId',
        'scopeGrant',
      ] as const) {
        if (!(required in body)) {
          throw new ApiValidationError(`Field ${required} is required`);
        }
      }
      if (typeof body.planId !== 'string' || !isStrictSafeId(body.planId)) {
        throw new ApiValidationError('Field planId must satisfy strict identifier format');
      }
      if (typeof body.operatorId !== 'string' || !isStrictSafeId(body.operatorId)) {
        throw new ApiValidationError('Field operatorId must satisfy strict identifier format');
      }
      if (typeof body.credentialRefId !== 'string' || !isStrictSafeId(body.credentialRefId)) {
        throw new ApiValidationError('Field credentialRefId must satisfy strict identifier format');
      }
      if (typeof body.sourceHost !== 'string' || body.sourceHost.trim().length === 0) {
        throw new ApiValidationError('Field sourceHost must be a non-empty string');
      }
      if (typeof body.destinationHost !== 'string' || body.destinationHost.trim().length === 0) {
        throw new ApiValidationError('Field destinationHost must be a non-empty string');
      }
      if (!isLateralMovementMechanism(body.mechanism)) {
        throw new ApiValidationError('Field mechanism must be a closed LateralMovementMechanism');
      }
      if (!body.scopeGrant || typeof body.scopeGrant !== 'object' || Array.isArray(body.scopeGrant)) {
        throw new ApiValidationError('Field scopeGrant is required');
      }
      if (!isAuthorizedScopeGrant(body.scopeGrant)) {
        throw new ApiValidationError('Field scopeGrant shape is invalid');
      }
      if ('secret' in body || 'password' in body || 'token' in body) {
        throw new ApiValidationError('Raw secrets are forbidden in credential-reuse requests');
      }

      const token = this.attackAuthorizationService.getRuntimeToken(body.planId, assessmentId);
      if (!token) {
        throw new UnauthorizedGatewayError(
          'No runtime-branded attack authorization token for this plan',
          'token_missing'
        );
      }

      const result = await this.service.evaluateCredentialReuseHttp(
        {
          assessmentId,
          planId: body.planId,
          sourceHost: body.sourceHost,
          destinationHost: body.destinationHost,
          mechanism: body.mechanism,
          credentialRefId: body.credentialRefId,
          operatorId: body.operatorId,
          scopeGrant: body.scopeGrant,
          ...(typeof body.targetUrl === 'string' ? { targetUrl: body.targetUrl } : {}),
          ...(typeof body.recordedAt === 'string' ? { recordedAt: body.recordedAt } : {}),
        },
        token
      );
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };

  public getEvidenceDrafts = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const drafts = await this.service.getEvidenceDrafts(assessmentId);
      res.status(200).json(drafts);
    } catch (err) {
      next(err);
    }
  };

  public reviewEvidenceDraft = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      const draftId = req.params.draftId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }
      if (!draftId || typeof draftId !== 'string' || !isStrictSafeId(draftId)) {
        throw new ApiValidationError('Field draftId must satisfy strict identifier format');
      }

      const body = parseReviewEvidenceDraftBody(req.body);
      const result = await this.service.reviewEvidenceDraft({
        assessmentId,
        draftId,
        decision: body.decision,
        reviewerId: body.reviewerId,
        reviewedAt: body.reviewedAt,
        ...(body.notes ? { notes: body.notes } : {}),
      });

      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };

  public generateHtmlReport = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }

      const body = parseGenerateHtmlReportHttpBody(req.body);
      const html = await this.service.generateHtmlReport(
        assessmentId,
        body.operatorId,
        body.attestationText
      );

      res.setHeader('Content-Type', 'text/html; charset=utf-8').status(200).send(html);
    } catch (err) {
      next(err);
    }
  };

  /**
   * Milestone A4 — mint a runtime-branded AttackAuthorizationToken for a plan.
   * Does not execute attacks. Self-authorization flags are rejected by the service.
   * Plan must exist in AttackPlanRepository for the assessment.
   */
  public authorizeAttackPlan = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      if (!this.attackAuthorizationService) {
        throw new ApiValidationError('Attack authorization service is not configured');
      }

      const assessmentId = req.params.assessmentId;
      const planId = req.params.planId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }
      if (!planId || typeof planId !== 'string' || !isStrictSafeId(planId)) {
        throw new ApiValidationError('Field planId must satisfy strict identifier format');
      }

      if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        throw new ApiValidationError('Authorization request body must be a non-empty object');
      }

      const body = req.body as Record<string, unknown>;
      const operatorId = body.operatorId;
      const blastRadiusClass = body.blastRadiusClass;
      if (typeof operatorId !== 'string' || !isStrictSafeId(operatorId)) {
        throw new ApiValidationError('Field operatorId must satisfy strict identifier format');
      }
      if (typeof blastRadiusClass !== 'string') {
        throw new ApiValidationError('Field blastRadiusClass must be a closed-world string');
      }

      const result = await this.attackAuthorizationService.establishAttackAuthorization({
        contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
        kind: 'establish_attack_authorization_request',
        planId,
        assessmentId,
        blastRadiusClass,
        operatorId,
        ...(typeof body.authorizedAt === 'string' ? { authorizedAt: body.authorizedAt } : {}),
      });

      if (result.status === 'failed') {
        if (result.reasonCode === 'blast_radius_class_prohibited') {
          throw new UnauthorizedGatewayError(result.safeMessage, result.reasonCode);
        }
        if (result.reasonCode === 'plan_not_found') {
          throw new ApiValidationError(result.safeMessage);
        }
        throw new ApiValidationError(result.safeMessage);
      }

      res.status(201).json({
        status: 'established',
        reasonCode: result.reasonCode,
        token: {
          planId: result.token.planId,
          assessmentId: result.token.assessmentId,
          blastRadiusClass: result.token.blastRadiusClass,
          authorizationLevel: result.token.authorizationLevel,
          authorizedBy: result.token.authorizedBy,
          authorizedAt: result.token.authorizedAt,
        },
      });
    } catch (err) {
      next(err);
    }
  };

  /**
   * Milestone A5 — execute an authorized attack plan under 7 safety gates.
   * Requires a prior in-process authorize that sealed a WeakSet-branded token.
   * Exact-key body: operatorId, scopeGrant, findings (optional), dnsAnswers (optional hermetic),
   * primaryIdentity / secondaryIdentity (optional differential identities).
   *
   * When dnsAnswers is omitted, the assessment-configured DNS resolver resolves the target host
   * dynamically (fail closed with dns_resolution_failed). Never defaults to example.com.
   *
   * scopeGrant from the client is re-bound against the sealed assessment grant (scope_violation
   * on host expansion / permission escalation).
   *
   * verifiedAuthorizationDecision is NEVER accepted from the HTTP body (not forgeable).
   * Resolved server-side via OrchestratedAssessmentApplicationService
   * getRuntimeVerifiedAuthorizationDecision (A4 getRuntimeToken pattern).
   */
  public executeAttackPlan = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      if (!this.attackAuthorizationService || !this.attackExecutionService) {
        throw new ApiValidationError('Attack execution services are not configured');
      }

      const assessmentId = req.params.assessmentId;
      const planId = req.params.planId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }
      if (!planId || typeof planId !== 'string' || !isStrictSafeId(planId)) {
        throw new ApiValidationError('Field planId must satisfy strict identifier format');
      }

      if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        throw new ApiValidationError('Execution request body must be a non-empty object');
      }

      const body = req.body as Record<string, unknown>;
      const allowedKeys = [
        'operatorId',
        'scopeGrant',
        'findings',
        'dnsAnswers',
        'primaryIdentity',
        'secondaryIdentity',
        'investigationId',
      ];
      for (const k of Object.keys(body)) {
        if (!allowedKeys.includes(k)) {
          throw new ApiValidationError('Execution request contains unknown or forbidden field');
        }
      }

      const operatorId = body.operatorId;
      if (typeof operatorId !== 'string' || !isStrictSafeId(operatorId)) {
        throw new ApiValidationError('Field operatorId must satisfy strict identifier format');
      }
      if (!body.scopeGrant || typeof body.scopeGrant !== 'object' || Array.isArray(body.scopeGrant)) {
        throw new ApiValidationError('Field scopeGrant is required');
      }
      if (!isAuthorizedScopeGrant(body.scopeGrant)) {
        throw new ApiValidationError('Field scopeGrant shape is invalid');
      }

      const investigationIdRaw = body.investigationId;
      const investigationId =
        investigationIdRaw === undefined
          ? null
          : typeof investigationIdRaw === 'string' && isStrictSafeId(investigationIdRaw)
            ? investigationIdRaw
            : null;
      if (investigationIdRaw !== undefined && investigationId === null) {
        throw new ApiValidationError('Field investigationId must satisfy strict identifier format');
      }

      const findings =
        body.findings === undefined
          ? []
          : isFindingArray(body.findings)
            ? body.findings
            : null;
      if (findings === null) {
        throw new ApiValidationError('Field findings must be an array of Finding objects');
      }

      const clientPrimary = parseOptionalIdentity(body.primaryIdentity, 'primaryIdentity');
      const clientSecondary = parseOptionalIdentity(body.secondaryIdentity, 'secondaryIdentity');
      const ephemeralByot = this.service.getEphemeralByotExecuteIdentities(assessmentId);
      const primaryIdentity =
        clientPrimary ??
        (ephemeralByot
          ? {
              identityId: ephemeralByot.primaryIdentity.identityId,
              ...(ephemeralByot.primaryIdentity.headers
                ? { headers: { ...ephemeralByot.primaryIdentity.headers } }
                : {}),
            }
          : null);
      const secondaryIdentity =
        clientSecondary ??
        (ephemeralByot?.secondaryIdentity
          ? {
              identityId: ephemeralByot.secondaryIdentity.identityId,
              ...(ephemeralByot.secondaryIdentity.headers
                ? { headers: { ...ephemeralByot.secondaryIdentity.headers } }
                : {}),
            }
          : null);

      const token = this.attackAuthorizationService.getRuntimeToken(planId, assessmentId);
      if (!token) {
        throw new UnauthorizedGatewayError(
          'No runtime-branded attack authorization token for this plan',
          'token_missing'
        );
      }

      // Server-side branded decision — never from client JSON.
      const verifiedAuthorizationDecision =
        this.service.getRuntimeVerifiedAuthorizationDecision(assessmentId);
      const transport = this.service.getRuntimeHttpTransport();

      // Re-bind client scopeGrant against sealed assessment grant (fail closed on escalation).
      const scopeGrant = await this.service.rebindScopeGrantForAssessment(
        assessmentId,
        body.scopeGrant
      );

      // Hermetic dnsAnswers override when provided; otherwise resolve via assessment DNS.
      // Never fall back to a hardcoded example.com IP.
      const hermeticDnsAnswers =
        Array.isArray(body.dnsAnswers) && body.dnsAnswers.every((ip) => typeof ip === 'string')
          ? body.dnsAnswers
          : null;
      const assessmentDnsResolver = this.service.getRuntimeDnsResolver();
      const dnsResolver =
        hermeticDnsAnswers !== null
          ? async () => hermeticDnsAnswers
          : assessmentDnsResolver;

      let coordinator = new TargetExecutionCoordinator();
      if (investigationId) {
        const scopeSubject = body.scopeGrant as {
          readonly subject?: {
            readonly host?: string;
            readonly domain?: string;
            readonly normalizedOrigin?: string;
          };
          readonly boundaries?: { readonly allowedHosts?: readonly string[] };
        };
        const targetHostFromScope =
          (typeof scopeSubject.subject?.host === 'string' && scopeSubject.subject.host.trim()) ||
          (typeof scopeSubject.subject?.domain === 'string' && scopeSubject.subject.domain.trim()) ||
          (Array.isArray(scopeSubject.boundaries?.allowedHosts) &&
          typeof scopeSubject.boundaries.allowedHosts[0] === 'string'
            ? scopeSubject.boundaries.allowedHosts[0].trim()
            : '') ||
          (() => {
            const origin = scopeSubject.subject?.normalizedOrigin;
            if (typeof origin !== 'string' || !origin.trim()) return '';
            try {
              return new URL(origin).hostname;
            } catch {
              return '';
            }
          })();

        const { gate, coordinator: investigationCoordinator } =
          this.service.gateAttackExecutionUnderInvestigation({
            assessmentId,
            investigationId,
            planId,
            attackAuthorizationToken: token,
            expectedRequestCost: 1,
            ...(targetHostFromScope ? { targetHost: targetHostFromScope } : {}),
          });
        if (gate.status !== 'authorized' || !investigationCoordinator) {
          throw new UnauthorizedGatewayError(
            gate.status === 'denied' ? gate.safeMessage : 'Investigation gate denied',
            gate.status === 'denied' ? gate.reasonCode : 'investigation_gate_denied'
          );
        }
        coordinator = investigationCoordinator;
      }

      const result = await this.attackExecutionService.execute({
        contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
        kind: 'attack_execution_request',
        planId,
        assessmentId,
        token,
        scopeGrant,
        coordinator,
        dnsResolver,
        findings,
        operatorId,
        ...(primaryIdentity ? { primaryIdentity } : {}),
        ...(secondaryIdentity ? { secondaryIdentity } : {}),
        ...(verifiedAuthorizationDecision
          ? { verifiedAuthorizationDecision }
          : {}),
        transport,
      });

      if (investigationId) {
        const executionId =
          result.record && typeof result.record.executionId === 'string'
            ? result.record.executionId
            : planId;
        this.service.recordInvestigationExecutionStep({
          investigationId,
          stepId: `exec_${executionId}`.replace(/[^A-Za-z0-9_\-.:]/g, '_').slice(0, 128),
          requestCost:
            result.status === 'completed'
              ? Math.max(1, result.record.stepRecords.length)
              : 0,
        });
      }

      if (result.status === 'preflight_denied') {
        throw new UnauthorizedGatewayError(result.safeMessage, result.reasonCode);
      }
      if (result.status === 'failed') {
        throw new ApiValidationError(result.safeMessage);
      }

      let refresh:
        | {
            readonly attackChains: unknown;
            readonly postExploitationState: unknown;
            readonly lateralMovementSnapshot: unknown;
            readonly impactAssessments: unknown;
          }
        | undefined;
      try {
        const payload = await this.service.recordAttackExecutionOutcome({
          assessmentId,
          planId,
          executionRecord: result.record,
        });
        refresh = {
          attackChains: payload.attackChains,
          postExploitationState: payload.postExploitationState,
          lateralMovementSnapshot: payload.lateralMovementSnapshot,
          impactAssessments: payload.impactAssessments,
        };
      } catch (err: unknown) {
        // Hermetic execute paths may lack an orchestrated assessment record;
        // fall back to refresh-only when assessment exists without chain write.
        if (!(err instanceof SessionNotFoundError)) {
          throw err;
        }
        try {
          const payload = await this.service.getAttackModeRefresh(assessmentId);
          refresh = {
            attackChains: payload.attackChains,
            postExploitationState: payload.postExploitationState,
            lateralMovementSnapshot: payload.lateralMovementSnapshot,
            impactAssessments: payload.impactAssessments,
          };
        } catch (refreshErr: unknown) {
          if (!(refreshErr instanceof SessionNotFoundError)) {
            throw refreshErr;
          }
        }
      }

      res.status(200).json({
        status: result.status,
        reasonCode: result.reasonCode,
        record: {
          executionId: result.record.executionId,
          planId: result.record.planId,
          assessmentId: result.record.assessmentId,
          capability: result.record.capability,
          status: result.record.status,
          stepRecords: result.record.stepRecords.map((s) => ({
            stepId: s.stepId,
            outcome: s.outcome,
            reasonCode: s.reasonCode,
            safeMessage: s.safeMessage,
            gatesPassed: s.gatesPassed,
            verificationStateBefore: s.verificationStateBefore,
            verificationStateAfter: s.verificationStateAfter,
            ...(s.evidenceId ? { evidenceId: s.evidenceId } : {}),
            ...(s.commandSummary ? { commandSummary: s.commandSummary } : {}),
            ...(s.consoleLines ? { consoleLines: s.consoleLines } : {}),
          })),
          updatedFindingStates: result.record.updatedFindings.map((f) => ({
            id: f.id,
            verificationState: f.verificationState,
          })),
        },
        ...(refresh ? { refresh } : {}),
      });
    } catch (err) {
      next(err);
    }
  };

  /**
   * Etapa 2 · F1 — start ActiveInvestigationRuntime (state + budget + auth bundle).
   * Does not execute AttackPlans.
   */
  public startActiveInvestigation = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }
      if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        throw new ApiValidationError('Start investigation body must be a non-empty object');
      }
      const body = req.body as Record<string, unknown>;
      const allowedKeys = ['investigationId', 'budget', 'openHypothesisRefs', 'startedAt'];
      for (const k of Object.keys(body)) {
        if (!allowedKeys.includes(k)) {
          throw new ApiValidationError('Start investigation body contains unknown or forbidden field');
        }
      }
      const investigationId = body.investigationId;
      if (typeof investigationId !== 'string' || !isStrictSafeId(investigationId)) {
        throw new ApiValidationError('Field investigationId must satisfy strict identifier format');
      }

      let budget:
        | {
            readonly maxRequests: number;
            readonly maxDurationMs: number;
            readonly maxConcurrentSteps?: number;
            readonly requestsPerSecondCeiling?: number;
            readonly maxConcurrencyCeiling?: number;
          }
        | undefined;
      if (body.budget !== undefined) {
        if (!body.budget || typeof body.budget !== 'object' || Array.isArray(body.budget)) {
          throw new ApiValidationError('Field budget must be an object');
        }
        const rawBudget = body.budget as Record<string, unknown>;
        const maxRequests = rawBudget.maxRequests;
        const maxDurationMs = rawBudget.maxDurationMs;
        if (typeof maxRequests !== 'number' || !Number.isInteger(maxRequests) || maxRequests < 1) {
          throw new ApiValidationError('Field budget.maxRequests must be a positive integer');
        }
        if (
          typeof maxDurationMs !== 'number' ||
          !Number.isInteger(maxDurationMs) ||
          maxDurationMs < 1
        ) {
          throw new ApiValidationError('Field budget.maxDurationMs must be a positive integer');
        }
        budget = {
          maxRequests,
          maxDurationMs,
          ...(typeof rawBudget.maxConcurrentSteps === 'number'
            ? { maxConcurrentSteps: rawBudget.maxConcurrentSteps }
            : {}),
          ...(typeof rawBudget.requestsPerSecondCeiling === 'number'
            ? { requestsPerSecondCeiling: rawBudget.requestsPerSecondCeiling }
            : {}),
          ...(typeof rawBudget.maxConcurrencyCeiling === 'number'
            ? { maxConcurrencyCeiling: rawBudget.maxConcurrencyCeiling }
            : {}),
        };
      }

      const openHypothesisRefs = body.openHypothesisRefs;
      if (openHypothesisRefs !== undefined) {
        if (
          !Array.isArray(openHypothesisRefs) ||
          !openHypothesisRefs.every((r) => typeof r === 'string' && isStrictSafeId(r))
        ) {
          throw new ApiValidationError(
            'Field openHypothesisRefs must be an array of strict identifiers'
          );
        }
      }

      const result = await this.service.startActiveInvestigation({
        assessmentId,
        investigationId,
        ...(budget ? { budget } : {}),
        ...(openHypothesisRefs ? { openHypothesisRefs } : {}),
        ...(typeof body.startedAt === 'string' ? { startedAt: body.startedAt } : {}),
      });

      if (result.status === 'denied') {
        throw new UnauthorizedGatewayError(result.safeMessage, result.reasonCode);
      }

      res.status(201).json({
        status: result.status,
        reasonCode: result.reasonCode,
        snapshot: result.snapshot,
        authorizationBundle: {
          investigationId: result.authorizationBundle.investigationId,
          assessmentId: result.authorizationBundle.assessmentId,
          sealedAt: result.authorizationBundle.sealedAt,
          hasVerifiedAuthorizationDecision:
            result.authorizationBundle.hasVerifiedAuthorizationDecision,
          hasAttackAuthorizationToken: result.authorizationBundle.hasAttackAuthorizationToken,
        },
      });
    } catch (err) {
      next(err);
    }
  };

  /**
   * Etapa 2 · F1 — cancel or engage kill-switch on an active investigation.
   */
  public cancelActiveInvestigation = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      const investigationId = req.params.investigationId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }
      if (
        !investigationId ||
        typeof investigationId !== 'string' ||
        !isStrictSafeId(investigationId)
      ) {
        throw new ApiValidationError('Field investigationId must satisfy strict identifier format');
      }
      if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        throw new ApiValidationError('Cancel investigation body must be a non-empty object');
      }
      const body = req.body as Record<string, unknown>;
      const allowedKeys = ['operatorId', 'mode', 'cancelledAt'];
      for (const k of Object.keys(body)) {
        if (!allowedKeys.includes(k)) {
          throw new ApiValidationError('Cancel investigation body contains unknown or forbidden field');
        }
      }
      const operatorId = body.operatorId;
      const mode = body.mode;
      if (typeof operatorId !== 'string' || !isStrictSafeId(operatorId)) {
        throw new ApiValidationError('Field operatorId must satisfy strict identifier format');
      }
      if (mode !== 'cancel' && mode !== 'kill_switch') {
        throw new ApiValidationError('Field mode must be cancel or kill_switch');
      }

      const result = this.service.cancelActiveInvestigation({
        assessmentId,
        investigationId,
        operatorId,
        mode,
        ...(typeof body.cancelledAt === 'string' ? { cancelledAt: body.cancelledAt } : {}),
      });

      if (result.status === 'denied') {
        throw new UnauthorizedGatewayError(result.safeMessage, result.reasonCode);
      }

      res.status(200).json({
        status: result.status,
        reasonCode: result.reasonCode,
        snapshot: result.snapshot,
      });
    } catch (err) {
      next(err);
    }
  };

  public getActiveInvestigation = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const assessmentId = req.params.assessmentId;
      const investigationId = req.params.investigationId;
      if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
        throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
      }
      if (
        !investigationId ||
        typeof investigationId !== 'string' ||
        !isStrictSafeId(investigationId)
      ) {
        throw new ApiValidationError('Field investigationId must satisfy strict identifier format');
      }

      const snapshot = this.service.getActiveInvestigationSnapshot(assessmentId, investigationId);
      if (!snapshot) {
        throw new SessionNotFoundError(
          `Active investigation '${investigationId}' was not found`,
          investigationId
        );
      }
      res.status(200).json({ snapshot });
    } catch (err) {
      next(err);
    }
  };
}

