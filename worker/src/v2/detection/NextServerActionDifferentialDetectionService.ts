/**
 * Plan A Fase 5 thin — Next.js Server Action differential detection.
 *
 * POSTs with `Next-Action` header (OBSERVED action id) as unauth vs optional BYOT.
 * Does not invent action IDs. Does not claim Critical severity. No Supabase REST.
 */

import { createHash } from 'node:crypto';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import { defaultHttpProbeTransport } from './IdorDifferentialDetectionService.js';
import { probeAuthContextHasCredentials } from './DetectionTargetBridge.js';
import {
  NEXT_SERVER_ACTION_DIFF_CONTRACT_VERSION,
  type NextServerActionDiffRequest,
  type NextServerActionDiffResult,
} from './NextServerActionDifferentialContracts.js';

function sha256(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

function redactActionId(actionId: string): string {
  const t = actionId.trim();
  if (t.length <= 12) return '…';
  return `${t.slice(0, 8)}…${t.slice(-4)}`;
}

function actionAccepted(statusCode: number, bodyText: string): boolean {
  if (statusCode >= 200 && statusCode < 300) return true;
  // Next sometimes returns 303/redirect on success; treat 3xx as accepted signal.
  if (statusCode >= 300 && statusCode < 400) return true;
  // Explicit denial shapes
  if (statusCode === 401 || statusCode === 403) return false;
  if (/unauthorized|forbidden|not authenticated/i.test(bodyText)) return false;
  return false;
}

export async function runNextServerActionDifferential(
  request: NextServerActionDiffRequest
): Promise<NextServerActionDiffResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const deny = (
    status: NextServerActionDiffResult['status'],
    reasonCode: string,
    safeMessage: string
  ): NextServerActionDiffResult => ({
    contractVersion: NEXT_SERVER_ACTION_DIFF_CONTRACT_VERSION,
    kind: 'next_server_action_diff_result',
    detectionId: request.detectionId,
    status,
    reasonCode,
    lineage,
    endpointUrl: request.endpointUrl,
    actionIdRedacted: redactActionId(request.actionId),
    error: { code: reasonCode, safeMessage },
  });

  const actionId = request.actionId.trim();
  if (actionId.length < 8) {
    return deny(
      'prerequisite_missing',
      'action_id_not_observed',
      'OBSERVED Next-Action id required (min length 8)'
    );
  }

  const endpointUrl = request.endpointUrl.trim();
  if (!endpointUrl) {
    return deny(
      'prerequisite_missing',
      'endpoint_url_missing',
      'Server Action endpoint URL required'
    );
  }

  const allowedMethods = request.scopeGrant.boundaries.allowedMethods ?? [];
  if (!allowedMethods.includes('POST')) {
    return deny(
      'prerequisite_missing',
      'post_method_not_in_scope',
      'Scope grant boundaries do not include POST'
    );
  }

  const preflight = await runAdapterPreflight({
    target: endpointUrl,
    targetKind: 'url',
    verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
    authorizedScopeGrant: request.scopeGrant,
    lineage: {
      assessmentId: request.assessmentId,
      scanId: request.scanId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
    },
    permissionCheck: (ps) =>
      Boolean(
        ps.endpointDiscovery ||
          ps.lightValidation ||
          ps.activeValidation ||
          ps.authenticatedTesting
      ),
    dnsResolver: request.dnsResolver,
  });

  if (!preflight.ok) {
    return deny(
      'preflight_denied',
      preflight.reasonCode,
      `Preflight denied: ${preflight.reasonCode}`
    );
  }

  const transport = request.transport ?? defaultHttpProbeTransport;
  const bodyText = request.bodyText ?? '[]';
  const baseHeaders: Record<string, string> = {
    'content-type': 'text/plain;charset=UTF-8',
    accept: 'text/x-component',
    'next-action': actionId,
    'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
  };

  try {
    const unauthRes = await transport({
      url: endpointUrl,
      method: 'POST',
      headers: baseHeaders,
      body: bodyText,
      timeoutMs: request.timeoutMs ?? 8_000,
    });

    let authStatus: number | undefined;
    let authHash: string | undefined;
    if (
      request.authenticatedContext &&
      probeAuthContextHasCredentials(request.authenticatedContext)
    ) {
      const authHeaders: Record<string, string> = { ...baseHeaders };
      if (request.authenticatedContext.headers) {
        for (const [k, v] of Object.entries(request.authenticatedContext.headers)) {
          authHeaders[k.toLowerCase()] = v;
        }
      }
      const authRes = await transport({
        url: endpointUrl,
        method: 'POST',
        headers: authHeaders,
        body: bodyText,
        timeoutMs: request.timeoutMs ?? 8_000,
      });
      authStatus = authRes.statusCode;
      authHash = sha256(authRes.bodyText);
    }

    const unauthAccepted = actionAccepted(unauthRes.statusCode, unauthRes.bodyText);

    // Differential: unauth accepts action (authz bypass signal) OR unauth≠auth status.
    const authzDifferential =
      unauthAccepted === true ||
      (typeof authStatus === 'number' && unauthRes.statusCode !== authStatus);

    return {
      contractVersion: NEXT_SERVER_ACTION_DIFF_CONTRACT_VERSION,
      kind: 'next_server_action_diff_result',
      detectionId: request.detectionId,
      status: authzDifferential
        ? 'differential_observed'
        : 'secure_target_abstained',
      reasonCode: authzDifferential
        ? unauthAccepted
          ? 'unauth_server_action_accepted'
          : 'server_action_status_differential'
        : 'no_server_action_authz_differential',
      lineage,
      endpointUrl,
      actionIdRedacted: redactActionId(actionId),
      observation: {
        unauthStatusCode: unauthRes.statusCode,
        ...(typeof authStatus === 'number' ? { authStatusCode: authStatus } : {}),
        unauthBodyHash: sha256(unauthRes.bodyText),
        ...(authHash ? { authBodyHash: authHash } : {}),
        actionAcceptedUnauth: unauthAccepted,
        authzDifferential,
      },
    };
  } catch (err) {
    return deny(
      'unexpected_failure',
      'transport_error',
      err instanceof Error ? err.message.slice(0, 160) : 'transport_error'
    );
  }
}
