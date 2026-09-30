/**
 * Applies FindingAutoPromotionPolicy to pending evidence drafts after detection.
 * Produces Findings for confirmed attack-relevant signals only.
 * Does not execute attacks; AttackPlan execute remains human-authorized.
 */

import type { Finding } from '../core/Evidence.js';
import type {
  DifferentialEvidenceContext,
  EnrichedEvidenceDraft,
} from '../application/OrchestratedAssessmentContracts.js';
import {
  evaluateFindingAutoPromotion,
  type FindingAutoPromotionEvaluation,
} from './FindingAutoPromotionPolicy.js';

export const FINDING_AUTO_PROMOTION_ACTOR_ID = 'system_auto_confirmed_signal' as const;

export interface ApplyFindingAutoPromotionInput {
  readonly drafts: readonly EnrichedEvidenceDraft[];
  readonly assessmentId: string;
  readonly scanId: string;
  readonly targetDomain: string;
  readonly actorId: string;
  readonly evaluatedAt: string;
}

export interface ApplyFindingAutoPromotionResult {
  readonly findings: readonly Finding[];
  readonly remainingDrafts: readonly EnrichedEvidenceDraft[];
  readonly droppedDraftIds: readonly string[];
  readonly evaluations: readonly Readonly<{
    draftId: string;
    evaluation: FindingAutoPromotionEvaluation;
  }>[];
}

function draftIdSuffix(draftId: string): string {
  return draftId.replace(/^dft_/, '').replace(/^draft_/, '').slice(0, 40);
}

function endpointOrDomain(
  ctx: DifferentialEvidenceContext | undefined,
  targetDomain: string
): string {
  return ctx?.endpointUrl ?? `https://${targetDomain}/`;
}

function buildAutoFinding(
  draft: EnrichedEvidenceDraft,
  input: ApplyFindingAutoPromotionInput
): Finding | null {
  const ctx = draft.differentialContext;
  if (!ctx) return null;

  const detKind = ctx.detectionKind;
  const draftId = draft.draftId;
  const suffix = draftIdSuffix(draftId);
  const target = endpointOrDomain(ctx, input.targetDomain);
  const evaluatedAt = input.evaluatedAt;

  const baseEvidence = JSON.stringify({
    draftId,
    promotionSource: 'auto_confirmed_signal',
    evaluatedAt,
    actorId: FINDING_AUTO_PROMOTION_ACTOR_ID,
    differentialContext: ctx,
    safeRationale: draft.safeRationale,
  });

  const lineage = {
    assessmentId: input.assessmentId,
    scanId: input.scanId,
    actorId: input.actorId,
    promotionSource: 'auto_confirmed_signal',
    evaluatedAt,
  };

  switch (detKind) {
    case 'idor_access_control':
      return {
        id: `fnd_idor_${suffix}`,
        type: 'BROKEN_ACCESS_CONTROL',
        severity: 'high',
        title: `Observed Broken Access Control on ${target}`,
        description: `Observed authorization differential on resource parameter '${ctx.resourceParamName ?? 'id'}' (auto-promoted from confirmed IDOR/BOLA signal).`,
        target,
        evidence: baseEvidence,
        confidence: 0.9,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'broken_access_control_metadata',
          category: 'BROKEN_ACCESS_CONTROL',
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
          endpointUrl: ctx.endpointUrl,
          resourceParamName: ctx.resourceParamName,
          baselineResourceId: ctx.baselineResourceId,
        },
      };

    case 'auth_bypass': {
      const mechanism = ctx.bypassMechanism ?? 'header_stripping';
      const similarity = ctx.bodySimilarityRatio ?? 1.0;
      return {
        id: `fnd_ab_${suffix}`,
        type: 'BROKEN_AUTHENTICATION',
        severity: 'high',
        title: `Observed Authentication Bypass on ${target}`,
        description: `Observed anonymous access via ${mechanism} with ${Math.round(similarity * 100)}% body match (auto-promoted from confirmed auth-bypass signal).`,
        target,
        evidence: baseEvidence,
        confidence: 0.9,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'auth_bypass_metadata',
          category: 'BROKEN_AUTHENTICATION',
          endpointUrl: target,
          httpMethod: ctx.httpMethod ?? 'GET',
          authenticatedStatusCode: ctx.baselineStatusCode ?? 200,
          anonymousStatusCode: ctx.validationStatusCode ?? 200,
          bypassMechanism: mechanism,
          bodySimilarityRatio: similarity,
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };
    }

    case 'supabase_rls_abuse': {
      const tableName = ctx.supabaseTableName ?? 'unknown_table';
      const anonEquals = ctx.supabaseAnonEqualsAuth === true;
      return {
        id: `fnd_sbrls_${suffix}`,
        type: 'BROKEN_ACCESS_CONTROL',
        severity: 'high',
        title: `Supabase RLS world-readable table '${tableName}'`,
        description: `OBSERVED anon Data API GET returned HTTP ${ctx.baselineStatusCode ?? 200} JSON on '${tableName}'${
          anonEquals
            ? ' with authenticated response matching anon (no RLS read boundary).'
            : ' (anon role can SELECT).'
        }`,
        target,
        evidence: baseEvidence,
        confidence: anonEquals ? 0.95 : 0.88,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'supabase_rls_abuse_metadata',
          category: 'BROKEN_ACCESS_CONTROL',
          claimKind: 'SUPABASE_RLS_WORLD_READABLE',
          tableName,
          tableUrl: target,
          anonStatusCode: ctx.baselineStatusCode ?? 200,
          authenticatedStatusCode: ctx.validationStatusCode,
          anonBodyHash: ctx.baselineBodyHash ?? '',
          authenticatedBodyHash: ctx.validationBodyHash,
          topLevelJsonKeys: ctx.supabaseTopLevelJsonKeys ?? [],
          rowCountHint: ctx.supabaseRowCountHint,
          anonEqualsAuth: anonEquals,
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };
    }

    case 'cors_misconfiguration':
    case 'credentialed_cors': {
      const reflected = ctx.reflectedOrigin ?? ctx.suppliedOrigin ?? ctx.acaoHeader ?? '';
      // credentialed_cors_metadata is reserved for the dedicated detector (later execute).
      // Phase-1 generic CORS drafts stay security_misconfiguration even when credentials are allowed.
      if (detKind === 'credentialed_cors') {
        return {
          id: `fnd_cors_${suffix}`,
          type: 'SECURITY_MISCONFIGURATION',
          severity: 'high',
          title: `Observed Credentialed CORS Misconfiguration on ${target}`,
          description: `Observed credentialed CORS reflection for origin '${reflected || 'untrusted'}' (auto-promoted).`,
          target,
          evidence: baseEvidence,
          confidence: 0.9,
          verificationState: 'suspected_vulnerability',
          metadata: {
            kind: 'credentialed_cors_metadata',
            category: 'SECURITY_MISCONFIGURATION',
            endpointUrl: target,
            httpMethod: ctx.httpMethod ?? 'GET',
            suppliedOrigin: ctx.suppliedOrigin ?? reflected,
            reflectedOrigin: reflected,
            allowCredentialsHeader: ctx.allowCredentialsHeader ?? ctx.allowCredentials ?? true,
            acaoHeader: ctx.acaoHeader ?? reflected,
            observedAt: evaluatedAt,
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage,
          },
        };
      }
      return {
        id: `fnd_cors_${suffix}`,
        type: 'SECURITY_MISCONFIGURATION',
        severity: 'medium',
        title: `Observed CORS Misconfiguration on ${target}`,
        description: `Observed origin '${reflected || 'untrusted'}' reflected (auto-promoted from confirmed CORS signal).`,
        target,
        evidence: baseEvidence,
        confidence: 0.88,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'security_misconfiguration_metadata',
          category: 'CORS_MISCONFIGURATION',
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
          endpointUrl: ctx.endpointUrl,
          reflectedOrigin: reflected || undefined,
          allowCredentials: ctx.allowCredentials === true,
        },
      };
    }

    case 'parameter_reflection':
      return {
        id: `fnd_refl_${suffix}`,
        type: 'INPUT_VALIDATION_FLAW',
        severity: 'medium',
        title: `Observed Parameter Reflection on ${target}`,
        description: `Observed reflection of parameter '${ctx.parameterName ?? 'q'}' canary (auto-promoted; XSS not claimed without further verification).`,
        target,
        evidence: baseEvidence,
        confidence: 0.85,
        verificationState: 'observed_anomaly',
        metadata: {
          kind: 'input_validation_flaw_metadata',
          category: 'PARAMETER_REFLECTION',
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
          endpointUrl: ctx.endpointUrl,
          parameterName: ctx.parameterName,
          reflectedCanary: ctx.reflectedCanary,
        },
      };

    case 'open_redirect':
      return {
        id: `fnd_redir_${suffix}`,
        type: 'INPUT_VALIDATION_FLAW',
        severity: 'medium',
        title: `Observed Open Redirect on ${target}`,
        description: `Observed redirect to '${ctx.finalDestination}' via parameter '${ctx.parameterName ?? 'url'}' (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.9,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'open_redirect_metadata',
          parameterName: ctx.parameterName ?? 'url',
          injectedCanary: ctx.injectedCanary ?? '',
          finalDestination: ctx.finalDestination ?? '',
          redirectChain: ctx.redirectChain ?? [],
          observedAt: evaluatedAt,
          category: 'INPUT_VALIDATION_FLAW',
          endpointUrl: ctx.endpointUrl,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'jwt_algorithm_confusion':
      return {
        id: `fnd_jwt_${suffix}`,
        type: 'BROKEN_AUTHENTICATION',
        severity: 'high',
        title: `Observed JWT Algorithm Confusion on ${target}`,
        description: `Observed JWT alg confusion probe (${ctx.jwtProbeMechanism ?? 'alg_none_header'}) accepted (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.9,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'jwt_algorithm_confusion_metadata',
          category: 'BROKEN_AUTHENTICATION',
          endpointUrl: target,
          httpMethod: ctx.httpMethod ?? 'GET',
          originalAlgorithm: ctx.originalAlgorithm ?? 'HS256',
          manipulatedAlgorithm: ctx.manipulatedAlgorithm ?? 'none',
          probeMechanism: ctx.jwtProbeMechanism ?? 'alg_none_header',
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'sql_error_oracle':
      return {
        id: `fnd_sqlo_${suffix}`,
        type: 'INFORMATION_DISCLOSURE',
        severity: 'medium',
        title: `Observed SQL Error Oracle on ${target}`,
        description: `Observed SQL error oracle (${ctx.databaseEngine ?? 'unknown'}) on parameter '${ctx.parameterName ?? 'id'}' (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.88,
        verificationState: 'observed_anomaly',
        metadata: {
          kind: 'sql_error_oracle_metadata',
          category: 'INFORMATION_DISCLOSURE',
          endpointUrl: target,
          parameterName: ctx.parameterName ?? 'id',
          databaseEngine: ctx.databaseEngine ?? 'unknown',
          errorFragment: ctx.sqlErrorFragment ?? '',
          injectedProbe: ctx.injectedProbe ?? '',
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'subdomain_takeover':
      return {
        id: `fnd_takeover_${suffix}`,
        type: 'DNS_HIJACKING_RISK',
        severity: 'high',
        title: `Observed Subdomain Takeover Signal on ${ctx.subdomain ?? target}`,
        description: `Observed dangling CNAME to ${ctx.cnameTarget ?? 'unknown'} (${ctx.hostingProvider ?? 'unknown'}) (auto-promoted).`,
        target: ctx.subdomain ? `https://${ctx.subdomain}/` : target,
        evidence: baseEvidence,
        confidence: 0.9,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'subdomain_takeover_metadata',
          subdomain: ctx.subdomain ?? input.targetDomain,
          cnameTarget: ctx.cnameTarget ?? '',
          hostingProvider: ctx.hostingProvider ?? 'unknown',
          fingerprintMatch: ctx.fingerprintMatch ?? '',
          observedAt: evaluatedAt,
          category: 'DNS_HIJACKING_RISK',
          endpointUrl: ctx.endpointUrl,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'static_secret_exposure':
      return {
        id: `fnd_secret_${suffix}`,
        type: 'INFORMATION_DISCLOSURE',
        severity: 'high',
        title: `Observed Static Secret Exposure in ${ctx.filePath ?? target}`,
        description: `Observed ${ctx.secretKind ?? 'secret'} exposure in source artifact (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.92,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'static_secret_exposure_metadata',
          category: 'INFORMATION_DISCLOSURE',
          filePath: ctx.filePath ?? '',
          lineNumber: ctx.lineNumber ?? 0,
          secretKind: ctx.secretKind ?? 'generic_api_key',
          exposureSeverity: ctx.exposureSeverity === 'critical' ? 'critical' : 'high',
          sanitizedSnippet: ctx.sanitizedSnippet ?? '',
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'blind_ssrf':
      return {
        id: `fnd_bssrf_${suffix}`,
        type: 'SERVER_SIDE_REQUEST_FORGERY',
        severity: 'high',
        title: `Observed Blind SSRF Callback on ${target}`,
        description: `Confirmed OOB canary interaction for parameter '${ctx.parameterName ?? 'url'}' (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.95,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'blind_ssrf_detection_metadata',
          category: 'SERVER_SIDE_REQUEST_FORGERY',
          endpointUrl: target,
          parameterName: ctx.parameterName ?? 'url',
          injectedCanaryUrl: ctx.injectedCanaryUrl ?? '',
          canaryToken: ctx.canaryToken ?? '',
          interactionConfirmed: true,
          remoteAddress: ctx.remoteAddress,
          exposureSeverity: 'critical',
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'blind_xss':
      return {
        id: `fnd_bxss_${suffix}`,
        type: 'CROSS_SITE_SCRIPTING',
        severity: 'high',
        title: `Observed Blind XSS Callback on ${target}`,
        description: `Confirmed OOB XSS canary interaction for parameter '${ctx.parameterName ?? 'comment'}' (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.95,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'blind_xss_detection_metadata',
          category: 'CROSS_SITE_SCRIPTING',
          endpointUrl: target,
          parameterName: ctx.parameterName ?? 'comment',
          injectedPayloadSnippet: ctx.injectedPayloadSnippet ?? '',
          canaryToken: ctx.canaryToken ?? '',
          interactionConfirmed: true,
          remoteAddress: ctx.remoteAddress,
          exposureSeverity: 'high',
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'oob_canary_interaction':
      return {
        id: `fnd_oob_${suffix}`,
        type: 'SERVER_SIDE_REQUEST_FORGERY',
        severity: 'high',
        title: `Observed OOB Canary Interaction on ${target}`,
        description: `Confirmed OOB canary callback (${ctx.interactionType ?? 'http_callback'}) (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.95,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'oob_canary_metadata',
          category: 'SERVER_SIDE_REQUEST_FORGERY',
          canaryToken: ctx.canaryToken ?? '',
          callbackDomain: ctx.callbackDomain ?? '',
          interactionType: ctx.interactionType ?? 'http_callback',
          remoteAddress: ctx.remoteAddress,
          interactionTimestamp: ctx.interactionTimestamp ?? evaluatedAt,
          exposureSeverity: 'high',
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'session_fixation':
      return {
        id: `fnd_sf_${suffix}`,
        type: 'BROKEN_AUTHENTICATION',
        severity: 'high',
        title: `Observed Session Fixation on ${target}`,
        description: `Observed session fixation on cookie '${ctx.sessionCookieName ?? 'session'}' (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.9,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'session_fixation_metadata',
          category: 'BROKEN_AUTHENTICATION',
          endpointUrl: target,
          httpMethod: ctx.httpMethod ?? 'GET',
          sessionCookieName: ctx.sessionCookieName ?? 'session',
          fixedSessionId: (ctx.fixedSessionId ?? '').slice(0, 32),
          serverRegeneratedSession: ctx.serverRegeneratedSession ?? false,
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'parameter_integrity':
      return {
        id: `fnd_pint_${suffix}`,
        type: 'INPUT_VALIDATION_FLAW',
        severity: 'medium',
        title: `Observed Parameter Integrity Anomaly on ${target}`,
        description: `Observed parameter integrity / path boundary anomaly on '${ctx.parameterName ?? 'file'}' (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.85,
        verificationState: 'observed_anomaly',
        metadata: {
          kind: 'parameter_integrity_metadata',
          category: 'INFORMATION_DISCLOSURE',
          endpointUrl: target,
          parameterName: ctx.parameterName ?? 'file',
          injectedProbePattern: ctx.injectedProbePattern ?? '',
          boundaryEnforced: ctx.boundaryEnforced ?? false,
          sanitizedExcerpt: ctx.sanitizedExcerpt ?? '',
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'cms_plugin_vulnerability':
      return {
        id: `fnd_cms_${suffix}`,
        type: 'SECURITY_MISCONFIGURATION',
        severity: 'medium',
        title: `Observed Outdated CMS Plugin ${ctx.pluginSlug ?? ''} on ${target}`,
        description: `Observed outdated ${ctx.cmsType ?? 'cms'} plugin '${ctx.pluginSlug ?? 'unknown'}' version ${ctx.detectedVersion ?? '?'} (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.85,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'cms_plugin_vulnerability_metadata',
          category: 'SECURITY_MISCONFIGURATION',
          cmsType: ctx.cmsType ?? 'wordpress',
          pluginSlug: ctx.pluginSlug ?? '',
          detectedVersion: ctx.detectedVersion ?? '',
          minimumSafeVersion: ctx.minimumSafeVersion ?? '',
          isOutdated: true,
          evidenceSourceUrl: ctx.evidenceSourceUrl ?? target,
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'http_method_manipulation':
      return {
        id: `fnd_hmm_${suffix}`,
        type: 'SECURITY_MISCONFIGURATION',
        severity: 'medium',
        title: `Observed HTTP Method Manipulation on ${target}`,
        description: `Observed method manipulation bypass (${ctx.bypassType ?? 'method_override_header'}) (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.85,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'http_method_manipulation_metadata',
          category: 'SECURITY_MISCONFIGURATION',
          endpointUrl: target,
          targetOperation: ctx.targetOperation ?? 'write',
          baselineMethod: ctx.baselineMethod ?? 'POST',
          bypassMethodOrHeader: ctx.bypassMethodOrHeader ?? '',
          baselineStatusCode: ctx.baselineStatusCode ?? 401,
          manipulatedStatusCode: ctx.manipulatedStatusCode ?? ctx.validationStatusCode ?? 200,
          bypassType: ctx.bypassType ?? 'method_override_header',
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'information_disclosure':
      return {
        id: `fnd_infodisc_${suffix}`,
        type: 'INFORMATION_DISCLOSURE',
        severity: 'medium',
        title: `Observed Information Disclosure (${ctx.disclosureKind ?? 'leak'}) on ${target}`,
        description: `Observed ${ctx.disclosureKind ?? 'disclosure'} via ${ctx.trigger ?? 'response'} (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.88,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'information_disclosure_metadata',
          disclosureKind: ctx.disclosureKind ?? 'internal_path',
          disclosedFragment: ctx.disclosedFragment ?? '',
          trigger: ctx.trigger ?? '',
          observedAt: evaluatedAt,
          category: 'SECURITY_MISCONFIGURATION',
          endpointUrl: ctx.endpointUrl,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'weak_tls_configuration':
      return {
        id: `fnd_tls_${suffix}`,
        type: 'SECURITY_MISCONFIGURATION',
        severity: 'medium',
        title: `Observed Weak TLS Configuration on ${ctx.targetHost ?? input.targetDomain}`,
        description: `Observed weak TLS protocols/ciphers/certificate issues (auto-promoted).`,
        target: `https://${ctx.targetHost ?? input.targetDomain}/`,
        evidence: baseEvidence,
        confidence: 0.9,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'weak_tls_metadata',
          targetHost: ctx.targetHost ?? input.targetDomain,
          port: ctx.port ?? 443,
          weakProtocols: ctx.weakProtocols ?? [],
          weakCiphers: ctx.weakCiphers ?? [],
          certificateIssues: ctx.certificateIssues ?? [],
          supportedTlsVersions: ctx.supportedTlsVersions ?? [],
          observedAt: evaluatedAt,
          category: 'SECURITY_MISCONFIGURATION',
          endpointUrl: ctx.endpointUrl,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'dependency_vulnerability':
      return {
        id: `fnd_depvuln_${suffix}`,
        type: 'SECURITY_MISCONFIGURATION',
        severity: 'medium',
        title: `Observed Dependency Vulnerability ${ctx.packageName ?? ''} (${ctx.advisoryId ?? ''})`,
        description: `Observed vulnerable dependency ${ctx.packageName ?? 'package'} ${ctx.installedVersion ?? ''} in range ${ctx.vulnerableRange ?? ''} (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.9,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'dependency_vulnerability_metadata',
          category: 'SUPPLY_CHAIN_RISK',
          ecosystem: ctx.ecosystem ?? 'npm',
          packageName: ctx.packageName ?? '',
          installedVersion: ctx.installedVersion ?? '',
          vulnerableRange: ctx.vulnerableRange ?? '',
          advisoryId: ctx.advisoryId ?? '',
          exposureSeverity:
            ctx.exposureSeverity === 'critical'
              ? 'critical'
              : ctx.exposureSeverity === 'high'
                ? 'high'
                : 'medium',
          sourceManifestPath: ctx.sourceManifestPath ?? '',
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'dependency_confusion':
      return {
        id: `fnd_depconf_${suffix}`,
        type: 'SECURITY_MISCONFIGURATION',
        severity: 'high',
        title: `Observed Dependency Confusion Risk for ${ctx.packageName ?? 'package'}`,
        description: `Observed unclaimed public registry package '${ctx.packageName ?? ''}' referenced privately (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.9,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'dependency_confusion_metadata',
          category: 'SUPPLY_CHAIN_RISK',
          packageName: ctx.packageName ?? '',
          sourceManifestUrl: ctx.sourceManifestUrl ?? '',
          publicRegistryUrl: ctx.publicRegistryUrl ?? '',
          registryStatusCode: ctx.registryStatusCode ?? 404,
          isUnclaimedPublicly: true,
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'cors_idor_compound':
      return {
        id: `fnd_chain_${suffix}`,
        type: 'BROKEN_ACCESS_CONTROL',
        severity: 'high',
        title: ctx.chainTitle ?? `Observed CORS+IDOR Compound Chain on ${target}`,
        description: `Observed CORS+IDOR compound chain from correlated findings (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.9,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'compound_chain_metadata',
          category: 'BROKEN_ACCESS_CONTROL',
          chainKind: 'cors_idor_compound',
          primaryFindingId: ctx.primaryFindingId ?? '',
          secondaryFindingId: ctx.secondaryFindingId ?? '',
          sharedOrigin: ctx.sharedOrigin ?? '',
          targetEndpointUrl: ctx.targetEndpointUrl ?? target,
          compoundImpactScore: ctx.compoundImpactScore ?? 0.9,
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    case 'cross_finding_chain':
      return {
        id: `fnd_xchain_${suffix}`,
        type: 'BROKEN_ACCESS_CONTROL',
        severity: 'high',
        title: ctx.chainTitle ?? `Observed Cross-Finding Attack Chain on ${target}`,
        description: `Observed cross-finding compound chain from correlated findings (auto-promoted).`,
        target,
        evidence: baseEvidence,
        confidence: 0.9,
        verificationState: 'suspected_vulnerability',
        metadata: {
          kind: 'cross_finding_chain_metadata',
          category: 'BROKEN_ACCESS_CONTROL',
          chainTitle: ctx.chainTitle ?? 'Cross-finding compound chain',
          constituentFindingIds: ctx.constituentFindingIds ?? [],
          primaryVector: ctx.primaryVector ?? '',
          secondaryVector: ctx.secondaryVector ?? '',
          compoundImpactScore: ctx.compoundImpactScore ?? 0.9,
          observedAt: evaluatedAt,
          candidateId: `cnd_${draftId}`,
          evidenceRecordId: `evd_${draftId}`,
          lineage,
        },
      };

    default:
      return null;
  }
}

/**
 * Partition pending drafts: auto-promote confirmed attack-relevant signals to Findings;
 * drop discovery noise; keep soft/cosmetic drafts for optional HITL.
 */
export function applyFindingAutoPromotion(
  input: ApplyFindingAutoPromotionInput
): ApplyFindingAutoPromotionResult {
  const findings: Finding[] = [];
  const remainingDrafts: EnrichedEvidenceDraft[] = [];
  const droppedDraftIds: string[] = [];
  const evaluations: ApplyFindingAutoPromotionResult['evaluations'][number][] = [];

  for (const draft of input.drafts) {
    const evaluation = evaluateFindingAutoPromotion(draft);
    evaluations.push({ draftId: draft.draftId, evaluation });

    if (evaluation.decision === 'drop_as_noise') {
      droppedDraftIds.push(draft.draftId);
      continue;
    }

    if (evaluation.decision === 'keep_as_draft') {
      remainingDrafts.push(draft);
      continue;
    }

    const finding = buildAutoFinding(draft, input);
    if (!finding) {
      remainingDrafts.push(draft);
      continue;
    }
    findings.push(finding);
  }

  return {
    findings,
    remainingDrafts,
    droppedDraftIds,
    evaluations,
  };
}
