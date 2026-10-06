/**
 * FixGuard V2 — Challenge Classifier Service.
 *
 * Distinguishes between:
 * - Application-level authorization denial (e.g. 403 Forbidden with application JSON)
 * - Rate limiting (HTTP 429)
 * - WAF presence without blocking (HTTP 200 with cf-ray / x-amz-cf-id)
 * - Edge browser challenge (Cloudflare, Vercel Security Checkpoint, Turnstile, bot mitigation)
 * - Static edge block
 *
 * Invariants:
 * 1. 403 != WAF: does not misclassify standard application access control as a WAF challenge.
 * 2. 429 != WAF: rate limiting without challenge tokens is classified as rate_limited.
 * 3. Never produces speculative claims.
 */

import {
  CHALLENGE_CONTINUATION_CONTRACT_VERSION,
  type EdgeChallengeClassification,
  type EdgeChallengeClassificationVerdict,
} from './ChallengeContinuationContracts.js';
import { observeDefensesFromHttpResponse } from '../test-validity/DefenseObservationService.js';
import type { HttpResponseDefenseSignals } from '../test-validity/TestValidityContracts.js';

const BROWSER_CHALLENGE_BODY_REGEX =
  /vercel\s*security\s*checkpoint|cf-browser-verification|just\s+a\s+moment|attention\s+required|enable\s+javascript|challenge-platform|_cf_chl|turnstile|recaptcha|hcaptcha|cloudflare\s+ray\s+id/i;

const INTERACTIVE_CAPTCHA_REGEX =
  /turnstile|recaptcha|hcaptcha|solve\s+the\s+challenge|verify\s+you\s+are\s+human|complete\s+the\s+captcha/i;

const APP_AUTHZ_DENIAL_BODY_REGEX =
  /["']?(?:error|message)["']?\s*:\s*["'](?:unauthorized|forbidden|access\s+denied|permission\s+denied|invalid\s+token|token\s+expired|insufficient\s+privileges)["']/i;

export interface ResponseChallengeSignals {
  readonly statusCode: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly bodyText: string;
  readonly targetHost?: string;
}

export class ChallengeClassifierService {
  public static classify(signals: ResponseChallengeSignals): EdgeChallengeClassification {
    const defenseSignals: HttpResponseDefenseSignals = {
      statusCode: signals.statusCode,
      headerValues: signals.headers,
      bodyExcerpt: signals.bodyText.slice(0, 500),
      ...(signals.targetHost ? { targetHost: signals.targetHost } : {}),
    };

    const defenses = observeDefensesFromHttpResponse(defenseSignals);
    const body = signals.bodyText;
    const status = signals.statusCode;

    // 1. Rate limiting (HTTP 429)
    if (status === 429) {
      const hasBotChallenge = BROWSER_CHALLENGE_BODY_REGEX.test(body);
      if (hasBotChallenge) {
        return {
          contractVersion: CHALLENGE_CONTINUATION_CONTRACT_VERSION,
          verdict: 'browser_challenge',
          isBlocking: true,
          requiresBrowser: true,
          requiresOperatorHitl: INTERACTIVE_CAPTCHA_REGEX.test(body),
          reasonCode: 'rate_limited_with_browser_challenge',
          explanation: 'Target returned HTTP 429 along with an active bot/browser verification challenge',
          defenses,
        };
      }
      return {
        contractVersion: CHALLENGE_CONTINUATION_CONTRACT_VERSION,
        verdict: 'rate_limited',
        isBlocking: true,
        requiresBrowser: false,
        requiresOperatorHitl: false,
        reasonCode: 'rate_limit_exceeded',
        explanation: 'Target returned HTTP 429 rate limit without interactive challenge',
        defenses,
      };
    }

    // 2. HTTP 403 or 503 inspection
    if (status === 403 || status === 503) {
      // Check for browser / bot challenge signatures
      if (BROWSER_CHALLENGE_BODY_REGEX.test(body)) {
        const isInteractive = INTERACTIVE_CAPTCHA_REGEX.test(body);
        return {
          contractVersion: CHALLENGE_CONTINUATION_CONTRACT_VERSION,
          verdict: 'browser_challenge',
          isBlocking: true,
          requiresBrowser: true,
          requiresOperatorHitl: isInteractive,
          reasonCode: isInteractive ? 'interactive_captcha_challenge' : 'js_browser_verification_challenge',
          explanation: isInteractive
            ? 'Edge defense presented an interactive challenge (Turnstile/CAPTCHA) requiring human completion'
            : 'Edge defense presented an automated JavaScript challenge (Cloudflare/Vercel) solvable via browser flow',
          defenses,
        };
      }

      // Check if this is a standard application authorization denial
      if (APP_AUTHZ_DENIAL_BODY_REGEX.test(body) || signals.headers['content-type']?.includes('application/json')) {
        return {
          contractVersion: CHALLENGE_CONTINUATION_CONTRACT_VERSION,
          verdict: 'application_reachable',
          isBlocking: false,
          requiresBrowser: false,
          requiresOperatorHitl: false,
          reasonCode: 'application_authorization_denied',
          explanation: 'Target returned HTTP 403 from the application authorization layer, not an edge WAF challenge',
          defenses,
        };
      }

      // If WAF headers are explicitly present on 403
      const hasWafHeader = defenses.some((d) => d.controlKind === 'waf');
      if (hasWafHeader) {
        return {
          contractVersion: CHALLENGE_CONTINUATION_CONTRACT_VERSION,
          verdict: 'waf_confirmed',
          isBlocking: true,
          requiresBrowser: true,
          requiresOperatorHitl: false,
          reasonCode: 'waf_static_denial',
          explanation: 'Target returned HTTP 403 accompanied by explicit edge WAF headers',
          defenses,
        };
      }

      return {
        contractVersion: CHALLENGE_CONTINUATION_CONTRACT_VERSION,
        verdict: 'waf_suspected',
        isBlocking: true,
        requiresBrowser: false,
        requiresOperatorHitl: false,
        reasonCode: 'http_403_static_forbidden',
        explanation: 'Target returned HTTP 403 without decisive challenge markers',
        defenses,
      };
    }

    // 3. Normal / Reachable responses (200..399)
    const hasWaf = defenses.some((d) => d.controlKind === 'waf');
    const verdict: EdgeChallengeClassificationVerdict = hasWaf
      ? 'waf_confirmed'
      : 'no_waf_observed';

    return {
      contractVersion: CHALLENGE_CONTINUATION_CONTRACT_VERSION,
      verdict,
      isBlocking: false,
      requiresBrowser: false,
      requiresOperatorHitl: false,
      reasonCode: hasWaf ? 'waf_detected_passive' : 'standard_response',
      explanation: hasWaf
        ? 'Application is reachable; edge WAF headers observed in passive inspection'
        : 'Application is reachable; no intermediate edge challenge observed',
      defenses,
    };
  }
}
