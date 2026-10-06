/**
 * FixGuard V2 — Challenge Browser Continuation Service.
 *
 * Coordinates browser-mediated challenge progression and HITL operator completion
 * using existing Playwright infrastructure.
 *
 * Execution flow:
 * HTTP (challenge observed)
 *   ↓
 * Detect & Classify (ChallengeClassifierService)
 *   ↓
 * Isolated Browser Context (Playwright + Stealth)
 *   ↓
 * Automated JS challenge progression wait
 *   ↓
 * If interactive challenge required:
 *   Pause at HITL boundary (waiting_for_operator)
 *   ↓
 * Operator completes challenge
 *   ↓
 * Capture resulting cookies into SessionSanctuary
 *   ↓
 * Validate post-challenge application reachability
 *   ↓
 * Resume authorized assessment
 */

import type {
  ChallengeContinuationResult,
  OperatorChallengeCallbackInput,
} from './ChallengeContinuationContracts.js';
import {
  ChallengeClassifierService,
  type ResponseChallengeSignals,
} from './ChallengeClassifierService.js';
import type { SessionSanctuaryService } from '../session/SessionSanctuaryService.js';
import type { PlaywrightBrowserLauncher } from '../recon/adapters/BrowserAutomationContracts.js';
import { DefaultPlaywrightBrowserLauncher } from '../recon/adapters/PlaywrightSpaAdapter.js';
import {
  selectBrowserProfile,
  buildStealthContextOptions,
  applyPlaywrightStealth,
} from '../recon/adapters/PlaywrightStealth.js';
import type { IdorHttpProbeTransport } from '../detection/DetectionContracts.js';

export interface ChallengeContinuationOptions {
  readonly challengeUrl: string;
  readonly signals: ResponseChallengeSignals;
  readonly sessionSanctuary: SessionSanctuaryService;
  readonly browserLauncher?: PlaywrightBrowserLauncher;
  readonly transport?: IdorHttpProbeTransport;
  readonly timeoutMs?: number;
}

export class ChallengeBrowserContinuationService {
  /**
   * Evaluates response signals and attempts browser-mediated progression if an edge challenge is present.
   */
  public static async evaluateAndProgress(
    options: ChallengeContinuationOptions
  ): Promise<ChallengeContinuationResult> {
    const classification = ChallengeClassifierService.classify(options.signals);

    // If no challenge requiring browser, return early
    if (!classification.requiresBrowser && !classification.isBlocking) {
      return {
        state: 'validated',
        challengeUrl: options.challengeUrl,
        reasonCode: classification.reasonCode,
        applicationReachable: true,
        capturedCookieNames: Object.freeze([]),
        validatedAt: new Date().toISOString(),
      };
    }

    if (!classification.requiresBrowser && classification.isBlocking) {
      return {
        state: 'failed',
        challengeUrl: options.challengeUrl,
        reasonCode: classification.reasonCode,
        applicationReachable: false,
        capturedCookieNames: Object.freeze([]),
        operatorMessage: classification.explanation,
      };
    }

    // Requires browser-mediated flow
    const launcher = options.browserLauncher ?? new DefaultPlaywrightBrowserLauncher();
    let browser: Awaited<ReturnType<PlaywrightBrowserLauncher['launch']>> | null = null;

    try {
      browser = await launcher.launch({ headless: true });
      const profile = selectBrowserProfile();
      const stealthOpts = buildStealthContextOptions(profile);
      const context = await browser.newContext(stealthOpts);
      await applyPlaywrightStealth(context, profile);

      const page = await context.newPage();
      await page.goto(options.challengeUrl, {
        waitUntil: 'domcontentloaded',
        timeout: options.timeoutMs ?? 15_000,
      });

      // Allow JS challenge to execute and settle
      await page.waitForTimeout(2000);

      const title = (await page.title()) || '';

      // Check if challenge is still actively blocking
      const stillChallenged =
        /just\s*a\s*moment|attention\s*required|security\s*checkpoint|cf-browser-verification|challenge-platform/i.test(
          title
        );

      if (stillChallenged) {
        if (classification.requiresOperatorHitl) {
          return {
            state: 'waiting_for_operator',
            challengeUrl: options.challengeUrl,
            reasonCode: 'interactive_challenge_pending',
            applicationReachable: false,
            capturedCookieNames: Object.freeze([]),
            operatorMessage:
              'Target requires interactive verification (Turnstile/CAPTCHA). Operator assistance required to proceed.',
          };
        }

        return {
          state: 'failed',
          challengeUrl: options.challengeUrl,
          reasonCode: 'browser_challenge_unresolved',
          applicationReachable: false,
          capturedCookieNames: Object.freeze([]),
          operatorMessage: 'Automated browser progression could not resolve challenge within timeout',
        };
      }

      // Application route reached!
      const validatedAt = new Date().toISOString();
      options.sessionSanctuary.updateChallengeState('anonymous', 'resolved');
      if (options.sessionSanctuary.hasAuthenticatedContext()) {
        options.sessionSanctuary.updateChallengeState('authenticated', 'resolved');
      }

      return {
        state: 'validated',
        challengeUrl: options.challengeUrl,
        reasonCode: 'browser_progression_succeeded',
        applicationReachable: true,
        capturedCookieNames: Object.freeze([]),
        validatedAt,
        operatorMessage: 'Browser progression successfully navigated past edge challenge to application',
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        state: 'failed',
        challengeUrl: options.challengeUrl,
        reasonCode: 'browser_continuation_error',
        applicationReachable: false,
        capturedCookieNames: Object.freeze([]),
        operatorMessage: `Browser continuation failed: ${msg}`,
      };
    } finally {
      if (browser) {
        await browser.close().catch(() => {});
      }
    }
  }

  /**
   * Resumes assessment after operator completes an interactive challenge (HITL).
   */
  public static async resumeAfterOperatorCompletion(
    input: OperatorChallengeCallbackInput,
    challengeUrl: string,
    sessionSanctuary: SessionSanctuaryService,
    transport?: IdorHttpProbeTransport
  ): Promise<ChallengeContinuationResult> {
    const validatedAt = new Date().toISOString();

    if (input.confirmedCookies && Object.keys(input.confirmedCookies).length > 0) {
      sessionSanctuary.updateChallengeState(
        'anonymous',
        'operator_completed',
        input.confirmedCookies
      );
      if (sessionSanctuary.hasAuthenticatedContext()) {
        sessionSanctuary.updateChallengeState(
          'authenticated',
          'operator_completed',
          input.confirmedCookies
        );
      }
    }

    // Validate post-challenge application reachability if transport is provided
    if (transport) {
      const canary = await sessionSanctuary.validateSessionHealth(
        sessionSanctuary.hasAuthenticatedContext() ? 'authenticated' : 'anonymous',
        transport,
        challengeUrl
      );

      if (canary.healthState === 'valid') {
        return {
          state: 'validated',
          challengeUrl,
          reasonCode: 'operator_completion_validated',
          applicationReachable: true,
          capturedCookieNames: Object.freeze(
            input.confirmedCookies ? Object.keys(input.confirmedCookies) : []
          ),
          validatedAt,
          operatorMessage: 'Operator completed challenge and application reachability was validated',
        };
      } else {
        return {
          state: 'failed',
          challengeUrl,
          reasonCode: 'validation_failed_after_operator_completion',
          applicationReachable: false,
          capturedCookieNames: Object.freeze(
            input.confirmedCookies ? Object.keys(input.confirmedCookies) : []
          ),
          operatorMessage: `Operator completed challenge, but application remained unreachable (${canary.reason})`,
        };
      }
    }

    return {
      state: 'operator_completed',
      challengeUrl,
      reasonCode: 'operator_completed_unvalidated',
      applicationReachable: true,
      capturedCookieNames: Object.freeze(
        input.confirmedCookies ? Object.keys(input.confirmedCookies) : []
      ),
      validatedAt,
      operatorMessage: 'Operator completed challenge (validation deferred)',
    };
  }
}
