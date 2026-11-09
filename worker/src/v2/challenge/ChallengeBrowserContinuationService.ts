/**
 * FixGuard V2 — Challenge Browser Continuation Service.
 *
 * Coordinates fully automated browser-mediated challenge progression using
 * existing Playwright infrastructure. A challenge is never treated as a
 * terminal outcome: evaluateAndProgress() is retried by the caller across
 * multiple strategies (fresh_context, persistent_context) within a bounded
 * budget — see CompositeActiveReconOrchestratorService.
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
 * Capture resulting cookies into SessionSanctuary
 *   ↓
 * Validate post-challenge application reachability
 *   ↓
 * Resume reconnaissance automatically — no operator step
 *
 * A genuinely interactive challenge (Turnstile/CAPTCHA) that no automated
 * strategy can complete reports `waiting_for_operator` as an honest,
 * non-terminal diagnostic (never silently claimed resolved) — this service
 * does not attempt to solve it, and nothing in FixGuard requires a human to
 * act on it for the assessment to continue investigating other resources.
 */

import type {
  ChallengeContinuationResult,
  ChallengeContinuationStrategyKind,
  ChallengeProviderHint,
  ChallengeResolutionMethod,
} from './ChallengeContinuationContracts.js';
import {
  ChallengeClassifierService,
  detectChallengeProviderHint,
  matchesAnyChallengeSignature,
  type ResponseChallengeSignals,
} from './ChallengeClassifierService.js';
import type { SessionSanctuaryService } from '../session/SessionSanctuaryService.js';
import type {
  PlaywrightBrowserLauncher,
  BrowserCookieRecord,
  BrowserInstance,
  BrowserContextInstance,
  PageInstance,
} from '../recon/adapters/BrowserAutomationContracts.js';
import { DefaultPlaywrightBrowserLauncher } from '../recon/adapters/PlaywrightSpaAdapter.js';
import {
  selectBrowserProfile,
  buildStealthContextOptions,
  applyPlaywrightStealth,
  STEALTH_CHROMIUM_LAUNCH_ARGS,
} from '../recon/adapters/PlaywrightStealth.js';
import type { IdorHttpProbeTransport } from '../detection/DetectionContracts.js';

/** Default upper bound for bounded, condition-based resolution observation. */
const DEFAULT_RESOLUTION_TIMEOUT_MS = 8_000;
/** Sample interval while polling for resolution within the bound. */
const RESOLUTION_POLL_INTERVAL_MS = 500;

export interface ChallengeContinuationOptions {
  readonly challengeUrl: string;
  readonly signals: ResponseChallengeSignals;
  readonly sessionSanctuary: SessionSanctuaryService;
  readonly browserLauncher?: PlaywrightBrowserLauncher;
  readonly transport?: IdorHttpProbeTransport;
  readonly timeoutMs?: number;
  /**
   * Milestone: Challenge Continuation Reliability — upper bound (ms) for
   * condition-based resolution observation after navigation. Replaces the
   * old fixed 2s sleep with a bounded poll: still deterministic and capped,
   * never indefinite. Defaults to DEFAULT_RESOLUTION_TIMEOUT_MS.
   */
  readonly resolutionTimeoutMs?: number;
  /**
   * Explicit opt-out for stealth evasions (default: false, stealth is
   * enabled) — mirrors BrowserAutomationRequest.disableStealth. Threaded
   * through both launch arguments and context/page initialization; this
   * milestone adds no new fingerprint-spoofing or stealth techniques.
   */
  readonly disableStealth?: boolean;
  /**
   * Milestone: Challenge Continuation Reliability (Recovery, Not Terminal
   * State) — which retry approach this attempt should use. Defaults to
   * 'fresh_context', i.e. today's only behavior (isolated browser+context,
   * closed at the end of this call) — omitting this option changes nothing.
   */
  readonly strategy?: ChallengeContinuationStrategyKind;
  /**
   * Required when strategy === 'persistent_context'. The caller (the
   * orchestrator's per-URL retry loop) owns this handle across multiple
   * evaluateAndProgress() calls for the SAME URL and is responsible for
   * closing browser/context once the retry sequence ends (resolved,
   * waiting_for_operator, or exhausted) — this function never closes a
   * browser it did not itself launch.
   */
  readonly persistentContextHandle?: PersistentChallengeContextHandle;
}

/**
 * Milestone: Challenge Continuation Reliability — mutable handle a caller
 * can pass across multiple evaluateAndProgress() calls to reuse the same
 * Playwright browser+context for the 'persistent_context' strategy, instead
 * of a fresh isolated launch per attempt. Populated by the first call that
 * receives it; subsequent calls with the same (populated) handle skip
 * launch/newContext entirely. The handle's owner (caller), not this
 * service, is responsible for closing it when done.
 */
export interface PersistentChallengeContextHandle {
  browser?: BrowserInstance;
  context?: BrowserContextInstance;
}

/**
 * Fix: Correct Challenge Resolution — closed outcome of the bounded poll.
 * 'still_challenged': a known signature matched in whatever evidence was
 *   available (title and/or body) — definite, same as before.
 * 'content_cleared': the body sample was positively obtained (non-empty,
 *   evaluate() succeeded) and matched no known signature — genuine content
 *   evidence, though still not by itself proof the real application was
 *   reached (see evaluateAndProgress's transport/canary gating below).
 * 'inconclusive': the bound was exhausted without ever matching a known
 *   signature AND without ever obtaining a non-empty body sample — only
 *   title evidence (or nothing) was ever available. Title-only evidence is
 *   never treated as 'content_cleared'.
 */
type ResolutionVerdict = 'still_challenged' | 'content_cleared' | 'inconclusive';

interface ResolutionObservation {
  readonly verdict: ResolutionVerdict;
  readonly providerHint: ChallengeProviderHint;
}

/**
 * Bounded, condition-based observation of whether a challenge is still
 * showing. Samples the page title AND, where evaluate() is available, a
 * short in-browser body excerpt. A challenge signature matched anywhere
 * (title or body) is always definitive ('still_challenged'). The converse
 * is never assumed from title alone: the loop may only conclude
 * 'content_cleared' when it has a positively-obtained, non-empty body
 * sample that matches no signature. When the body sample is empty or
 * evaluate() throws (mid-navigation, or no DOM in a non-browser harness),
 * that sample contributes no resolution evidence and polling continues;
 * if the bound is reached without ever obtaining real content, the result
 * is 'inconclusive' — never silently promoted to resolved.
 */
async function observeChallengeResolution(
  page: PageInstance,
  maxWaitMs: number
): Promise<ResolutionObservation> {
  const deadline = Date.now() + Math.max(0, maxWaitMs);
  let providerHint: ChallengeProviderHint = 'unknown';

  for (;;) {
    const title = (await page.title()) || '';
    let bodyExcerpt = '';
    let bodyAvailable: 'ok' | 'empty' | 'unavailable';
    try {
      bodyExcerpt = await page.evaluate(() => {
        const body = (globalThis as { document?: { body?: { innerText?: string } } }).document
          ?.body;
        return body?.innerText ? body.innerText.slice(0, 2000) : '';
      });
      bodyAvailable = bodyExcerpt.length > 0 ? 'ok' : 'empty';
    } catch {
      // No DOM access this sample (mid-navigation, or a non-browser
      // harness). This sample carries no body evidence — it must not be
      // treated as equivalent to a positively-empty, challenge-free page.
      bodyExcerpt = '';
      bodyAvailable = 'unavailable';
    }

    const sample = `${title}\n${bodyExcerpt}`;
    const signatureMatched = matchesAnyChallengeSignature(sample);

    if (signatureMatched) {
      providerHint = detectChallengeProviderHint(sample);
    } else if (bodyAvailable === 'ok') {
      // The ONLY condition under which the loop may conclude resolution:
      // a real, non-empty body sample that matches no known signature.
      // Title-only evidence (bodyAvailable !== 'ok') can never reach here.
      return { verdict: 'content_cleared', providerHint: detectChallengeProviderHint(sample) };
    }

    if (Date.now() >= deadline) {
      return {
        verdict: signatureMatched ? 'still_challenged' : 'inconclusive',
        providerHint,
      };
    }
    await page.waitForTimeout(RESOLUTION_POLL_INTERVAL_MS);
  }
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
        providerHint: classification.providerHint,
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
        providerHint: classification.providerHint,
      };
    }

    // Requires browser-mediated flow
    const launcher = options.browserLauncher ?? new DefaultPlaywrightBrowserLauncher();
    const strategy: ChallengeContinuationStrategyKind = options.strategy ?? 'fresh_context';
    const handle = strategy === 'persistent_context' ? options.persistentContextHandle : undefined;
    let browser: BrowserInstance | null = null;
    // Milestone: Challenge Continuation Reliability — when a persistent
    // context handle is in play (reused OR newly stashed for a later
    // attempt), the CALLER owns closing it, not this function. Only a
    // browser this call itself launched and did not hand off gets closed
    // in the finally block below.
    let ownsBrowser = true;

    try {
      // Milestone: Challenge Continuation Reliability — mirrors the
      // disableStealth threading in PlaywrightSpaAdapter.ts exactly: default
      // (undefined/false) preserves the current stealth-enabled behavior at
      // both the launch-args layer and the context/init-script layer.
      const disableStealth = options.disableStealth === true;
      let context: BrowserContextInstance;
      if (handle?.browser && handle?.context) {
        // Reuse the caller-supplied browser+context from a prior attempt on
        // the same URL — skip launch/newContext/stealth re-apply entirely.
        browser = handle.browser;
        context = handle.context;
        ownsBrowser = false;
      } else {
        // Fix: Correct Challenge Resolution — the real DefaultPlaywrightBrowserLauncher
        // treats `args: undefined` as "caller did not specify args" and substitutes its
        // own STEALTH_CHROMIUM_LAUNCH_ARGS default (PlaywrightSpaAdapter.ts), which
        // silently defeated disableStealth at this layer. An explicit empty array is
        // truthy and is preserved by that launcher's own `options?.args ? [...] : [...]`
        // check, so it genuinely results in no launch arguments.
        browser = await launcher.launch({
          headless: true,
          args: disableStealth ? [] : [...STEALTH_CHROMIUM_LAUNCH_ARGS],
        });
        const profile = selectBrowserProfile();
        context = disableStealth
          ? await browser.newContext()
          : await browser.newContext(buildStealthContextOptions(profile));
        if (!disableStealth) {
          await applyPlaywrightStealth(context, profile);
        }
        if (handle) {
          // First attempt using this handle: stash for reuse by a later
          // 'persistent_context' attempt on the same URL. The handle's
          // owner (the orchestrator's per-URL retry loop) now owns closing
          // browser/context once the whole retry sequence ends.
          handle.browser = browser;
          handle.context = context;
          ownsBrowser = false;
        }
      }

      const page = await context.newPage();
      await page.goto(options.challengeUrl, {
        waitUntil: 'domcontentloaded',
        timeout: options.timeoutMs ?? 15_000,
      });

      // Milestone: Challenge Continuation Reliability — bounded,
      // condition-based observation replaces the old fixed 2s sleep +
      // title-only regex. Combines title and in-browser body content (never
      // title alone) and is capped by resolutionTimeoutMs, never indefinite.
      const resolution = await observeChallengeResolution(
        page,
        options.resolutionTimeoutMs ?? DEFAULT_RESOLUTION_TIMEOUT_MS
      );

      if (resolution.verdict === 'still_challenged') {
        if (classification.requiresOperatorHitl) {
          return {
            state: 'waiting_for_operator',
            challengeUrl: options.challengeUrl,
            reasonCode: 'interactive_challenge_pending',
            applicationReachable: false,
            capturedCookieNames: Object.freeze([]),
            operatorMessage:
              'Target requires interactive verification (Turnstile/CAPTCHA), which no automated continuation strategy can complete. Reconnaissance continues automatically on other authorized resources.',
            providerHint: resolution.providerHint,
            resolutionMethod: 'title_and_content',
            strategyUsed: strategy,
          };
        }

        return {
          state: 'failed',
          challengeUrl: options.challengeUrl,
          reasonCode: 'browser_challenge_unresolved',
          applicationReachable: false,
          capturedCookieNames: Object.freeze([]),
          operatorMessage: 'Automated browser progression could not resolve challenge within timeout',
          providerHint: resolution.providerHint,
          resolutionMethod: 'title_and_content',
          strategyUsed: strategy,
        };
      }

      // Extract cookies from browser context BEFORE closing it
      let capturedCookies: readonly BrowserCookieRecord[] = Object.freeze([]);
      // Milestone R11 — previously silent: this catch left zero trace that
      // extraction was even attempted and failed, indistinguishable from
      // "there were no cookies." Now exposed as a secondary diagnostic only
      // — it never changes the continuation's own state/reasonCode below.
      let cookieExtractionFailed = false;
      if (typeof context.cookies === 'function') {
        try {
          capturedCookies = await context.cookies(options.challengeUrl);
        } catch {
          cookieExtractionFailed = true;
        }
      }

      // Transfer captured cookies into sanctuary with strict origin boundaries
      const importedCookieNames = options.sessionSanctuary.importBrowserCookies(
        'anonymous',
        capturedCookies,
        'resolved'
      );
      if (options.sessionSanctuary.hasAuthenticatedContext()) {
        options.sessionSanctuary.importBrowserCookies(
          'authenticated',
          capturedCookies,
          'resolved'
        );
      }

      // Fix: Correct Challenge Resolution — central invariant: absence of
      // detected challenge markers is not proof of successful application
      // access. Without a transport, there is no independent way to
      // confirm the real application was reached, whether the browser-side
      // check found genuinely clean content or was simply inconclusive.
      // Never claim 'validated' (nor a confirmed-unreachable 'failed') on
      // browser-side evidence alone — report the honest middle state.
      if (!options.transport) {
        return {
          state: 'validation_pending',
          challengeUrl: options.challengeUrl,
          reasonCode: 'resolution_evidence_insufficient',
          applicationReachable: false,
          capturedCookieNames: importedCookieNames,
          validatedAt: new Date().toISOString(),
          operatorMessage:
            resolution.verdict === 'content_cleared'
              ? 'No known challenge signature observed in page content, but no independent canary was available to confirm the application is actually reachable.'
              : 'Unable to obtain page content to evaluate for a challenge signature, and no independent canary was available either; resolution remains inconclusive.',
          ...(cookieExtractionFailed ? { cookieExtractionFailed: true } : {}),
          providerHint: resolution.providerHint,
          resolutionMethod: 'insufficient_evidence',
          strategyUsed: strategy,
        };
      }

      // Validate post-challenge application reachability using the
      // independent transport/canary — the sole positive confirmation path.
      // `transport` is guaranteed defined here: the !options.transport case
      // already returned above.
      const transport = options.transport;
      let applicationReachable = true;
      let reasonCode = 'browser_progression_succeeded';
      let operatorMessage =
        'Browser progression successfully navigated past edge challenge to application';

      try {
        const canary = await options.sessionSanctuary.validateSessionHealth(
          options.sessionSanctuary.hasAuthenticatedContext() ? 'authenticated' : 'anonymous',
          transport,
          options.challengeUrl
        );
        if (canary.healthState === 'challenged') {
          applicationReachable = false;
          reasonCode = 'still_challenged_after_browser_progression';
          operatorMessage = `Browser progression completed but application canary was still challenged: ${canary.reason}`;
        } else if (canary.healthState !== 'valid' && canary.healthState !== 'degraded') {
          applicationReachable = false;
          reasonCode = 'application_unreachable_after_browser_progression';
          operatorMessage = `Browser progression completed but application canary failed: ${canary.reason}`;
        }
      } catch (canaryErr) {
        applicationReachable = false;
        reasonCode = 'canary_failed_after_browser_progression';
        operatorMessage = `Application canary failed after browser progression: ${canaryErr instanceof Error ? canaryErr.message : String(canaryErr)}`;
      }

      const validatedAt = new Date().toISOString();
      // A transport is guaranteed present at this point (see above), so the
      // canary is always the authority for this return.
      const resolutionMethod: ChallengeResolutionMethod = 'canary_probe';

      return {
        state: applicationReachable ? 'validated' : 'failed',
        challengeUrl: options.challengeUrl,
        reasonCode,
        applicationReachable,
        capturedCookieNames: importedCookieNames,
        validatedAt,
        operatorMessage,
        ...(cookieExtractionFailed ? { cookieExtractionFailed: true } : {}),
        providerHint: resolution.providerHint,
        resolutionMethod,
        strategyUsed: strategy,
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
        strategyUsed: strategy,
      };
    } finally {
      // Milestone: Challenge Continuation Reliability — only close a browser
      // this call itself owns. A reused or newly-stashed persistent-context
      // browser is left open for the caller (the handle's owner) to close
      // once the whole per-URL retry sequence ends.
      if (browser && ownsBrowser) {
        await browser.close().catch(() => {});
      }
    }
  }
}
