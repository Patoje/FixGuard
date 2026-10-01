/**
 * Milestone 7 / Phase D1 Extension — Playwright Stealth & Legitimate Browser Automation
 *
 * Implements native, zero-dependency browser stealth, profile rotation, client-hints,
 * and fail-closed proxy validation for defensive SPA and API discovery in FixGuard V2.
 *
 * Key components:
 * 1. Curated Browser Profiles: Modern desktop Chrome & Safari with authentic User-Agents,
 *    viewports, locales, timezones, and Sec-CH-UA client hints.
 * 2. Chromium Launch Args: Enforces '--disable-blink-features=AutomationControlled' to eliminate
 *    automation flags at the engine level without modifying browser binaries.
 * 3. In-Browser Evasion Scripts: Injected via addInitScript to mask navigator.webdriver,
 *    simulate window.chrome (runtime, app, csi, loadTimes), normalize navigator.plugins,
 *    languages, deviceMemory, and WebGL unmasked vendor/renderer.
 * 4. Fail-Closed Proxy Validation: Validates that proxy endpoints do NOT target loopback,
 *    RFC1918 private subnets, or cloud metadata (Gate 1 SSRF safety invariant).
 */

import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import type {
  BrowserContextInstance,
  BrowserProxyConfig,
} from './BrowserAutomationContracts.js';

export interface BrowserProfile {
  readonly id: string;
  readonly name: string;
  readonly userAgent: string;
  readonly viewport: { readonly width: number; readonly height: number };
  readonly locale: string;
  readonly timezoneId: string;
  readonly deviceScaleFactor: number;
  readonly platform: string;
  readonly secChUa?: string;
  readonly secChUaPlatform?: string;
  readonly secChUaMobile: string;
}

/** Standard desktop browser profiles representing modern consumer hardware and OSs. */
export const BROWSER_PROFILES: readonly BrowserProfile[] = Object.freeze([
  {
    id: 'macos-chrome-131',
    name: 'Chrome 131 on macOS (Apple Silicon / Intel)',
    userAgent:
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    viewport: { width: 1920, height: 1080 },
    locale: 'en-US',
    timezoneId: 'America/New_York',
    deviceScaleFactor: 2,
    platform: 'MacIntel',
    secChUa: '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    secChUaPlatform: '"macOS"',
    secChUaMobile: '?0',
  },
  {
    id: 'windows-chrome-131',
    name: 'Chrome 131 on Windows 11',
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    viewport: { width: 1920, height: 1080 },
    locale: 'en-US',
    timezoneId: 'America/Chicago',
    deviceScaleFactor: 1,
    platform: 'Win32',
    secChUa: '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    secChUaPlatform: '"Windows"',
    secChUaMobile: '?0',
  },
  {
    id: 'macos-safari-18',
    name: 'Safari 18 on macOS Sequoia',
    userAgent:
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
    viewport: { width: 1920, height: 1080 },
    locale: 'en-US',
    timezoneId: 'America/Los_Angeles',
    deviceScaleFactor: 2,
    platform: 'MacIntel',
    secChUaMobile: '?0',
  },
  {
    id: 'linux-chrome-131',
    name: 'Chrome 131 on Ubuntu Linux',
    userAgent:
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    viewport: { width: 1920, height: 1080 },
    locale: 'en-US',
    timezoneId: 'America/New_York',
    deviceScaleFactor: 1,
    platform: 'Linux x86_64',
    secChUa: '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    secChUaPlatform: '"Linux"',
    secChUaMobile: '?0',
  },
]);

export const DEFAULT_BROWSER_PROFILE: BrowserProfile = BROWSER_PROFILES[0];

/** Recommended flags to launch Chromium without automated bot artifacts. */
export const STEALTH_CHROMIUM_LAUNCH_ARGS: readonly string[] = Object.freeze([
  '--no-sandbox',
  '--disable-setuid-sandbox',
  '--disable-dev-shm-usage',
  '--disable-blink-features=AutomationControlled',
  '--disable-infobars',
  '--window-size=1920,1080',
  '--disable-background-timer-throttling',
  '--disable-backgrounding-occluded-windows',
  '--disable-renderer-backgrounding',
]);

/** Select a profile by ID or return default macOS Chrome. */
export function selectBrowserProfile(profileId?: string): BrowserProfile {
  if (!profileId) {
    return DEFAULT_BROWSER_PROFILE;
  }
  const normalized = profileId.trim().toLowerCase();
  const found = BROWSER_PROFILES.find((p) => p.id === normalized);
  return found ?? DEFAULT_BROWSER_PROFILE;
}

/** Deterministically rotate or pick a profile from a numeric or string seed. */
export function getProfileBySeed(seed: string | number): BrowserProfile {
  let index = 0;
  if (typeof seed === 'number') {
    index = Math.abs(seed) % BROWSER_PROFILES.length;
  } else {
    let hash = 0;
    for (let i = 0; i < seed.length; i++) {
      hash = (hash << 5) - hash + seed.charCodeAt(i);
      hash |= 0;
    }
    index = Math.abs(hash) % BROWSER_PROFILES.length;
  }
  return BROWSER_PROFILES[index];
}

/** Validate proxy configuration ensuring it does NOT target private/loopback/cloud metadata. */
export function validateBrowserProxyConfig(
  proxyConfig: BrowserProxyConfig
): { valid: true } | { valid: false; reason: string } {
  if (!proxyConfig || typeof proxyConfig.server !== 'string') {
    return { valid: false, reason: 'Proxy configuration must specify a valid server URL string' };
  }

  const trimmed = proxyConfig.server.trim();
  if (trimmed.length === 0) {
    return { valid: false, reason: 'Proxy server URL cannot be empty' };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, reason: `Proxy server URL is malformed: ${trimmed}` };
  }

  const protocol = parsed.protocol.toLowerCase();
  if (protocol !== 'http:' && protocol !== 'https:' && protocol !== 'socks5:') {
    return {
      valid: false,
      reason: `Unsupported proxy protocol "${protocol}". Must be http:, https:, or socks5:`,
    };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (!hostname) {
    return { valid: false, reason: 'Proxy server hostname is empty' };
  }

  if (isInternalOrSsrfTarget(hostname)) {
    return {
      valid: false,
      reason: `Proxy server cannot target private, loopback, or metadata addresses: ${hostname}`,
    };
  }

  return { valid: true };
}

/**
 * Builds the stealth initialization JavaScript to be evaluated on every new document.
 * Masks automation indicators without breaking genuine DOM APIs.
 */
export function buildStealthInitScript(profile: BrowserProfile = DEFAULT_BROWSER_PROFILE): string {
  const languagesJson = JSON.stringify([profile.locale, profile.locale.split('-')[0]]);
  const platformJson = JSON.stringify(profile.platform);

  return `(() => {
  // 1. Evade navigator.webdriver
  try {
    if ('webdriver' in navigator) {
      const proto = Object.getPrototypeOf(navigator);
      if (proto && 'webdriver' in proto) {
        delete proto.webdriver;
      }
      Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined,
        configurable: true,
        enumerable: true,
      });
    }
  } catch (_) {}

  // 2. Simulate window.chrome (runtime, app, csi, loadTimes)
  try {
    if (!window.chrome) {
      window.chrome = {};
    }
    if (!window.chrome.runtime) {
      window.chrome.runtime = {
        connect: function () {},
        sendMessage: function () {},
        id: undefined,
      };
    }
    if (!window.chrome.app) {
      window.chrome.app = {
        isInstalled: false,
        InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
        RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' },
      };
    }
    if (!window.chrome.csi) {
      window.chrome.csi = function () {
        return {
          startE: Date.now(),
          onloadT: Date.now(),
          pageT: 120,
          tran: 15,
        };
      };
    }
    if (!window.chrome.loadTimes) {
      window.chrome.loadTimes = function () {
        return {
          requestTime: Date.now() / 1000,
          startLoadTime: Date.now() / 1000,
          commitLoadTime: Date.now() / 1000,
          finishDocumentLoadTime: Date.now() / 1000,
          finishLoadTime: Date.now() / 1000,
          firstPaintTime: Date.now() / 1000,
          firstPaintAfterLoadTime: 0,
          navigationType: 'Other',
          wasFetchedViaSpdy: false,
          wasNpnNegotiated: false,
          npnNegotiatedProtocol: 'unknown',
          wasAlternateProtocolAvailable: false,
          connectionInfo: 'http/1.1',
        };
      };
    }
  } catch (_) {}

  // 3. Normalize navigator.languages and navigator.platform
  try {
    Object.defineProperty(navigator, 'languages', {
      get: () => ${languagesJson},
      configurable: true,
      enumerable: true,
    });
    Object.defineProperty(navigator, 'platform', {
      get: () => ${platformJson},
      configurable: true,
      enumerable: true,
    });
  } catch (_) {}

  // 4. Normalize navigator.plugins and mimeTypes
  try {
    if (navigator.plugins && navigator.plugins.length === 0) {
      const mockPlugins = [
        { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
        { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
        { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' },
      ];
      Object.defineProperty(navigator, 'plugins', {
        get: () => mockPlugins,
        configurable: true,
        enumerable: true,
      });
    }
  } catch (_) {}

  // 5. Normalise hardware concurrency and device memory
  try {
    if (!navigator.deviceMemory || navigator.deviceMemory < 4) {
      Object.defineProperty(navigator, 'deviceMemory', { get: () => 8, configurable: true });
    }
    if (!navigator.hardwareConcurrency || navigator.hardwareConcurrency < 4) {
      Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8, configurable: true });
    }
  } catch (_) {}

  // 6. WebGL Unmasked Vendor & Renderer spoofing
  try {
    const patchGetParameter = (proto) => {
      if (!proto || !proto.getParameter) return;
      const original = proto.getParameter;
      proto.getParameter = function (param) {
        // UNMASKED_VENDOR_WEBGL = 37445 (0x9245)
        if (param === 37445) return 'Intel Inc.';
        // UNMASKED_RENDERER_WEBGL = 37446 (0x9246)
        if (param === 37446) return 'Intel Iris OpenGL Engine';
        return original.apply(this, [param]);
      };
    };
    if (typeof WebGLRenderingContext !== 'undefined') {
      patchGetParameter(WebGLRenderingContext.prototype);
    }
    if (typeof WebGL2RenderingContext !== 'undefined') {
      patchGetParameter(WebGL2RenderingContext.prototype);
    }
  } catch (_) {}

  // 7. Notification permissions query normalization
  try {
    if (navigator.permissions && navigator.permissions.query) {
      const origQuery = navigator.permissions.query;
      navigator.permissions.query = function (params) {
        if (params && params.name === 'notifications') {
          return Promise.resolve({
            state: typeof Notification !== 'undefined' && Notification.permission === 'denied' ? 'denied' : 'prompt',
            name: 'notifications',
            onchange: null,
            addEventListener: function () {},
            removeEventListener: function () {},
            dispatchEvent: function () { return true; },
          });
        }
        return origQuery.apply(this, [params]);
      };
    }
  } catch (_) {}
})();`;
}

/**
 * Builds BrowserContextOptions for Playwright newContext().
 * Combines realistic user-agent, viewport, locale, timezone, Sec-CH-UA client hints, and proxy.
 */
export function buildStealthContextOptions(
  profile: BrowserProfile = DEFAULT_BROWSER_PROFILE,
  proxyConfig?: BrowserProxyConfig
): Record<string, unknown> {
  const extraHeaders: Record<string, string> = {
    'Accept-Language': `${profile.locale},${profile.locale.split('-')[0]};q=0.9`,
  };

  if (profile.secChUa) {
    extraHeaders['sec-ch-ua'] = profile.secChUa;
  }
  if (profile.secChUaPlatform) {
    extraHeaders['sec-ch-ua-platform'] = profile.secChUaPlatform;
  }
  if (profile.secChUaMobile) {
    extraHeaders['sec-ch-ua-mobile'] = profile.secChUaMobile;
  }

  const options: Record<string, unknown> = {
    userAgent: profile.userAgent,
    viewport: { ...profile.viewport },
    locale: profile.locale,
    timezoneId: profile.timezoneId,
    deviceScaleFactor: profile.deviceScaleFactor,
    extraHTTPHeaders: extraHeaders,
  };

  if (proxyConfig) {
    options.proxy = {
      server: proxyConfig.server,
      ...(proxyConfig.username ? { username: proxyConfig.username } : {}),
      ...(proxyConfig.password ? { password: proxyConfig.password } : {}),
      ...(proxyConfig.bypass ? { bypass: proxyConfig.bypass } : {}),
    };
  }

  return options;
}

/**
 * Applies stealth evasions to a BrowserContextInstance before any pages are opened.
 */
export async function applyPlaywrightStealth(
  context: BrowserContextInstance,
  profile: BrowserProfile = DEFAULT_BROWSER_PROFILE
): Promise<void> {
  if (typeof context.addInitScript === 'function') {
    const script = buildStealthInitScript(profile);
    await context.addInitScript(script);
  }
}
