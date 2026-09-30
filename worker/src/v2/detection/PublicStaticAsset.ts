/**
 * Public static assets are not authentication boundaries.
 * Shared by auth-bypass abstention and read-plan selection.
 */

const PUBLIC_STATIC_EXTENSIONS = Object.freeze([
  '.js',
  '.css',
  '.map',
  '.woff',
  '.woff2',
  '.ttf',
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.svg',
  '.ico',
  '.webp',
]);

/** Identical authenticated and anonymous bodies in the auth-bypass detector. */
export const IDENTICAL_BODY_SIMILARITY = 1;

export function isPublicStaticAssetPath(pathname: string): boolean {
  const lower = pathname.toLowerCase();
  const pathOnly = lower.split('?')[0] ?? lower;
  if (pathOnly === '/_next/static' || pathOnly.startsWith('/_next/static/')) {
    return true;
  }
  return PUBLIC_STATIC_EXTENSIONS.some((extension) => pathOnly.endsWith(extension));
}

export function isPublicStaticAssetUrl(rawUrl: string): boolean {
  const trimmed = rawUrl.trim();
  if (trimmed.length === 0) {
    return false;
  }
  try {
    const parsed = new URL(trimmed, 'https://static.invalid');
    return isPublicStaticAssetPath(parsed.pathname);
  } catch {
    return isPublicStaticAssetPath(trimmed);
  }
}
