export function filterInScope(urls: string[], targetUrl: string): { inScope: string[], filtered: number } {
  let baseDomain = '';
  try {
    baseDomain = new URL(targetUrl).hostname;
  } catch {
    // If targetUrl is invalid, fallback to accepting everything (shouldn't happen)
    return { inScope: urls, filtered: 0 };
  }

  const inScope: string[] = [];
  const filteredUrls: string[] = [];

  for (const url of urls) {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname;

      // Check if it's the same domain or a subdomain
      if (hostname === baseDomain || hostname.endsWith(`.${baseDomain}`)) {
        inScope.push(url);
      } else {
        filteredUrls.push(url);
      }
    } catch {
      // Allow relative paths starting with /
      if (url.startsWith('/')) {
        inScope.push(url);
      } else {
        filteredUrls.push(url);
      }
    }
  }

  if (filteredUrls.length > 0) {
    const sample = filteredUrls.slice(0, 5);
    console.log(`[Scope] Eliminadas ${filteredUrls.length} URLs fuera de scope. Ejemplos eliminados: ${sample.join(', ')}`);
  }

  return { inScope, filtered: filteredUrls.length };
}
