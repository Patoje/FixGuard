import { NextResponse } from "next/server";

function isPrivateOrSsrfHost(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (lower === "localhost" || lower.endsWith(".localhost") || lower === "127.0.0.1" || lower === "0.0.0.0") {
    return true;
  }
  if (/^127\./.test(lower)) return true;
  if (/^10\./.test(lower)) return true;
  if (/^192\.168\./.test(lower)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(lower)) return true;
  if (/^169\.254\./.test(lower)) return true;
  return false;
}

export async function POST(request: Request) {
  const startTime = Date.now();
  try {
    const json = await request.json();
    const { url, method = "GET", headers = {}, body } = json;

    if (!url || typeof url !== "string") {
      return NextResponse.json(
        { success: false, error: "Parámetro 'url' es requerido" },
        { status: 400 }
      );
    }

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return NextResponse.json(
        { success: false, error: `URL inválida: '${url}'` },
        { status: 400 }
      );
    }

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return NextResponse.json(
        { success: false, error: "Solo se permiten protocolos http o https" },
        { status: 400 }
      );
    }

    if (isPrivateOrSsrfHost(parsed.hostname)) {
      return NextResponse.json(
        {
          success: false,
          error: `Egress bloqueó host privado o loopback: '${parsed.hostname}' (SSRF gate)`,
        },
        { status: 403 }
      );
    }

    const cleanHeaders: Record<string, string> = {
      "User-Agent": "FixGuard-Security-Auditor/2.0",
      Accept: "*/*",
      ...headers,
    };

    const fetchOptions: RequestInit = {
      method: method.toUpperCase(),
      headers: cleanHeaders,
      redirect: "manual",
      signal: AbortSignal.timeout(12000),
    };

    if (body && method.toUpperCase() !== "GET" && method.toUpperCase() !== "HEAD") {
      fetchOptions.body = body;
    }

    const response = await fetch(parsed.toString(), fetchOptions);
    const durationMs = Date.now() - startTime;

    const resHeaders: Record<string, string> = {};
    response.headers.forEach((val, key) => {
      resHeaders[key] = val;
    });

    let bodyText = "";
    try {
      const text = await response.text();
      bodyText = text.slice(0, 4096);
    } catch {
      bodyText = "<binary or non-text response>";
    }

    return NextResponse.json({
      success: true,
      status: response.status,
      statusText: response.statusText,
      headers: resHeaders,
      bodySnippet: bodyText,
      durationMs,
      url: parsed.toString(),
      method: method.toUpperCase(),
    });
  } catch (err: unknown) {
    const durationMs = Date.now() - startTime;
    const msg = err instanceof Error ? err.message : "Error desconocido en sonda HTTP";
    return NextResponse.json({
      success: false,
      error: msg,
      durationMs,
    });
  }
}
