/**
 * Thin PostgREST HTTP transport adapter over IdorHttpProbeTransport.
 * Adds Supabase-required apikey / Authorization headers without logging secrets.
 */

import type {
  HttpProbeRequest,
  HttpProbeResponse,
  IdorHttpProbeTransport,
} from '../../detection/DetectionContracts.js';
import { defaultHttpProbeTransport } from '../../detection/IdorDifferentialDetectionService.js';

export interface PostgrestTransportHeadersInput {
  readonly anonApiKey: string;
  /** When set, used as Bearer; otherwise anon key is used as Bearer (anon role). */
  readonly bearerToken?: string;
  readonly extraHeaders?: Readonly<Record<string, string>>;
}

export function buildPostgrestHeaders(
  input: PostgrestTransportHeadersInput
): Readonly<Record<string, string>> {
  const bearer = (input.bearerToken ?? input.anonApiKey).trim();
  const headers: Record<string, string> = {
    apikey: input.anonApiKey.trim(),
    authorization: `Bearer ${bearer}`,
    accept: 'application/json',
    'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
  };
  if (input.extraHeaders) {
    for (const [k, v] of Object.entries(input.extraHeaders)) {
      const lk = k.toLowerCase();
      if (lk === 'apikey' || lk === 'authorization') continue;
      headers[lk] = v;
    }
  }
  return Object.freeze(headers);
}

export function createPostgrestHttpTransport(
  base?: IdorHttpProbeTransport
): IdorHttpProbeTransport {
  const inner = base ?? defaultHttpProbeTransport;
  return async (request: HttpProbeRequest): Promise<HttpProbeResponse> => {
    return inner(request);
  };
}
