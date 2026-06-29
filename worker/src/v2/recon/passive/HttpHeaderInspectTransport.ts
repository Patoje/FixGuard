export interface RawTransportResponse {
  statusCode: number;
  statusText: string;
  headers: Record<string, string | string[] | undefined>;
}

export interface HttpHeaderInspectTransport {
  execute(url: string, timeoutMs: number): Promise<RawTransportResponse>;
}
