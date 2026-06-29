import type { HttpHeaderInspectTransport, RawTransportResponse } from './HttpHeaderInspectTransport';

export class FakeHttpHeaderInspectTransport implements HttpHeaderInspectTransport {
  public lastRequestedUrl?: string;
  public lastTimeoutMs?: number;
  public shouldFail: boolean = false;
  
  async execute(targetUrl: string, timeoutMs: number): Promise<RawTransportResponse> {
    this.lastRequestedUrl = targetUrl;
    this.lastTimeoutMs = timeoutMs;
    
    if (this.shouldFail) {
      throw new Error('Fake timeout error');
    }

    return {
      statusCode: 200,
      statusText: 'OK',
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'server': 'FakeServer',
        'set-cookie': 'session=abc; HttpOnly',
        'authorization': 'Bearer token',
        'location': 'https://example.com/redirect?secret=123',
        'x-api-key': 'supersecretkey',
        'PassWd': 'my-password'
      }
    };
  }
}
