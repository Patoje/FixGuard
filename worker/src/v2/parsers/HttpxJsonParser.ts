import type { RawExecutionOutput } from '../core/ExecutionContracts';
import type { EvidenceCollection, Finding } from '../core/Evidence';
import type { Parser } from './Parser';

export class HttpxJsonParser implements Parser {
  parse(output: RawExecutionOutput): EvidenceCollection {
    const findings: Finding[] = [];
    const parseErrors: string[] = [];

    if (!output.stdout || output.stdout.trim() === '') {
      return {
        findings: [],
        metadata: {
          note: 'No stdout from httpx'
        }
      };
    }

    const lines = output.stdout.split('\n');
    for (const line of lines) {
      if (line.trim() === '') continue;
      
      try {
        const record = JSON.parse(line);
        if (record && record.failed === true) {
          continue;
        }
        
        if (record && record.url) {
          const statusCode = record['status-code'] || 0;
          let severity: Finding['severity'] = 'info';
          if (statusCode >= 400 && statusCode < 500) {
            severity = 'low';
          } else if (statusCode >= 500) {
            severity = 'medium';
          }

          const finding: Finding = {
            id: `httpx_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
            type: 'http_live_host',
            severity,
            title: `Live HTTP Host: ${record.url}`,
            description: `HTTP service detected at ${record.url}. Title: "${record.title || 'N/A'}". Server: "${record.webserver || 'unknown'}"`,
            target: record.url,
            evidence: JSON.stringify(record),
            confidence: 0.95,
            metadata: {
              host: record.host,
              port: record.port,
              statusCode,
              title: record.title,
              webserver: record.webserver,
              technologies: record.tech || [],
              scheme: record.scheme,
              finalUrl: record['final-url']
            }
          };
          findings.push(finding);
        }
      } catch (e) {
        parseErrors.push(`Failed to parse line: ${line.substring(0, 50)}...`);
      }
    }

    return {
      findings,
      metadata: {
        parseErrors: parseErrors.length > 0 ? parseErrors : undefined,
        totalParsed: findings.length,
        durationMs: output.durationMs
      }
    };
  }
}
