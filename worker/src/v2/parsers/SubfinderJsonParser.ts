import type { RawExecutionOutput } from '../core/ExecutionContracts';
import type { EvidenceCollection, Finding } from '../core/Evidence';
import type { Parser } from './Parser';

export class SubfinderJsonParser implements Parser {
  parse(output: RawExecutionOutput): EvidenceCollection {
    const findings: Finding[] = [];
    const parseErrors: string[] = [];

    if (!output.stdout || output.stdout.trim() === '') {
      return {
        findings: [],
        metadata: {
          note: 'No stdout from subfinder'
        }
      };
    }

    const lines = output.stdout.split('\n');
    for (const line of lines) {
      if (line.trim() === '') continue;
      
      try {
        const record = JSON.parse(line);
        // Subfinder JSON output typically contains a "host" field
        if (record && record.host) {
          const finding: Finding = {
            id: `subfinder_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
            type: 'subdomain_discovery',
            severity: 'info',
            title: 'Discovered Subdomain',
            description: `Subdomain discovered via passive reconnaissance`,
            target: record.host,
            evidence: JSON.stringify(record),
            confidence: 0.9, // High confidence for passive OSINT
            metadata: {
              source: record.source || 'unknown',
              ip: record.ip || ''
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
