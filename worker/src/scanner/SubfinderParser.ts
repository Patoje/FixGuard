import { ResultParser } from '../types/ScannerResult';
import type { ScannerResult, Finding } from '../types/ScannerResult';

/**
 * Parser for Subfinder tool output
 */
export class SubfinderParser extends ResultParser {
  parse(rawOutput: string): ScannerResult {
    const startTime = new Date(Date.now() - 1000); // Approximate start time
    const endTime = new Date();
    
    const subdomains = this.extractSubdomains(rawOutput);
    
    const findings: Finding[] = subdomains.map(subdomain => 
      this.createFinding({
        type: 'subdomain_discovery',
        severity: 'info',
        title: 'Discovered Subdomain',
        description: `Subdomain discovered during passive reconnaissance`,
        evidence: subdomain,
        confidence: 0.8,
        affectedAssets: [subdomain],
        metadata: {
          subdomain: subdomain
        }
      })
    );

    return {
      scanId: `scan_subfinder_${Date.now()}`,
      scannerName: 'subfinder',
      target: '', // Will be filled in by caller
      startTime,
      endTime,
      durationMs: endTime.getTime() - startTime.getTime(),
      status: 'success',
      findings,
      rawOutput,
      metadata: {
        subdomainCount: subdomains.length
      }
    };
  }

  getFindings(rawOutput: string): Finding[] {
    return this.parse(rawOutput).findings;
  }

  private extractSubdomains(output: string): string[] {
    // Split output by lines and filter out empty lines
    const lines = output.split('\n').filter(line => line.trim() !== '');
    
    // Filter out likely subdomains (basic validation)
    return lines.filter(line => {
      const trimmedLine = line.trim();
      // Basic validation - should contain at least one dot and not be too long
      return trimmedLine.includes('.') && trimmedLine.length < 254;
    });
  }
}