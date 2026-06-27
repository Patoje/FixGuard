import type { CapabilityRequest, ExecutionRequest } from '../core/ExecutionContracts';
import type { ToolAdapter, ValidationResult } from './ToolAdapter';
import * as os from 'os';

export class SubfinderAdapter implements ToolAdapter {
  readonly capability = 'subdomain_discovery';

  prepare(request: CapabilityRequest): ExecutionRequest {
    const targetDomain = this.extractDomain(request.target.uri);

    // Extend PATH to support Go tools typical in security tooling
    const homedir = os.homedir();
    const extraPaths = [
      `${homedir}/go/bin`,
      `${homedir}/bin`,
      `${homedir}/.local/bin`,
    ];
    const separator = process.platform === 'win32' ? ';' : ':';
    const currentPath = process.env.PATH || '';
    
    const toAdd = extraPaths.filter(p => !currentPath.includes(p));
    const extendedPath = toAdd.length > 0 
      ? `${currentPath}${separator}${toAdd.join(separator)}` 
      : currentPath;

    return {
      binary: 'subfinder',
      args: ['-d', targetDomain, '-j', '-silent'],
      env: { PATH: extendedPath },
      timeoutMs: 120_000
    };
  }

  validate(config: Record<string, unknown>, targetUri: string): ValidationResult {
    const errors: string[] = [];
    if (!targetUri || targetUri.trim() === '') {
      errors.push('Target URI is required');
    } else {
      const domain = this.extractDomain(targetUri);
      // Basic IP check - subfinder doesn't work on bare IPs
      if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
         errors.push('Subfinder requires a domain name, not an IP address');
      }
    }
    return {
      isValid: errors.length === 0,
      errors
    };
  }

  private extractDomain(url: string): string {
    try {
      if (!url.includes('://') && !url.startsWith('http')) {
        return url;
      }
      const parsedUrl = new URL(url);
      return parsedUrl.hostname.replace(/^www\./, '');
    } catch (error) {
      const match = url.match(/^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n]+)/im);
      return match && match[1] ? match[1] : url;
    }
  }
}
