import type { ToolAdapter, ExecutableCommand } from '../types/ToolAdapter';
import { BaseToolAdapter } from './BaseToolAdapter';
import type { ExecutionStep, TargetContext } from '../types/ExecutionPlan';

/**
 * Adapter for Subfinder tool
 */
export class SubfinderAdapter extends BaseToolAdapter implements ToolAdapter {
  readonly toolId = 'subfinder';
  readonly capabilities = ['subdomain_discovery', 'passive_recon', 'dns_enumeration'];

  prepare(step: ExecutionStep, targetContext: TargetContext): ExecutableCommand {
    // Get the target domain from context, falling back to step config
    const targetDomain = this.extractDomain(targetContext.targetUrl);
    
    // Default command for subfinder
    let args = ['-d', targetDomain, '-all', '-silent'];
    
    // Merge with any custom configuration from the step
    if (step.config && step.config.args) {
      args = step.config.args;
    }

    return {
      binary: 'subfinder',
      args: args,
      timeout: step.timeout || 120000, // 2 minutes default
      metadata: {
        preparedForStep: step.stepId,
        targetType: 'domain',
        ...step.metadata
      }
    }
  }
  
  getMetadata() {
    return {
      name: 'Subfinder',
      version: 'latest',
      description: 'Fast passive subdomain enumeration tool',
      author: 'ProjectDiscovery',
      homepage: 'https://github.com/projectdiscovery/subfinder',
      capabilities: this.capabilities,
      supportedTargets: ['domain'],
      requirements: {
        os: ['linux', 'darwin', 'win32'],
        arch: ['amd64', 'arm64'],
        dependencies: [],
        minimumResources: {
          cpu: '1 core',
          memory: '128MB',
          disk: '10MB',
          metadata: {}
        },
        networkAccess: true,
        fileSystemAccess: true,
        metadata: {}
      },
      metadata: {
        toolType: 'enumeration',
        category: 'recon'
      }
    };
  }
  
  private extractDomain(url: string): string {
    try {
      // If it's already a domain, return it
      if (!url.includes('://') && !url.startsWith('http')) {
        return url;
      }
      
      // Otherwise parse as URL and extract hostname
      const parsedUrl = new URL(url);
      return parsedUrl.hostname.replace(/^www\./, ''); // Remove www. prefix if present
    } catch (error) {
      // If URL parsing fails, try basic extraction
      const match = url.match(/^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n]+)/im);
      return match ? (match[1] as string) : url;
    }
  }
  
  async isAvailable(): Promise<boolean> {
    // Check if subfinder is installed
    try {
      const { spawnSync } = require('child_process');
      const result = spawnSync('subfinder', ['-version'], {
        stdio: 'pipe'
      });
      
      return result.error ? false : true;
    } catch (error) {
      return false;
    }
  }
  
  validate(config: Record<string, any>) {
    const errors: string[] = [];
    const warnings: string[] = [];
    
    if (config && typeof config !== 'object') {
      errors.push('Configuration must be an object');
      return { isValid: false, errors, warnings };
    }
    
    if (config.args && !Array.isArray(config.args)) {
      errors.push('Args must be an array');
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }
}