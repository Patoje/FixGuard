/**
 * FixGuard V2 — Recon Tool Availability Service (Milestone P0-3)
 *
 * Enforces honest capability detection and binary availability probing.
 * Probes host PATH for CLI binaries without using shell execution,
 * enforcing a strict allowlist and closed-world status mapping.
 */

import type { ProcessRunner } from '../core/ProcessRunner.js';
import { LocalProcessRunner } from '../core/ProcessRunner.js';
import type {
  CapabilityStatusResponse,
  ReconToolName,
  SingleToolStatus,
  ToolCapabilityMatrix,
} from './CapabilityStatusContracts.js';
import {
  CAPABILITY_STATUS_CONTRACT_VERSION,
  isAllowedReconTool,
  RECON_TOOL_ALLOWLIST,
} from './CapabilityStatusContracts.js';
import { ApiValidationError } from '../api/ApiErrors.js';

interface ToolProbeSpec {
  readonly versionArgs: readonly string[];
  readonly versionPattern: RegExp;
}

const TOOL_PROBE_SPECS: Record<ReconToolName, ToolProbeSpec> = {
  subfinder: {
    versionArgs: ['-version'],
    versionPattern: /v?(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?)/i,
  },
  naabu: {
    versionArgs: ['-version'],
    versionPattern: /v?(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?)/i,
  },
  httpx: {
    versionArgs: ['-version'],
    versionPattern: /v?(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?)/i,
  },
  dnsx: {
    versionArgs: ['-version'],
    versionPattern: /v?(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?)/i,
  },
  tlsx: {
    versionArgs: ['-version'],
    versionPattern: /v?(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?)/i,
  },
  ffuf: {
    versionArgs: ['-V'],
    versionPattern: /version:\s*v?(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?)/i,
  },
  gau: {
    versionArgs: ['--version'],
    versionPattern: /version:\s*v?(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?)/i,
  },
  arjun: {
    versionArgs: ['--version'],
    versionPattern: /v?(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?)/i,
  },
  trufflehog: {
    versionArgs: ['--version'],
    versionPattern: /(?:trufflehog\s+)?v?(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?)/i,
  },
};

export class ReconToolAvailabilityService {
  private readonly processRunner: ProcessRunner;

  constructor(processRunner?: ProcessRunner) {
    this.processRunner = processRunner ?? new LocalProcessRunner();
  }

  /**
   * Probes availability and version of a single recon CLI binary.
   */
  public async checkTool(toolName: string): Promise<SingleToolStatus> {
    if (!isAllowedReconTool(toolName)) {
      throw new ApiValidationError(
        `Tool '${toolName}' is not in the recognized FixGuard recon tool allowlist.`
      );
    }

    const probedAt = new Date().toISOString();
    const spec = TOOL_PROBE_SPECS[toolName];

    // 1. Find binary absolute path via safe 'which' probe if available
    let binaryPath: string | undefined;
    try {
      const whichOutput = await this.processRunner.execute({
        binary: 'which',
        args: [toolName],
        timeoutMs: 2000,
      });
      if (whichOutput.exitCode === 0 && whichOutput.stdout.trim().length > 0) {
        binaryPath = whichOutput.stdout.trim().split('\n')[0];
      }
    } catch {
      // 'which' failed or not present; proceed directly to binary execution
    }

    // 2. Probe binary version using safe argument array (shell: false)
    try {
      const output = await this.processRunner.execute({
        binary: toolName,
        args: [...spec.versionArgs],
        timeoutMs: 3000,
      });

      const combinedText = `${output.stdout}\n${output.stderr}`.trim();
      const match = combinedText.match(spec.versionPattern);
      const extractedVersion = match ? match[1] : undefined;

      if (output.exitCode === 0 || extractedVersion) {
        return {
          tool: toolName,
          status: 'available',
          ...(binaryPath ? { path: binaryPath } : {}),
          ...(extractedVersion ? { version: extractedVersion } : {}),
          probedAt,
        };
      }

      // Non-zero exit with no recognizable version pattern
      return {
        tool: toolName,
        status: 'wrong_version',
        ...(binaryPath ? { path: binaryPath } : {}),
        error: combinedText || `Exit code ${output.exitCode}`,
        probedAt,
      };
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      return {
        tool: toolName,
        status: 'missing',
        error: errorMsg,
        probedAt,
      };
    }
  }

  /**
   * Probes all 9 underlying recon binaries in parallel and synthesizes the capability matrix.
   */
  public async checkAllTools(): Promise<CapabilityStatusResponse> {
    const results = await Promise.all(
      RECON_TOOL_ALLOWLIST.map((tool) => this.checkTool(tool))
    );

    const tools = {} as Record<ReconToolName, SingleToolStatus>;
    let availableCount = 0;
    let missingCount = 0;
    let wrongVersionCount = 0;

    for (const res of results) {
      tools[res.tool] = res;
      if (res.status === 'available') {
        availableCount++;
      } else if (res.status === 'missing') {
        missingCount++;
      } else if (res.status === 'wrong_version') {
        wrongVersionCount++;
      }
    }

    return {
      contractVersion: CAPABILITY_STATUS_CONTRACT_VERSION,
      tools: tools as ToolCapabilityMatrix,
      summary: {
        total: RECON_TOOL_ALLOWLIST.length,
        availableCount,
        missingCount,
        wrongVersionCount,
        allAvailable: availableCount === RECON_TOOL_ALLOWLIST.length,
      },
      generatedAt: new Date().toISOString(),
    };
  }

  /**
   * Verifies that a specific subset of required tools are available.
   */
  public async verifyRequiredTools(
    requiredTools: readonly ReconToolName[]
  ): Promise<{ allAvailable: boolean; missingTools: readonly ReconToolName[] }> {
    const checkPromises = requiredTools.map((tool) => this.checkTool(tool));
    const results = await Promise.all(checkPromises);

    const missingTools: ReconToolName[] = [];
    for (const res of results) {
      if (res.status !== 'available') {
        missingTools.push(res.tool);
      }
    }

    return {
      allAvailable: missingTools.length === 0,
      missingTools,
    };
  }
}
