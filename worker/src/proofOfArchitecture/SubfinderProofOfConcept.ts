import { ToolAdapterRegistry } from '../registry/ToolAdapterRegistry';
import { SubfinderAdapter } from '../adapters/SubfinderAdapter';
import { SubfinderParser } from '../scanner/SubfinderParser';
import type { ExecutionPlan, ExecutionStep } from '../types/ExecutionPlan';
import type { TargetContext } from '../types/TargetContext';
import type { AssessmentProfile } from '../types/AssessmentProfile';
import type { RawExecutionOutput } from '../types/RawExecutionOutput';
import type { EvidenceCollection } from '../types/Evidence';

/**
 * Proof of concept implementation for the ToolAdapter Registry + ExecutionPlan architecture
 * Demonstrates the complete new execution flow with Subfinder
 */
export class SubfinderProofOfConcept {
  private registry: ToolAdapterRegistry;
  private parser: SubfinderParser;

  constructor() {
    this.registry = new ToolAdapterRegistry();
    this.parser = new SubfinderParser();
    this.initializeRegistry();
  }

  private initializeRegistry(): void {
    // Register the Subfinder adapter
    this.registry.register(new SubfinderAdapter());
  }

  /**
   * Executes the complete new architecture flow with Subfinder
   */
  async executeFlow(
    targetContext: TargetContext,
    assessmentProfile: AssessmentProfile
  ): Promise<{
    executionPlan: ExecutionPlan;
    rawOutput: RawExecutionOutput;
    scannerResult: any; // ScannerResult type
    evidenceCollection: EvidenceCollection;
  }> {
    // 1. Create an execution plan based on the assessment profile
    const executionPlan = this.createExecutionPlan(targetContext, assessmentProfile);

    // 2. Execute the plan using the new architecture
    const rawOutput = await this.executePlan(executionPlan);

    // 3. Parse the raw output to get scanner results
    const scannerResult = this.parseResults(rawOutput.stdout, targetContext);

    // 4. Transform scanner results to evidence
    const evidenceCollection = this.transformToEvidence(scannerResult);

    return {
      executionPlan,
      rawOutput,
      scannerResult,
      evidenceCollection
    };
  }

  /**
   * Creates an execution plan based on assessment profile
   */
  private createExecutionPlan(targetContext: TargetContext, assessmentProfile: AssessmentProfile): ExecutionPlan {
    // Create a simple execution step for subdomain discovery
    const executionStep: ExecutionStep = {
      stepId: `step_${Date.now()}`,
      profileId: assessmentProfile.id,
      assessmentIntent: assessmentProfile.assessmentIntent, // Use the assessment intent
      toolCapability: 'subdomain_discovery',
      config: {
        args: ['-d', targetContext.targetUrl, '-all', '-silent']
      },
      targetContext,
      dependencies: [],
      metadata: {
        assessmentProfileId: assessmentProfile.id,
        assessmentType: 'subdomain_discovery'
      }
    };

    // Create the execution plan
    return {
      planId: `plan_${Date.now()}`,
      targetContext,
      steps: [executionStep],
      parallelGroups: [[]],
      dependencies: {},
      retryPolicy: {
        maxRetries: 3,
        backoffStrategy: 'exponential',
        backoffInterval: 1000, // 1 second
        retryConditions: [{
          statusCode: [500, 502, 503, 504],
          errorPatterns: ['timeout', 'connection refused'],
          shouldRetry: (error: Error, attempt: number) => {
            return attempt < 3;
          },
          metadata: {}
        }],
        metadata: {}
      },
      timeout: 300000, // 5 minutes
      metadata: {
        profileId: assessmentProfile.id,
        targetUrl: targetContext.targetUrl
      }
    };
  }

  /**
   * Executes the plan using the new architecture
   */
  private async executePlan(executionPlan: ExecutionPlan): Promise<RawExecutionOutput> {
    // Get the first step to execute
    const step = executionPlan.steps[0];
    if (!step) {
      throw new Error('No execution steps found in plan');
    }
    
    // Get the Subfinder adapter
    const adapter = this.registry.get('subfinder');
    if (!adapter) {
      throw new Error('Subfinder adapter not found in registry');
    }

    // Prepare the executable command using the adapter
    const executableCommand = adapter.prepare(step, executionPlan.targetContext);
    
    // Build command string from executable command
    const commandString = `${executableCommand.binary} ${executableCommand.args.join(' ')}`;
    
    // Import and use the existing runCliCommand function
    const { runCliCommand } = await import('../scanner/cliRunner');
    
    // Execute the command and capture output
    const startTime = new Date();
    let stdout = '';
    let stderr = '';
    let exitCode = 0;
    
    try {
      // For the proof of concept, we'll simulate execution or use the actual function
      stdout = await runCliCommand(commandString, executionPlan.targetContext.targetUrl);
    } catch (error) {
      stderr = error instanceof Error ? error.message : String(error);
      exitCode = 1;
    }
    
    const endTime = new Date();
    
    // Return a RawExecutionOutput object
    return {
      executionId: `exec_${Date.now()}`,
      toolId: 'subfinder',
      command: commandString,
      executableCommand,
      startTime,
      endTime,
      durationMs: endTime.getTime() - startTime.getTime(),
      exitCode,
      stdout,
      stderr,
      metadata: {
        stepId: step.stepId,
        profileId: step.profileId
      }
    };
  }

  /**
   * Parse raw results using the Subfinder parser
   */
  private parseResults(rawOutput: string, targetContext: TargetContext): any {
    // Parse the raw output to get structured results
    const parsedResult = this.parser.parse(rawOutput);
    
    // Update target in the result
    parsedResult.target = targetContext.targetUrl;
    
    return parsedResult;
  }

  /**
   * Transform scanner results to evidence
   */
  private transformToEvidence(scannerResult: any): EvidenceCollection {
    // Create evidence from scanner findings
    const evidenceItems = scannerResult.findings.map((finding: any) => ({
      evidenceId: `evidence_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      findingId: finding.id,
      sourceTool: 'subfinder',
      type: 'direct_confirmation' as const,
      data: finding.evidence,
      quality: finding.confidence || 0.8,
      timestamp: new Date(),
      metadata: {
        finding: finding,
        scannerResult: scannerResult.scanId
      }
    }));

    const evidenceCollection: EvidenceCollection = {
      findings: scannerResult.findings,
      evidenceItems,
      correlations: [],
      confidenceFactors: [],
      metadata: {
        scannerName: scannerResult.scannerName,
        scanId: scannerResult.scanId,
        findingCount: scannerResult.findings.length
      }
    };

    return evidenceCollection;
  }
}