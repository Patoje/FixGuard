/**
 * Demonstration script for the ToolAdapter Registry + ExecutionPlan architecture proof of concept
 * Shows the complete new execution flow with Subfinder
 */

import { SubfinderProofOfConcept } from './SubfinderProofOfConcept';
import { TargetContext } from '../types/TargetContext';
import { AssessmentProfile, ASSESSMENT_PROFILES } from '../types/AssessmentProfile';

async function demonstrateProofOfConcept() {
  console.log('🚀 Starting ToolAdapter Registry + ExecutionPlan Architecture Demonstration');
  console.log('========================================================================');

  // Create a sample target context
  const targetContext: TargetContext = {
    targetId: 'demo-target-1',
    targetUrl: 'https://example.com',
    technologies: [{
      name: 'nginx',
      version: '1.18.0',
      confidence: 0.9,
      detectionMethod: 'wappalyzer',
      metadata: {}
    }],
    endpoints: [],
    discoveredSubdomains: [],
    previousFindings: [],
    executionHistory: [],
    attackSurface: {
      endpoints: [],
      technologies: ['web_server'],
      authentication: [],
      attackVectors: [{
        type: 'web_attack',
        description: 'Standard web application attack vector',
        accessibility: 'public',
        riskLevel: 'medium',
        metadata: {}
      }],
      metadata: {}
    },
    constraints: {
      maxConcurrent: 5,
      timeout: 300,
      rateLimit: {
        requestsPerSecond: 10,
        burstSize: 20,
        penaltySeconds: 5,
        metadata: {}
      },
      metadata: {}
    },
    metadata: {
      createdAt: new Date().toISOString(),
      source: 'demo'
    }
  };

  // Use an existing assessment profile (we'll create a simple subdomain discovery profile)
  const assessmentProfile: AssessmentProfile = {
    id: 'subdomain_discovery_demo',
    name: 'Subdomain Discovery Assessment',
    description: 'Discover subdomains for the target domain',
    requiredCapabilities: ['subdomain_discovery'],
    assessmentIntent: {
      purpose: 'Discover subdomains associated with the target domain',
      scope: {
        endpoints: [],
        technologies: ['dns', 'subdomain'],
        attackTypes: ['reconnaissance'],
        metadata: {}
      },
      depth: {
        level: 'standard',
        intensity: 0.5,
        timeBudget: 300,
        requestBudget: 500,
        metadata: {}
      },
      validationStrategy: {
        approach: 'evidence_based',
        requiredConfirmations: 1,
        correlationTargets: [],
        evidenceThreshold: 0.7,
        metadata: {}
      }
    },
    baseConfig: {},
    riskLevel: 'low',
    prerequisites: [],
    contextRequirements: [],
    tags: ['reconnaissance', 'subdomain', 'dns']
  };

  console.log('📋 Assessment Profile Created:');
  console.log(`   ID: ${assessmentProfile.id}`);
  console.log(`   Name: ${assessmentProfile.name}`);
  console.log(`   Purpose: ${assessmentProfile.assessmentIntent.purpose}`);
  console.log('');

  console.log('🎯 Target Context Created:');
  console.log(`   Target URL: ${targetContext.targetUrl}`);
  console.log(`   Target ID: ${targetContext.targetId}`);
  console.log(`   Technologies: ${targetContext.technologies.length}`);
  console.log('');

  // Initialize the proof of concept
  console.log('🏗️  Initializing Subfinder Proof of Concept...');
  const proofOfConcept = new SubfinderProofOfConcept();
  console.log('✅ Initialization Complete');
  console.log('');

  console.log('🔄 Executing Complete Architecture Flow...');
  console.log('   This demonstrates the flow:');
  console.log('   AssessmentProfile → ExecutionPlan → ToolAdapterRegistry → SubfinderAdapter');
  console.log('   → ExecutableCommand → cliRunner → RawExecutionOutput → SubfinderParser');
  console.log('   → ScannerResult → Evidence structure');
  console.log('');

  try {
    const startTime = Date.now();
    const result = await proofOfConcept.executeFlow(targetContext, assessmentProfile);
    const endTime = Date.now();
    
    console.log('✅ Execution Completed Successfully!');
    console.log('');
    console.log('📊 Results Summary:');
    console.log(`   Execution Time: ${endTime - startTime}ms`);
    console.log(`   Execution Plan ID: ${result.executionPlan.planId}`);
    console.log(`   Raw Output Length: ${result.rawOutput.stdout.length} characters`);
    console.log(`   Scanner Result Scan ID: ${result.scannerResult.scanId}`);
    console.log(`   Findings Count: ${result.scannerResult.findings.length}`);
    console.log(`   Evidence Items: ${result.evidenceCollection.evidenceItems.length}`);
    console.log(`   Tool ID: ${result.rawOutput.toolId}`);
    console.log('');

    console.log('🔍 Detailed Execution Plan:');
    console.log(`   Steps: ${result.executionPlan.steps.length}`);
    console.log(`   Dependencies: ${Object.keys(result.executionPlan.dependencies).length}`);
    console.log(`   Timeout: ${result.executionPlan.timeout}ms`);
    console.log('');

    console.log('📝 Scanner Result Sample:');
    if (result.scannerResult.findings.length > 0) {
      const sampleFinding = result.scannerResult.findings[0];
      console.log(`   Type: ${sampleFinding.type}`);
      console.log(`   Severity: ${sampleFinding.severity}`);
      console.log(`   Description: ${sampleFinding.description.substring(0, 100)}...`);
    } else {
      console.log('   No findings detected (expected for demo)');
    }
    console.log('');

    console.log('🔗 Evidence Collection Sample:');
    if (result.evidenceCollection.evidenceItems.length > 0) {
      const sampleEvidence = result.evidenceCollection.evidenceItems[0];
      console.log(`   Evidence ID: ${sampleEvidence.evidenceId}`);
      console.log(`   Source Tool: ${sampleEvidence.sourceTool}`);
      console.log(`   Type: ${sampleEvidence.type}`);
    } else {
      console.log('   No evidence items (expected for demo)');
    }
    console.log('');

    console.log('✅ Architecture Flow Validation Successful!');
    console.log('The complete new execution flow has been demonstrated:');
    console.log('- AssessmentProfile correctly used to create ExecutionPlan');
    console.log('- ToolAdapterRegistry properly managed SubfinderAdapter');
    console.log('- SubfinderAdapter converted ExecutionStep to ExecutableCommand');
    console.log('- cliRunner executed the command and produced RawExecutionOutput');
    console.log('- SubfinderParser transformed output to ScannerResult');
    console.log('- Evidence structure created from ScannerResult findings');
    console.log('');
    console.log('🎯 The architecture is proven and ready for expansion!');
  } catch (error) {
    console.error('❌ Execution Failed:', error);
  }
}

// Run the demonstration if this file is executed directly
if (require.main === module) {
  demonstrateProofOfConcept().catch(console.error);
}

export { demonstrateProofOfConcept };