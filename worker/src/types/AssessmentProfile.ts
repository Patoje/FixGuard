/**
 * AssessmentProfile - Declarative definition of an assessment intention
 * Represents "what to evaluate", not "how to execute"
 */

export interface AssessmentProfile {
  id: string;
  name: string;
  description: string;
  requiredCapabilities: string[]; // e.g., ['http_fuzzer', 'sqli_tester', 'xss_scanner']
  assessmentIntent: AssessmentIntent;
  baseConfig: Record<string, any>;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  prerequisites: string[]; // e.g., ['target_has_database', 'csrf_token_available']
  contextRequirements: string[]; // e.g., ['database_detected', 'auth_required']
  tags: string[]; // e.g., ['modern_web', 'legacy_app', 'spa']
}

export interface AssessmentIntent {
  purpose: string; // "Detect SQL Injection vulnerabilities"
  scope: AssessmentScope;
  depth: AssessmentDepth;
  validationStrategy: ValidationStrategy;
}

export interface AssessmentScope {
  endpoints: string[]; // specific endpoints to test
  technologies: string[]; // technologies to focus on
  attackTypes: string[]; // types of attacks to perform
  metadata: Record<string, any>;
}

export interface AssessmentDepth {
  level: 'quick' | 'standard' | 'deep' | 'comprehensive';
  intensity: number; // 0.0 - 1.0
  timeBudget: number; // in seconds
  requestBudget: number; // max requests allowed
  metadata: Record<string, any>;
}

export interface ValidationStrategy {
  approach: 'single_confirm' | 'multi_confirm' | 'correlation_based' | 'evidence_based';
  requiredConfirmations: number;
  correlationTargets: string[]; // other assessments that can confirm this
  evidenceThreshold: number; // minimum evidence needed
  metadata: Record<string, any>;
}

// Predefined assessment profile templates
export const ASSESSMENT_PROFILES = {
  SQL_INJECTION: {
    id: 'sql_injection',
    name: 'SQL Injection Assessment',
    description: 'Detect SQL injection vulnerabilities across application endpoints',
    requiredCapabilities: ['http_fuzzer', 'sqli_tester'],
    assessmentIntent: {
      purpose: 'Detect SQL Injection vulnerabilities',
      scope: {
        endpoints: [],
        technologies: ['database'],
        attackTypes: ['sqli'],
        metadata: {}
      },
      depth: {
        level: 'standard',
        intensity: 0.7,
        timeBudget: 300,
        requestBudget: 1000,
        metadata: {}
      },
      validationStrategy: {
        approach: 'evidence_based',
        requiredConfirmations: 1,
        correlationTargets: [],
        evidenceThreshold: 0.8,
        metadata: {}
      }
    },
    baseConfig: {},
    riskLevel: 'high',
    prerequisites: ['target_has_database'],
    contextRequirements: [],
    tags: ['database', 'input_validation', 'web_application'],
  } as AssessmentProfile,
  
  CROSS_SITE_SCRIPTING: {
    id: 'xss',
    name: 'Cross-Site Scripting Assessment',
    description: 'Detect XSS vulnerabilities across application endpoints',
    requiredCapabilities: ['http_fuzzer', 'xss_scanner'],
    assessmentIntent: {
      purpose: 'Detect Cross-Site Scripting vulnerabilities',
      scope: {
        endpoints: [],
        technologies: ['web_application'],
        attackTypes: ['xss'],
        metadata: {}
      },
      depth: {
        level: 'standard',
        intensity: 0.7,
        timeBudget: 300,
        requestBudget: 1000,
        metadata: {}
      },
      validationStrategy: {
        approach: 'evidence_based',
        requiredConfirmations: 1,
        correlationTargets: [],
        evidenceThreshold: 0.8,
        metadata: {}
      }
    },
    baseConfig: {},
    riskLevel: 'high',
    prerequisites: [],
    contextRequirements: [],
    tags: ['client_side', 'input_validation', 'web_application'],
  } as AssessmentProfile,
  
  COMMAND_INJECTION: {
    id: 'cmd_injection',
    name: 'Command Injection Assessment',
    description: 'Detect command injection vulnerabilities in server-side operations',
    requiredCapabilities: ['http_fuzzer', 'cmd_injector'],
    assessmentIntent: {
      purpose: 'Detect Command Injection vulnerabilities',
      scope: {
        endpoints: [],
        technologies: ['server_side'],
        attackTypes: ['cmd_injection'],
        metadata: {}
      },
      depth: {
        level: 'standard',
        intensity: 0.8,
        timeBudget: 400,
        requestBudget: 1200,
        metadata: {}
      },
      validationStrategy: {
        approach: 'evidence_based',
        requiredConfirmations: 1,
        correlationTargets: [],
        evidenceThreshold: 0.85,
        metadata: {}
      }
    },
    baseConfig: {},
    riskLevel: 'critical',
    prerequisites: ['target_runs_commands'],
    contextRequirements: [],
    tags: ['server_side', 'command_execution', 'web_application'],
  } as AssessmentProfile,
  
  PATH_TRAVERSAL: {
    id: 'path_traversal',
    name: 'Path Traversal Assessment',
    description: 'Detect path traversal vulnerabilities in file access operations',
    requiredCapabilities: ['http_fuzzer', 'path_traversal_tester'],
    assessmentIntent: {
      purpose: 'Detect Path Traversal vulnerabilities',
      scope: {
        endpoints: [],
        technologies: ['file_access'],
        attackTypes: ['path_traversal'],
        metadata: {}
      },
      depth: {
        level: 'standard',
        intensity: 0.6,
        timeBudget: 200,
        requestBudget: 800,
        metadata: {}
      },
      validationStrategy: {
        approach: 'evidence_based',
        requiredConfirmations: 1,
        correlationTargets: [],
        evidenceThreshold: 0.75,
        metadata: {}
      }
    },
    baseConfig: {},
    riskLevel: 'high',
    prerequisites: [],
    contextRequirements: [],
    tags: ['file_access', 'input_validation', 'web_application'],
  } as AssessmentProfile,
};