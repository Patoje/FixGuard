/**
 * Milestone P4-2 — Technology Fingerprint Contracts
 *
 * Defines typed technology categories, detected technology models with confidence
 * and deterministic signals, and synthesized ecosystem profiles.
 */

export type TechnologyCategory =
  | 'cms'
  | 'framework'
  | 'frontend'
  | 'runtime'
  | 'server'
  | 'cdn'
  | 'database'
  | 'security'
  | 'unknown';

export interface DetectedTechnology {
  readonly name: string;
  readonly version?: string;
  readonly category: TechnologyCategory;
  readonly confidence: 'high' | 'medium' | 'low';
  readonly detectionSignal: string;
  readonly cpeIdentifier?: string;
}

export interface TechEcosystemProfile {
  readonly hasSpa: boolean;
  readonly spaFramework?: 'react' | 'vue' | 'angular' | 'nextjs' | 'nuxtjs' | 'unknown';
  readonly hasCms: boolean;
  readonly cmsType?: 'wordpress' | 'joomla' | 'drupal' | 'unknown';
  readonly hasGraphQL: boolean;
  readonly hasPhpLegacy: boolean;
  readonly hasExposedSourcemaps: boolean;
}

export interface TechnologyFingerprintInput {
  readonly url?: string;
  readonly headers?: Readonly<Record<string, string | string[] | undefined>>;
  readonly bodyText?: string;
  readonly rawObservations?: readonly unknown[];
}

export interface TechnologyFingerprintResult {
  readonly technologies: readonly DetectedTechnology[];
  readonly ecosystemProfile: TechEcosystemProfile;
}
