import type { ToolAdapter } from '../adapters/ToolAdapter';
import type { Parser } from '../parsers/Parser';

export interface ToolRequirements {
  binary: string;
  supportedPlatforms?: NodeJS.Platform[];
}

export interface ToolMetadata {
  name: string;
  version: string;
  description: string;
}

export interface ToolDefinition {
  capability: string;
  adapter: ToolAdapter;
  parser: Parser;
  requirements: ToolRequirements;
  metadata: ToolMetadata;
  priority: number;
}
