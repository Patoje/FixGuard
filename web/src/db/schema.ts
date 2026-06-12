import { pgTable, serial, text, timestamp, varchar, integer, json } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

export const scans = pgTable('scans', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').references(() => users.id).notNull(),
  targetUrl: text('target_url').notNull(),
  status: varchar('status', { length: 50 }).notNull().default('pending'),
  mode: varchar('mode', { enum: ['passive', 'active', 'aggressive', 'targeted'] }).default('passive').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  completedAt: timestamp('completed_at'),
});

export const vulnerabilities = pgTable('vulnerabilities', {
  id: serial('id').primaryKey(),
  scanId: integer('scan_id').references(() => scans.id).notNull(),
  type: varchar('type', { length: 100 }).notNull(),
  severity: varchar('severity', { length: 20 }).notNull(),
  description: text('description').notNull(),
  metadata: json('metadata'),
  parentId: integer('parent_id').references((): any => vulnerabilities.id),
  autoFixCode: text('auto_fix_code'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

export const reconProfiles = pgTable('recon_profiles', {
  id: serial('id').primaryKey(),
  scanId: integer('scan_id').references(() => scans.id).notNull(),
  techStack: json('tech_stack').notNull(),
  attackSurface: json('attack_surface').notNull(),
  frameworkIntelligence: json('framework_intelligence').notNull(),
  architectureTree: json('architecture_tree').notNull(),
  businessDictionary: json('business_dictionary'),
  authIntelligence: json('auth_intelligence'),
  cloudIntelligence: json('cloud_intelligence'),
  communicationIntelligence: json('communication_intelligence'),
  subdomainIntelligence: json('subdomain_intelligence'),
  artifactIntelligence: json('artifact_intelligence'),
  parameterIntelligence: json('parameter_intelligence'),
  serverActionsIntelligence: json('server_actions_intelligence'),
  aiIntelligence: json('ai_intelligence'),
  runtimeIntelligence: json('runtime_intelligence'),
  entityGraph: json('entity_graph'),
  auditReport: json('audit_report'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});
