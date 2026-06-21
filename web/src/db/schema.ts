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
  targetedVectorId: varchar('targeted_vector_id', { length: 100 }),
  parentScanId: integer('parent_scan_id'),
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
  workflowIntelligence: json('workflow_intelligence'),
  auditReport: json('audit_report'),
  smartVectors: json('smart_vectors'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

export const findings = pgTable('findings', {
  id: serial('id').primaryKey(),
  scanId: integer('scan_id').references(() => scans.id).notNull(),
  fingerprint: varchar('fingerprint', { length: 255 }).notNull().unique(),
  title: text('title').notNull(),
  severity: varchar('severity', { enum: ['critical', 'high', 'medium', 'low', 'info'] }).notNull(),
  status: varchar('status', { enum: ['open', 'accepted', 'fixed', 'false_positive'] }).notNull().default('open'),
  endpoint: text('endpoint'),
  method: varchar('method', { length: 10 }),
  requestRaw: text('request_raw'),
  responseRaw: text('response_raw'),
  payloadUsed: text('payload_used'),
  cweId: varchar('cwe_id', { length: 20 }),
  owaspCategory: varchar('owasp_category', { length: 100 }),
  toolSource: varchar('tool_source', { length: 50 }).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

export const authorizations = pgTable('authorizations', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').references(() => users.id).notNull(),
  targetDomain: varchar('target_domain', { length: 255 }).notNull(),
  authorizedAt: timestamp('authorized_at').defaultNow().notNull(),
  expiresAt: timestamp('expires_at'),
  signature: text('signature'),
});

export const sessions = pgTable('sessions', {
  id: serial('id').primaryKey(),
  targetUrl: text('target_url').notNull(),
  authType: varchar('auth_type', { enum: ['cookie', 'jwt', 'oauth'] }).notNull(),
  cookieHeader: text('cookie_header'),
  jwtToken: text('jwt_token'),
  loginFlow: json('login_flow'), // Para grabar secuencias de login
  isActive: varchar('is_active', { length: 1 }).default('1').notNull(), // '1' o '0' como booleano simple
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});
