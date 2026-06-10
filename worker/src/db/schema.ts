import { pgTable, serial, text, timestamp, varchar, integer } from 'drizzle-orm/pg-core';

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
  createdAt: timestamp('created_at').defaultNow().notNull(),
  completedAt: timestamp('completed_at'),
});

export const vulnerabilities = pgTable('vulnerabilities', {
  id: serial('id').primaryKey(),
  scanId: integer('scan_id').references(() => scans.id).notNull(),
  type: varchar('type', { length: 100 }).notNull(),
  severity: varchar('severity', { length: 20 }).notNull(),
  description: text('description').notNull(),
  autoFixCode: text('auto_fix_code'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});
