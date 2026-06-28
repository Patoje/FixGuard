import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  schema: './src/v2/storage/postgres/schema.ts',
  out: './drizzle-v2',
  dialect: 'postgresql'
});
