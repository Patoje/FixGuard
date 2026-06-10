import type { TechStackItem } from './TechStackProfiler';

export interface FrameworkVector {
  framework: string;
  vectors: string[];
}

export function runFrameworkIntelligence(techStack: TechStackItem[]): FrameworkVector[] {
  const intelligence: FrameworkVector[] = [];
  const stackNames = techStack.map(t => t.name.toLowerCase());

  if (stackNames.includes('next.js')) {
    intelligence.push({
      framework: 'Next.js',
      vectors: ['Server Actions (BFLA/IDOR)', 'Middleware bypass', 'API Routes exposure', 'Build Data (_next/data)', 'Static Assets', 'Incremental Static Regeneration cache poisoning', 'Route Handlers', 'Edge Functions mapping']
    });
  }

  if (stackNames.includes('react')) {
    intelligence.push({
      framework: 'React',
      vectors: ['Source Maps leak', 'Client Side Routing enumeration', 'Local Storage secrets', 'Session Storage secrets', 'DOM Injection Points (dangerouslySetInnerHTML)']
    });
  }

  if (stackNames.includes('node.js') || stackNames.includes('express')) {
    intelligence.push({
      framework: 'Node.js / Express',
      vectors: ['Express Route enumeration', 'Prototype Pollution', 'Uncaught Exceptions DOS', 'Regex DOS (ReDoS)']
    });
  }

  if (stackNames.includes('postgres') || stackNames.includes('postgresql') || stackNames.includes('neon')) {
    intelligence.push({
      framework: 'PostgreSQL',
      vectors: ['SQL Injection', 'Blind SQL Injection', 'Time Based SQL Injection', 'Connection String exposure', 'Role escalation']
    });
  }

  if (stackNames.includes('clerk')) {
    intelligence.push({
      framework: 'Clerk Auth',
      vectors: ['Session Token hijacking', 'OAuth bypass', 'JWT validation bypass', 'User Metadata manipulation']
    });
  }

  if (stackNames.includes('supabase')) {
    intelligence.push({
      framework: 'Supabase',
      vectors: ['Bucket enumeration', 'Realtime socket exposure', 'Row Level Security bypass', 'Edge Functions keys leak', 'Anon Key abuse']
    });
  }

  return intelligence;
}
