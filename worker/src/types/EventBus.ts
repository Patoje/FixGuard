/**
 * EventBus.ts
 * 
 * Contract for event-based communication between components in the ToolAdapter architecture.
 * This enables loose coupling between the intelligence layer (which makes decisions)
 * and the execution layer (which performs actions).
 */

export interface Event {
  eventId: string;
  eventType: string;
  timestamp: Date;
  source: string;
  payload: any;
  metadata?: Record<string, any>;
}

export interface EventHandler<T extends Event = Event> {
  readonly eventType: string;
  handle(event: T): void | Promise<void>;
}

export interface EventBus {
  /**
   * Publish an event to all interested subscribers
   */
  publish(event: Event): void | Promise<void>;

  /**
   * Subscribe a handler to events of a specific type
   */
  subscribe<T extends Event>(handler: EventHandler<T>): void;

  /**
   * Unsubscribe a handler from events
   */
  unsubscribe<T extends Event>(handler: EventHandler<T>): void;

  /**
   * Get statistics about event processing
   */
  getStats(): EventBusStats;
}

export interface EventBusStats {
  publishedEvents: number;
  handledEvents: number;
  activeSubscriptions: number;
  eventTypes: string[];
}

/**
 * Predefined event types for the ToolAdapter architecture
 */
export const EVENT_TYPES = {
  // Execution events
  EXECUTION_STARTED: 'execution.started',
  EXECUTION_COMPLETED: 'execution.completed',
  EXECUTION_FAILED: 'execution.failed',
  EXECUTION_OUTPUT: 'execution.output',
  
  // Assessment events
  ASSESSMENT_STARTED: 'assessment.started',
  ASSESSMENT_COMPLETED: 'assessment.completed',
  ASSESSMENT_FINDING: 'assessment.finding',
  
  // Tool adapter events
  TOOL_REGISTERED: 'tool.registered',
  TOOL_AVAILABLE: 'tool.available',
  TOOL_UNAVAILABLE: 'tool.unavailable',
  
  // Evidence events
  EVIDENCE_FOUND: 'evidence.found',
  EVIDENCE_CORRELATED: 'evidence.correlated',
  
  // Context events
  CONTEXT_UPDATED: 'context.updated',
  TARGET_DISCOVERED: 'target.discovered'
} as const;

export type EventType = typeof EVENT_TYPES[keyof typeof EVENT_TYPES];

/**
 * Simple implementation of EventBus for synchronous operations
 */
export class SyncEventBus implements EventBus {
  private handlers: Map<string, Set<EventHandler>> = new Map();
  private stats: EventBusStats = {
    publishedEvents: 0,
    handledEvents: 0,
    activeSubscriptions: 0,
    eventTypes: []
  };

  publish(event: Event): void {
    this.stats.publishedEvents++;
    
    const handlers = this.handlers.get(event.eventType);
    if (handlers) {
      for (const handler of handlers) {
        try {
          handler.handle(event);
          this.stats.handledEvents++;
        } catch (error) {
          console.error(`Error in event handler for ${event.eventType}:`, error);
        }
      }
    }
  }

  subscribe<T extends Event>(handler: EventHandler<T>): void {
    if (!this.handlers.has(handler.eventType)) {
      this.handlers.set(handler.eventType, new Set());
      this.stats.eventTypes.push(handler.eventType);
    }
    
    const handlers = this.handlers.get(handler.eventType)!;
    handlers.add(handler as EventHandler);
    this.stats.activeSubscriptions++;
  }

  unsubscribe<T extends Event>(handler: EventHandler<T>): void {
    const handlers = this.handlers.get(handler.eventType);
    if (handlers) {
      handlers.delete(handler as EventHandler);
      this.stats.activeSubscriptions--;
      
      if (handlers.size === 0) {
        this.handlers.delete(handler.eventType);
        this.stats.eventTypes = this.stats.eventTypes.filter(type => type !== handler.eventType);
      }
    }
  }

  getStats(): EventBusStats {
    return { ...this.stats };
  }
}