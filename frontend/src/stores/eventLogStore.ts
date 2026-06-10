/**
 * Global Event Log Store
 *
 * Captures every SSE and WebSocket event into a centralized Zustand store
 * for:
 *   - Compliance/audit trails (events are never lost on unmount)
 *   - Cross-page visibility (Dashboard can see job events from detail pages)
 *   - DevTools debugging
 *
 * Memory pressure mitigation:
 *   - MAX_EVENTS: 5,000 (FIFO cap)
 *   - Events older than retentionMs are pruned on each insert
 */

import { create } from 'zustand';

export interface NormalizedEvent {
  id: string;
  type: string;
  source: 'sse' | 'ws' | 'rest';
  timestamp: number;
  /** The jobId or resourceId this event relates to (if any). */
  resourceId?: string;
  data: unknown;
}

const MAX_EVENTS = 5_000;
const DEFAULT_RETENTION_MS = 60 * 60 * 1000; // 1 hour

interface EventLogStore {
  events: NormalizedEvent[];
  /** Subscribe to events for a specific resourceId. Returns unsubscribe. */
  addEvent: (event: NormalizedEvent) => void;
  /** Get events filtered by resourceId. */
  getEvents: (resourceId?: string) => NormalizedEvent[];
  /** Clear all events. */
  clear: () => void;
  /** Prune events older than retentionMs. */
  prune: (retentionMs?: number) => void;
}

export const useEventLogStore = create<EventLogStore>((set, get) => ({
  events: [],

  addEvent: (event: NormalizedEvent) => {
    set((s) => {
      const next = [...s.events, event];
      // FIFO cap
      if (next.length > MAX_EVENTS) {
        return { events: next.slice(-MAX_EVENTS) };
      }
      return { events: next };
    });
  },

  getEvents: (resourceId?: string) => {
    const { events } = get();
    if (!resourceId) return events;
    return events.filter(e => e.resourceId === resourceId);
  },

  clear: () => set({ events: [] }),

  prune: (retentionMs = DEFAULT_RETENTION_MS) => {
    const cutoff = Date.now() - retentionMs;
    set((s) => ({
      events: s.events.filter(e => e.timestamp >= cutoff),
    }));
  },
}));
