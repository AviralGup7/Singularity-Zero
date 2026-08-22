import { pingLivenessForTimeSync } from '@/api/health';
import { parseFindingTimestamp } from '@/utils/findingTime';

let serverTimeOffset = 0; // offset in milliseconds: serverTime - clientTime

/**
 * Contacts the server's liveness health check to synchronize timestamps
 * and compute client-to-server clock skew.
 */
export async function synchronizeTime(): Promise<number> {
  // Playwright E2E bypass: do not sync time to avoid making real API calls to offline backend
  if (typeof window !== 'undefined' && window.navigator.userAgent.includes('Playwright')) {
    if (import.meta.env.DEV) console.info('[TimeSync] Bypassing time synchronization in Playwright environment');
    return serverTimeOffset;
  }

  try {
    const startTime = Date.now();
    const { timestamp } = await pingLivenessForTimeSync();
    const endTime = Date.now();

    if (timestamp) {
      const serverTime = new Date(timestamp).getTime();
      const latency = (endTime - startTime) / 2;
      serverTimeOffset = (serverTime + latency) - endTime;

      if (import.meta.env.DEV) console.info(`[TimeSync] Network Latency: ${latency}ms, Server Time Offset: ${serverTimeOffset}ms`);
    }
  } catch (error) {
    console.warn('[TimeSync] Synchronization sequence aborted, default to client time:', error);
  }
  return serverTimeOffset;
}

/**
 * Sanitizes and normalizes any epoch or ISO timestamp to the corrected server epoch milliseconds.
 */
export function normalizeTimestamp(timestamp: string | number): number {
  const tsMs = parseFindingTimestamp(timestamp);
  return tsMs + serverTimeOffset;
}

/**
 * Returns a human-readable relative time string (e.g. "2 min ago", "about 1 hour ago").
 * Falls back to the locale time string if the date is more than 24 hours old.
 */
export function formatRelativeDistance(diffMs: number): string | null {
  if (!Number.isFinite(diffMs)) return 'just now';
  if (diffMs < 0) return Math.abs(diffMs) < 5000 ? 'just now' : 'in a moment';
  const diffSec = Math.round(diffMs / 1000);
  if (diffSec < 5) return 'just now';
  if (diffSec < 60) return `${diffSec} sec ago`;
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `${diffMin} min ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `about ${diffHr} hr ago`;
  return null;
}

export function formatDistanceToNow(date: Date): string {
  const label = formatRelativeDistance(Date.now() - date.getTime());
  return label ?? date.toLocaleTimeString();
}
