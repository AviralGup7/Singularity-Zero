import { apiClient } from '@/api/client';

let serverTimeOffset = 0; // offset in milliseconds: serverTime - clientTime

/**
 * Contacts the server's liveness health check to synchronize timestamps
 * and compute client-to-server clock skew.
 */
export async function synchronizeTime(): Promise<number> {
  // Playwright E2E bypass: do not sync time to avoid making real API calls to offline backend
  if (typeof window !== 'undefined' && window.navigator.userAgent.includes('Playwright')) {
    console.info('[TimeSync] Bypassing time synchronization in Playwright environment');
    return serverTimeOffset;
  }

  try {
    const startTime = Date.now();
    const response = await apiClient.get<{ status: string; timestamp: string }>('/api/health/live');
    const endTime = Date.now();

    const serverTimestampStr = response.data?.timestamp;
    if (serverTimestampStr) {
      const serverTime = new Date(serverTimestampStr).getTime();
      const latency = (endTime - startTime) / 2;
      serverTimeOffset = (serverTime + latency) - endTime;

      console.info(`[TimeSync] Network Latency: ${latency}ms, Server Time Offset: ${serverTimeOffset}ms`);
    }
  } catch (error) {
    console.warn('[TimeSync] Synchronization sequence aborted, default to client time:', error);
  }
  return serverTimeOffset;
}

/**
 * Returns the current calculated clock skew offset.
 */
export function getServerTimeOffset(): number {
  return serverTimeOffset;
}

/**
 * Returns a client timestamp corrected to match backend time.
 */
export function getNormalizedTime(clientTime = Date.now()): number {
  return clientTime + serverTimeOffset;
}

/**
 * Sanitizes and normalizes any epoch or ISO timestamp to the corrected server epoch milliseconds.
 */
export function normalizeTimestamp(timestamp: string | number): number {
  const tsMs = typeof timestamp === 'number' ? timestamp * 1000 : Date.parse(timestamp);
  return tsMs + serverTimeOffset;
}
