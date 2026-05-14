/**
 * High-Performance Time Synchronization Utility
 * Eliminates 'Silent Time Flicker' by normalizing client timestamps to server time.
 */

let serverOffset = 0;

export const syncServerTime = (serverNowIso: string) => {
  const serverMs = new Date(serverNowIso).getTime();
  const clientMs = Date.now();
  serverOffset = serverMs - clientMs;
  
  if (Math.abs(serverOffset) > 1000) {
    console.info(`[TIME-SYNC] Normalized server drift: ${serverOffset}ms`);
  }
};

/**
 * Returns the current normalized server time in milliseconds.
 */
export const getServerNow = () => Date.now() + serverOffset;

/**
 * Normalizes a client-side timestamp to its probable server equivalent.
 */
export const toServerTime = (clientMs: number) => clientMs + serverOffset;

/**
 * Normalizes a server-side timestamp for display relative to other server events.
 */
export const fromServerTime = (serverMs: number) => serverMs - serverOffset;
