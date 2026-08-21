export const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000;
export const WARNING_LEAD_MS = 2 * 60 * 1000;
export const MIN_TIMEOUT_MS = 60_000;
export const MIN_WARNING_AT_MS = 10_000;

export function resolveSessionTimeoutMs(timeoutMs: number | undefined): number {
  const requested = typeof timeoutMs === 'number' && Number.isFinite(timeoutMs) ? timeoutMs : DEFAULT_TIMEOUT_MS;
  return Math.max(MIN_TIMEOUT_MS, requested);
}

/** Keep the warning inside the timeout, and never more than 20% of the idle window. */
export function resolveSessionWarningAt(timeoutMs: number): number {
  const timeout = resolveSessionTimeoutMs(timeoutMs);
  const lead = Math.min(WARNING_LEAD_MS, Math.floor(timeout * 0.2));
  return Math.max(MIN_WARNING_AT_MS, timeout - lead);
}
