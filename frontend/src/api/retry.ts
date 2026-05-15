const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1000;
const MAX_DELAY_MS = 30000;

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function calculateBackoff(attempt: number): number {
  const delay = BASE_DELAY_MS * Math.pow(2, attempt - 1);
  const jitter = Math.random() * 500;
  return Math.min(delay + jitter, MAX_DELAY_MS);
}

export function shouldRetry(error: unknown): boolean {
  const name = (error as { name?: string })?.name;
  const message = ((error as { message?: string })?.message || '').toLowerCase();
  if (name === 'CanceledError' || name === 'AbortError' || message === 'canceled' || message === 'abort') {
    return false;
  }

  const status =
    (error as { status?: number })?.status ??
    (error as { response?: { status?: number } })?.response?.status ??
    (error as { original?: { response?: { status?: number } } })?.original?.response?.status;
  if (status === 429) return true;
  if (status && status >= 500) return true;
  const response =
    (error as { response?: unknown })?.response ??
    (error as { original?: { response?: unknown } })?.original?.response;
  if (!response) return true;
  return false;
}

export function getRetryAfterMs(error: unknown): number | null {
  const response =
    (error as { response?: { headers?: Record<string, string> } })?.response ??
    (error as { original?: { response?: { headers?: Record<string, string> } } })?.original?.response;
  const retryAfter = response?.headers?.['retry-after'] ?? response?.headers?.['Retry-After'];
  if (retryAfter) {
    const seconds = parseInt(retryAfter, 10);
    if (!isNaN(seconds)) return seconds * 1000;
    const date = new Date(retryAfter);
    if (!isNaN(date.getTime())) return Math.max(0, date.getTime() - Date.now());
  }
  return null;
}

export async function withRetry<T>(fn: () => Promise<T>, attempt: number = 1): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    if (attempt >= MAX_RETRIES || !shouldRetry(error)) {
      throw error;
    }
    const retryAfterMs = getRetryAfterMs(error);
    const delay = retryAfterMs ?? calculateBackoff(attempt);
    await sleep(delay);
    return withRetry(fn, attempt + 1);
  }
}
