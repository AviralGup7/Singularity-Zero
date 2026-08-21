import { isRetryable } from './errors';

export interface RetryAdvice {
  retry: boolean;
  afterSeconds: number;
  reason: string;
}

export function adviceFor(code: string, attempt = 0, retryAfter?: number): RetryAdvice {
  if (!isRetryable(code)) {
    return { retry: false, afterSeconds: 0, reason: code };
  }
  if (attempt >= 4) {
    return { retry: false, afterSeconds: 0, reason: 'exhausted' };
  }
  const base = 0.4 * 2 ** attempt;
  const wait = retryAfter !== undefined ? retryAfter : Math.min(8, base);
  return { retry: true, afterSeconds: wait, reason: code };
}

export function parseRetryAfter(header: string | null | undefined): number | undefined {
  if (!header) return undefined;
  const value = Number(header);
  if (!Number.isFinite(value) || value < 0) return undefined;
  return Math.min(value, 60);
}

export async function sleep(seconds: number): Promise<void> {
  if (seconds <= 0) return;
  await new Promise((resolve) => {
    setTimeout(resolve, seconds * 1000);
  });
}
