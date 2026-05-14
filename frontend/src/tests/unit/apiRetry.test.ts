import { describe, expect, it } from 'vitest';
import { getRetryAfterMs, shouldRetry } from '../../api/retry';

describe('api retry helpers', () => {
  it('reads Retry-After from wrapped interceptor errors', () => {
    const wrapped429 = {
      status: 429,
      original: {
        response: {
          headers: {
            'retry-after': '7',
          },
        },
      },
    };

    expect(shouldRetry(wrapped429)).toBe(true);
    expect(getRetryAfterMs(wrapped429)).toBe(7000);
  });

  it('does not retry canceled requests', () => {
    const canceled = { name: 'CanceledError', message: 'canceled' };
    expect(shouldRetry(canceled)).toBe(false);
  });
});
