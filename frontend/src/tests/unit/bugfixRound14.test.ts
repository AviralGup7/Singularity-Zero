import { describe, expect, it } from 'vitest';
import { displayNumericOrNA } from '@/utils/displayValue';
import { offlineRetryDelayMs } from '@/utils/offlineQueuePolicy';
import { parseFindingTimestamp } from '@/utils/findingTime';

describe('numeric display', () => {
  it('keeps a real zero instead of N/A', () => {
    expect(displayNumericOrNA(0)).toBe('0');
    expect(displayNumericOrNA(undefined)).toBe('N/A');
    expect(displayNumericOrNA(Number.NaN)).toBe('N/A');
  });
});

describe('offline retry backoff', () => {
  it('grows then caps', () => {
    expect(offlineRetryDelayMs(1)).toBe(500);
    expect(offlineRetryDelayMs(2)).toBe(1000);
    expect(offlineRetryDelayMs(20)).toBe(8000);
  });
});

describe('evidence timestamp', () => {
  it('does not treat millisecond stamps as seconds', () => {
    const ms = 1_700_000_000_000;
    expect(parseFindingTimestamp(ms)).toBe(ms);
  });
});
