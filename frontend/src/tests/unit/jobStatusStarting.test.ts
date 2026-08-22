import { describe, expect, it } from 'vitest';
import { canonicalizeJobStatus } from '@/api/contract';
import { shouldPollJob } from '@/hooks/useJobMonitor';

describe('starting/stopping stay pollable', () => {
  it('does not collapse starting or stopping to queued', () => {
    expect(canonicalizeJobStatus('starting')).toBe('starting');
    expect(canonicalizeJobStatus('stopping')).toBe('stopping');
    expect(canonicalizeJobStatus('running')).toBe('running');
  });

  it('polls starting and stopping so the first window is not stalled', () => {
    expect(shouldPollJob('starting')).toBe(true);
    expect(shouldPollJob('stopping')).toBe(true);
    expect(shouldPollJob('running')).toBe(true);
    expect(shouldPollJob('queued')).toBe(false);
    expect(shouldPollJob('completed')).toBe(false);
  });
});
