import { describe, expect, it } from 'vitest';
import { mapToVisualState, mapJobsToVisualState } from '@/lib/mapToVisualState';
import type { Job } from '@/types/api';

function buildJob(overrides: Partial<Job> = {}): Job {
  return {
    id: 'job-1',
    status: 'running',
    base_url: 'https://example.com',
    hostname: 'example.com',
    target_name: 'example.com',
    mode: 'idor',
    stage: 'subdomains',
    stage_label: 'Enumerating subdomains',
    progress_percent: 40,
    has_eta: false,
    eta_label: '',
    stalled: false,
    started_at: new Date().toISOString(),
    latest_logs: [],
    error: null,
    warnings: [],
    enabled_modules: [],
    scope_entries: [],
    status_message: '',
    execution_options: {},
    ...overrides,
  };
}

describe('mapToVisualState', () => {
  it('returns higher urgency for failed jobs', () => {
    const state = mapToVisualState(buildJob({ status: 'failed', failed_stage: 'subdomains' }));
    expect(state.urgency).toBeGreaterThan(0.9);
  });

  it('reduces confidence when sseError exists', () => {
    const withoutError = mapToVisualState(buildJob());
    const withError = mapToVisualState(buildJob(), { sseError: 'stream failed' });
    expect(withError.confidence).toBeLessThan(withoutError.confidence);
  });

  it('aggregates jobs visual state', () => {
    const state = mapJobsToVisualState([
      buildJob({ progress_percent: 20 }),
      buildJob({ status: 'failed', failed_stage: 'urls' }),
    ]);
    expect(state.urgency).toBeGreaterThan(0.8);
    expect(state.intensity).toBeGreaterThanOrEqual(0);
    expect(state.intensity).toBeLessThanOrEqual(1);
  });
});

