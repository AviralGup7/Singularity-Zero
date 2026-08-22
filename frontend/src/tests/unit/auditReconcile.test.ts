import { describe, expect, it } from 'vitest';
import { AppSettingsSchema } from '@/api/schemas';
import {
  liveConnectionLabel,
  pickSlowestJob,
  selectJobsByStatus,
  summarizeJobStages,
} from '@/components/livePipelineStatus';
import type { Job } from '@/types/api';

function job(partial: Partial<Job> & Pick<Job, 'id' | 'status'>): Job {
  return {
    progress_percent: 0,
    stage: 'init',
    ...partial,
  } as Job;
}

describe('optional leftover UI stays behind settings', () => {
  it('keeps live pipeline status off until operators opt in', () => {
    const settings = AppSettingsSchema.parse({});
    expect(settings.features.livePipelineStatus).toBe(false);
    expect(settings.features.clientPerformance).toBe(false);
  });
});

describe('live pipeline status helpers', () => {
  it('separates running and failed jobs without treating empty lists as running', () => {
    const jobs = [
      job({ id: 'a', status: 'running', stage: 'analysis', progress_percent: 40 }),
      job({ id: 'b', status: 'failed', stage: 'recon', progress_percent: 10 }),
      job({ id: 'c', status: 'running', stage: 'analysis', progress_percent: 12 }),
    ];
    expect(selectJobsByStatus(jobs, 'running').map((item) => item.id)).toEqual(['a', 'c']);
    expect(selectJobsByStatus(undefined, 'running')).toEqual([]);
    expect(pickSlowestJob(selectJobsByStatus(jobs, 'running'))?.id).toBe('c');
  });

  it('summarizes stages by active count and labels polling vs live', () => {
    const running = [
      job({ id: 'a', status: 'running', stage: 'analysis', progress_percent: 80 }),
      job({ id: 'b', status: 'running', stage: 'analysis', progress_percent: 20 }),
      job({ id: 'c', status: 'running', stage: 'recon', progress_percent: 5 }),
    ];
    const summary = summarizeJobStages(running, 2);
    expect(summary.map(([stage, info]) => [stage, info.count, info.maxPercent])).toEqual([
      ['analysis', 2, 80],
      ['recon', 1, 5],
    ]);
    expect(liveConnectionLabel('connected', false)).toBe('Live');
    expect(liveConnectionLabel('connected', true)).toBe('Polling');
    expect(liveConnectionLabel('mystery', false)).toBe('Unknown');
  });
});
