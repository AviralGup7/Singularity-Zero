import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { Job, StageProgressEntry } from '../../types/api';
import { PipelineStageTimeline } from '../../components/PipelineStageTimeline';

vi.mock('@/hooks/useMotionPolicy', () => ({
  useMotionPolicy: () => ({
    policy: { allowGsap: false },
    strategy: { distance: 8, duration: 0.2, stagger: 0.05 },
  }),
}));

function stageEntry(
  stage: string,
   
  status: StageProgressEntry['status'],
  percent: number,
  label?: string
): StageProgressEntry {
  return {
    stage,
    stage_label: label ?? stage,
    status,
    processed: percent,
    total: 100,
    percent,
  };
}

function makeJob(overrides: Partial<Job> = {}): Job {
  return {
    id: 'job-1',
    status: 'running',
    base_url: 'https://example.com',
    hostname: 'example.com',
    target_name: 'example.com',
    mode: 'safe',
    stage: 'urls',
    stage_label: 'URL collection',
    progress_percent: 50,
    has_eta: false,
    eta_label: '',
    stalled: false,
    started_at: '2026-04-01T00:00:00Z',
    latest_logs: [],
    error: null,
    warnings: [],
    enabled_modules: [],
    scope_entries: [],
    status_message: 'running',
    execution_options: {},
    stage_progress: [],
    ...overrides,
  };
}

describe('PipelineStageTimeline stage contract', () => {
  it('shows semgrep and maps priority stage to ranking', () => {
    const jobs: Job[] = [
      makeJob({
        id: 'job-semgrep',
        stage: 'semgrep',
        stage_label: 'Static analysis',
   
        stage_progress: [stageEntry('semgrep', 'running', 22, 'Static analysis')],
      }),
      makeJob({
        id: 'job-priority',
        stage: 'priority',
        stage_label: 'Priority ranking',
   
        stage_progress: [stageEntry('priority', 'running', 67, 'Priority ranking')],
      }),
    ];

    render(<PipelineStageTimeline jobs={jobs} />);

    expect(screen.getByText('semgrep')).toBeInTheDocument();
    expect(screen.getByText('ranking')).toBeInTheDocument();
    expect(screen.queryByText('priority')).not.toBeInTheDocument();
  });
});
