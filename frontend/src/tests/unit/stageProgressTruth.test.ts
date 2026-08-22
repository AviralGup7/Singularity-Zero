import { describe, expect, it } from 'vitest';
import type { Job, StageProgressEntry } from '../../types/api';
import { processJobMonitorSseEvent } from '../../hooks/useJobMonitorSse';
import {
  normalizeActiveTimeline,
  normalizeStageEntry,
} from '../../hooks/useJobMonitorUtils';
import { buildStageTheaterNodesFromJob } from '../../lib/stageTheaterUtils';

function entry(stage: string, status: StageProgressEntry['status'], percent = 0): StageProgressEntry {
  return {
    stage,
    stage_label: stage,
    status,
    processed: percent,
    total: 100,
    percent,
  };
}

describe('stage progress remains a DAG, not a linear baton', () => {
  it('does not complete earlier running siblings when job.stage advances', () => {
    const entries = [
      entry('active_scan', 'running', 40),
      entry('semgrep', 'running', 20),
      entry('nuclei', 'running', 55),
    ];
    const next = normalizeActiveTimeline(entries, 'nuclei', 'running');
    expect(next.find((item) => item.stage === 'active_scan')?.status).toBe('running');
    expect(next.find((item) => item.stage === 'semgrep')?.status).toBe('running');
    expect(next.find((item) => item.stage === 'nuclei')?.status).toBe('running');
  });

  it('does not wipe later completed or failed stages back to pending', () => {
    const entries = [
      entry('urls', 'running', 10),
      entry('nuclei', 'completed', 100),
      entry('semgrep', 'error', 30),
    ];
    const next = normalizeActiveTimeline(entries, 'urls', 'running');
    expect(next.find((item) => item.stage === 'nuclei')?.status).toBe('completed');
    expect(next.find((item) => item.stage === 'semgrep')?.status).toBe('error');
  });

  it('keeps ready distinct from running', () => {
    expect(normalizeStageEntry({ stage: 'live_hosts', status: 'ready' }).status).toBe('ready');
  });

  it('stage_change does not complete sibling running stages', () => {
    const stages = [entry('active_scan', 'running', 40), entry('nuclei', 'running', 10)];
    let nextStages = stages;
    processJobMonitorSseEvent(
      {
        id: 'evt-1',
        event_type: 'stage_change',
        job_id: 'job-1',
        timestamp: 1,
        data: { new_stage: 'nuclei', stage_label: 'Nuclei' },
      },
      {
        jobStage: 'active_scan',
        jobStatus: 'running',
        setStageProgress: (updater) => {
          nextStages = typeof updater === 'function' ? updater(nextStages) : updater;
        },
        setSseTelemetry: () => undefined,
        setJob: () => undefined,
        addPluginProgress: () => undefined,
        resetPluginProgress: () => undefined,
        addLogLine: () => undefined,
        handleStageProgress: () => undefined,
        setStreamingFindings: () => undefined,
        setSseError: () => undefined,
        loadData: () => undefined,
        toastError: () => undefined,
        lastErrorToastRef: { current: { key: '', ts: 0 } },
      },
    );
    expect(nextStages.find((item) => item.stage === 'active_scan')?.status).toBe('running');
  });

  it('theater still shows parallel running stages independently', () => {
    const job = {
      id: 'job-1',
      status: 'running',
      base_url: 'https://example.com',
      hostname: 'example.com',
      target_name: 'example.com',
      mode: 'safe',
      stage: 'nuclei',
      stage_label: 'Nuclei',
      progress_percent: 50,
      has_eta: false,
      eta_label: '',
      stalled: false,
      started_at: '2026-04-01T00:00:00Z',
      latest_logs: [],
      error: null,
      warnings: [],
      enabled_modules: ['subfinder', 'nuclei'],
      scope_entries: [],
      status_message: 'running',
      execution_options: {},
      stage_progress: [
        entry('active_scan', 'running', 40),
        entry('semgrep', 'skipped', 0),
        entry('nuclei', 'ready', 0),
      ],
    } as Job;
    const nodes = buildStageTheaterNodesFromJob(job);
    expect(nodes.find((node) => node.id === 'active_scan')?.status).toBe('running');
    expect(nodes.find((node) => node.id === 'semgrep')?.status).toBe('skipped');
    expect(nodes.find((node) => node.id === 'nuclei')?.status).toBe('ready');
  });
});
