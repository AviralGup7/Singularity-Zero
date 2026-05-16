import { describe, expect, it } from 'vitest';
import type { Job, StageProgressEntry } from '../../types/api';
import {
  buildStageTheaterNodesFromJob,
  buildStageTheaterNodesFromJobs,
} from '../../lib/stageTheaterUtils';

function makeStageEntry(
  stage: string,
   
  status: StageProgressEntry['status'],
  percent: number,
  stageLabel?: string
): StageProgressEntry {
  return {
    stage,
    stage_label: stageLabel ?? stage,
    status,
    processed: Math.round(percent),
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

function getNode(ids: ReturnType<typeof buildStageTheaterNodesFromJob>, stageId: string) {
  return ids.find((node) => node.id === stageId);
}

describe('StageTheater stage contract', () => {
  it('surfaces modern pipeline stages including ranking, active_scan, semgrep, and validation', () => {
    const job = makeJob({
      stage: 'semgrep',
      stage_label: 'Static analysis (Semgrep)',
      stage_progress: [
        makeStageEntry('subdomains', 'completed', 100, 'Subdomain enumeration'),
        makeStageEntry('live_hosts', 'completed', 100, 'Live host probing'),
        makeStageEntry('urls', 'completed', 100, 'URL collection'),
        makeStageEntry('parameters', 'completed', 100, 'Parameter extraction'),
        makeStageEntry('ranking', 'completed', 100, 'Priority ranking'),
        makeStageEntry('passive_scan', 'completed', 100, 'Passive analysis'),
        makeStageEntry('active_scan', 'completed', 100, 'Active probing'),
        makeStageEntry('semgrep', 'running', 45, 'Static analysis (Semgrep)'),
      ],
    });

    const nodes = buildStageTheaterNodesFromJob(job);
    const stageIds = nodes.map((node) => node.id);

   
    expect(stageIds).toEqual(expect.arrayContaining(['ranking', 'active_scan', 'semgrep', 'validation']));
    expect(stageIds).not.toContain('priority');

    expect(getNode(nodes, 'semgrep')).toMatchObject({
      status: 'running',
      percent: 45,
      label: 'Static analysis (Semgrep)',
    });
  });

  it('maps legacy priority stage data onto ranking node', () => {
    const job = makeJob({
      stage: 'priority',
      stage_label: 'Priority ranking',
      stage_progress: [
        makeStageEntry('priority', 'running', 62, 'Priority ranking'),
      ],
    });

    const nodes = buildStageTheaterNodesFromJob(job);

    expect(nodes.some((node) => node.id === 'priority')).toBe(false);
    expect(getNode(nodes, 'ranking')).toMatchObject({
      status: 'running',
      label: 'Priority ranking',
      percent: 62,
    });
  });

  it('renders recon_validation failures as explicit error stage nodes', () => {
    const job = makeJob({
      status: 'failed',
      stage: 'recon_validation',
      stage_label: 'Recon validation',
      failed_stage: 'recon_validation',
      failure_reason: 'Pipeline finished recon without discoverable URLs.',
      progress_percent: 0,
      stage_progress: [],
    });

    const nodes = buildStageTheaterNodesFromJob(job);
    const stageIds = nodes.map((node) => node.id);

    expect(stageIds).toContain('recon_validation');
    expect(stageIds.indexOf('recon_validation')).toBeGreaterThan(stageIds.indexOf('urls'));
    expect(stageIds.indexOf('recon_validation')).toBeLessThan(stageIds.indexOf('parameters'));
    expect(getNode(nodes, 'recon_validation')).toMatchObject({
      status: 'error',
      label: 'Recon validation',
    });
  });

  it('aggregates alias and modern stage telemetry across jobs without creating duplicate priority node', () => {
    const jobs: Job[] = [
      makeJob({
        id: 'job-running-semgrep',
        stage: 'semgrep',
        stage_label: 'Static analysis (Semgrep)',
   
        stage_progress: [makeStageEntry('semgrep', 'running', 30, 'Static analysis (Semgrep)')],
      }),
      makeJob({
        id: 'job-failed-priority',
        status: 'failed',
        stage: 'priority',
        stage_label: 'Priority ranking',
        failed_stage: 'priority',
   
        stage_progress: [makeStageEntry('priority', 'error', 73, 'Priority ranking')],
      }),
    ];

    const nodes = buildStageTheaterNodesFromJobs(jobs);
    const ranking = nodes.find((node) => node.id === 'ranking');
    const semgrep = nodes.find((node) => node.id === 'semgrep');

    expect(nodes.some((node) => node.id === 'priority')).toBe(false);
    expect(ranking).toMatchObject({
      status: 'error',
      errorCount: 1,
    });
    expect(semgrep).toMatchObject({
      status: 'running',
      activeCount: 1,
    });
  });
});
