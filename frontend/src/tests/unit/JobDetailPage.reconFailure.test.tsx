import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../components/ui/Skeleton', () => ({
  DetailSkeleton: () => <div data-testid="detail-skeleton">Loading...</div>,
}));
vi.mock('../../components/ui/ConfirmDialog', () => ({
  ConfirmDialog: () => null,
}));
vi.mock('../../components/StalledExplainerPanel', () => ({
  StalledExplainerPanel: () => null,
}));
vi.mock('../../components/ScanSummaryCard', () => ({
  ScanSummaryCard: () => null,
}));
vi.mock('../../components/IterationProgressBar', () => ({
  IterationProgressBar: () => null,
}));
vi.mock('../../components/PluginProgressGrid', () => ({
  PluginProgressGrid: () => null,
}));
vi.mock('../../components/DurationForecast', () => ({
  DurationForecast: () => null,
}));
vi.mock('../../components/charts/ModulePerformanceChart', () => ({
  ModulePerformanceChart: () => null,
}));
vi.mock('../../components/jobs/JobStatusHeader', () => ({
  JobStatusHeader: () => <div data-testid="job-status-header" />,
}));
vi.mock('../../components/jobs/JobLogViewer', () => ({
  JobLogViewer: () => <div data-testid="job-log-viewer" />,
}));
vi.mock('../../components/JobTimelineComponent', () => ({
  JobTimelineComponent: () => null,
}));
vi.mock('../../components/StageProgressBars', () => ({
  StageProgressBars: () => null,
}));

const useJobMonitorMock = vi.fn();
vi.mock('../../hooks/useJobMonitor', () => ({
  useJobMonitor: (...args: unknown[]) => useJobMonitorMock(...args),
}));

import { JobDetailPage } from '../../pages/JobDetailPage';

describe('JobDetailPage recon failure surfacing', () => {
  it('renders persistent recon failure card with stage and reason code', () => {
    useJobMonitorMock.mockReturnValue({
      job: {
        id: 'job-1',
        status: 'failed',
        base_url: 'https://example.com',
        hostname: 'example.com',
        target_name: 'example.com',
        mode: 'safe',
        stage: 'urls',
        stage_label: 'URL Collection',
        failed_stage: 'urls',
        failure_reason_code: 'fallback_only_urls',
        failure_step: 'src.recon.urls.collect_urls',
        failure_reason:
          'URL collection produced only fallback seed URLs and no discovery-source URLs.',
        progress_percent: 56,
        has_eta: false,
        eta_label: '',
        stalled: false,
        started_at: '2026-04-08T12:00:00Z',
        latest_logs: [],
        error: '',
        warnings: [],
        warning_count: 0,
        enabled_modules: ['subfinder'],
        scope_entries: ['example.com'],
        status_message: 'Recon failed during URL collection',
        execution_options: {},
        stage_progress: [],
      },
      loading: false,
      error: null,
      allLogLines: [],
      pluginProgress: [],
      streamingFindings: [],
      sseError: null,
      wsFailed: false,
      durationForecast: null,
      durationLoading: false,
      isPollingFallback: false,
      connectionState: 'connected',
      sseState: 'connected',
      actionLoading: null,
      showConfirmStop: false,
      showConfirmRestart: false,
      setShowConfirmStop: vi.fn(),
      setShowConfirmRestart: vi.fn(),
      reconnect: vi.fn(),
      refetch: vi.fn(),
      stopJob: vi.fn(),
      executeStop: vi.fn(),
      restartJob: vi.fn(),
      executeRestart: vi.fn(),
      clearSseError: vi.fn(),
    });

    render(
      <MemoryRouter initialEntries={['/jobs/job-1']}>
        <Routes>
          <Route path="/jobs/:jobId" element={<JobDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByRole('heading', { name: /Recon Failure/i })).toBeInTheDocument();
    expect(screen.getByText('urls')).toBeInTheDocument();
    expect(screen.getByText('fallback_only_urls')).toBeInTheDocument();
    expect(screen.getByText('src.recon.urls.collect_urls')).toBeInTheDocument();
    expect(
      screen.getByText(/fallback seed URLs and no discovery-source URLs/i)
    ).toBeInTheDocument();
  });

  it('renders recon failure card for recon_validation failed stage', () => {
    useJobMonitorMock.mockReturnValue({
      job: {
        id: 'job-2',
        status: 'failed',
        base_url: 'https://example.com',
        hostname: 'example.com',
        target_name: 'example.com',
        mode: 'safe',
        stage: 'recon_validation',
        stage_label: 'Recon validation',
        failed_stage: 'recon_validation',
        failure_reason_code: 'pipeline_stage_failed',
        failure_step: 'pipeline.recon.guard',
        failure_reason: 'Pipeline finished recon without discoverable URLs.',
        progress_percent: 56,
        has_eta: false,
        eta_label: '',
        stalled: false,
        started_at: '2026-04-08T12:00:00Z',
        latest_logs: [],
        error: '',
        warnings: [],
        warning_count: 0,
        enabled_modules: ['subfinder'],
        scope_entries: ['example.com'],
        status_message: 'Recon validation failed',
        execution_options: {},
        stage_progress: [],
      },
      loading: false,
      error: null,
      allLogLines: [],
      pluginProgress: [],
      streamingFindings: [],
      sseError: null,
      wsFailed: false,
      durationForecast: null,
      durationLoading: false,
      isPollingFallback: false,
      connectionState: 'connected',
      sseState: 'connected',
      actionLoading: null,
      showConfirmStop: false,
      showConfirmRestart: false,
      setShowConfirmStop: vi.fn(),
      setShowConfirmRestart: vi.fn(),
      reconnect: vi.fn(),
      refetch: vi.fn(),
      stopJob: vi.fn(),
      executeStop: vi.fn(),
      restartJob: vi.fn(),
      executeRestart: vi.fn(),
      clearSseError: vi.fn(),
    });

    render(
      <MemoryRouter initialEntries={['/jobs/job-2']}>
        <Routes>
          <Route path="/jobs/:jobId" element={<JobDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByRole('heading', { name: /Recon Failure/i })).toBeInTheDocument();
    expect(screen.getByText('recon_validation')).toBeInTheDocument();
    expect(screen.getByText('pipeline_stage_failed')).toBeInTheDocument();
    expect(screen.getByText('pipeline.recon.guard')).toBeInTheDocument();
  });

  it('surfaces degraded providers and timeout telemetry in runtime signals', () => {
    useJobMonitorMock.mockReturnValue({
      job: {
        id: 'job-3',
        status: 'failed',
        base_url: 'https://example.com',
        hostname: 'example.com',
        target_name: 'example.com',
        mode: 'safe',
        stage: 'access_control',
        stage_label: 'Access Control',
        failed_stage: 'access_control',
        failure_reason_code: 'pipeline_interrupted',
        failure_step: 'pipeline.access_control',
        failure_reason: 'Running automated authorization bypass detection',
        progress_percent: 92,
        has_eta: false,
        eta_label: '',
        stalled: false,
        started_at: '2026-04-08T12:00:00Z',
        latest_logs: [],
        error: '',
        warnings: [],
        warning_count: 13,
        fatal_signal_count: 2,
        degraded_providers: ['gau', 'waybackurls'],
        timeout_events: [
          "Provider 'gau' timed out after 12 seconds",
          "Provider 'waybackurls' timed out after 12 seconds",
        ],
        effective_timeout_seconds: 12,
        enabled_modules: ['subfinder'],
        scope_entries: ['example.com'],
        status_message: 'Access control stage interrupted',
        execution_options: {},
        stage_progress: [],
      },
      loading: false,
      error: null,
      allLogLines: [],
      pluginProgress: [],
      streamingFindings: [],
      sseError: null,
      wsFailed: false,
      durationForecast: null,
      durationLoading: false,
      isPollingFallback: false,
      connectionState: 'connected',
      sseState: 'connected',
      actionLoading: null,
      showConfirmStop: false,
      showConfirmRestart: false,
      setShowConfirmStop: vi.fn(),
      setShowConfirmRestart: vi.fn(),
      reconnect: vi.fn(),
      refetch: vi.fn(),
      stopJob: vi.fn(),
      executeStop: vi.fn(),
      restartJob: vi.fn(),
      executeRestart: vi.fn(),
      clearSseError: vi.fn(),
    });

    render(
      <MemoryRouter initialEntries={['/jobs/job-3']}>
        <Routes>
          <Route path="/jobs/:jobId" element={<JobDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    const runtimeSignalsCard = screen
      .getByRole('heading', { name: /Runtime Signals/i })
      .closest('.card');

    expect(runtimeSignalsCard).not.toBeNull();
    expect(within(runtimeSignalsCard as HTMLElement).getByText('13')).toBeInTheDocument();
    expect(within(runtimeSignalsCard as HTMLElement).getByText('Fatal Signals:')).toBeInTheDocument();
    expect(within(runtimeSignalsCard as HTMLElement).getByText('12s')).toBeInTheDocument();
    expect(within(runtimeSignalsCard as HTMLElement).getByText('Degraded Providers')).toBeInTheDocument();
    expect(within(runtimeSignalsCard as HTMLElement).getByText('Timeout Events')).toBeInTheDocument();
    expect(within(runtimeSignalsCard as HTMLElement).getByText('gau')).toBeInTheDocument();
    expect(within(runtimeSignalsCard as HTMLElement).getByText('waybackurls')).toBeInTheDocument();
    expect(
      within(runtimeSignalsCard as HTMLElement).getByText(/Provider 'gau' timed out after 12 seconds/i)
    ).toBeInTheDocument();
    expect(
      within(runtimeSignalsCard as HTMLElement).getByText(/Provider 'waybackurls' timed out after 12 seconds/i)
    ).toBeInTheDocument();
  });
});
