import { act, renderHook, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '../../components/Toast';

let sseEventHandler: ((event: Record<string, unknown>) => void) | undefined;

const getJobMock = vi.fn();
const getJobLogsMock = vi.fn();
const getHistoricalDurationsMock = vi.fn();

vi.mock('../../api/client', () => ({
  getJob: (...args: unknown[]) => getJobMock(...args),
  getJobLogs: (...args: unknown[]) => getJobLogsMock(...args),
  getHistoricalDurations: (...args: unknown[]) => getHistoricalDurationsMock(...args),
  stopJob: vi.fn(),
  restartJob: vi.fn(),
}));

vi.mock('../../hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    connectionState: 'connected',
    reconnect: vi.fn(),
    disconnect: vi.fn(),
  }),
}));

vi.mock('../../hooks/useSSEProgress', () => ({
  useSSEProgress: ({ onEvent }: { onEvent?: (event: Record<string, unknown>) => void }) => {
    sseEventHandler = onEvent;
    return {
      connectionState: 'connected',
      isPollingFallback: false,
      reconnect: vi.fn(),
      disconnect: vi.fn(),
      eventCount: 0,
      lastEvent: null,
    };
  },
}));

vi.mock('../../components/Toast', () => ({
  useToast: () => ({
    success: vi.fn(),
    error: vi.fn(),
    warning: vi.fn(),
    info: vi.fn(),
  }),
}));

import { useJobMonitor } from '../../hooks/useJobMonitor';

const baseJob = {
  id: 'job-1',
  status: 'running',
  base_url: 'https://example.com',
  hostname: 'example.com',
  target_name: 'example.com',
  mode: 'safe',
  stage: 'urls',
  stage_label: 'URL Collection',
  progress_percent: 56,
  has_eta: false,
  eta_label: '',
  stalled: false,
  started_at: '2026-04-08T12:00:00Z',
  latest_logs: [],
  error: '',
  warnings: [],
  enabled_modules: ['subfinder'],
  scope_entries: ['example.com'],
  status_message: 'Collecting URLs',
  execution_options: {},
  stage_progress: [],
};

describe('useJobMonitor recon failure terminal handling', () => {
  beforeEach(() => {
    sseEventHandler = undefined;
    getJobMock.mockReset();
    getJobLogsMock.mockReset();
    getHistoricalDurationsMock.mockReset();

    getJobMock.mockResolvedValue({ ...baseJob });
    getJobLogsMock.mockResolvedValue({ job_id: 'job-1', logs: [] });
    getHistoricalDurationsMock.mockResolvedValue([]);
  });

  it('keeps sseError after completed event with failed status', async () => {
    const { result } = renderHook(() => useJobMonitor('job-1'), {
      wrapper: ({ children }: { children: React.ReactNode }) => <ToastProvider>{children}</ToastProvider>,
    });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(sseEventHandler).toBeTypeOf('function');

    act(() => {
      sseEventHandler?.({
        event_type: 'error',
        id: 'evt-1',
        job_id: 'job-1',
        timestamp: Date.now(),
        data: { error: 'Recon failed at URLs' },
      });
    });

    await waitFor(() => expect(result.current.sseError).toBe('Recon failed at URLs'));

    act(() => {
      sseEventHandler?.({
        event_type: 'completed',
        id: 'evt-2',
        job_id: 'job-1',
        timestamp: Date.now(),
        data: { status: 'failed', failure_reason: 'Recon failed at URLs' },
      });
    });

    await waitFor(() => expect(result.current.sseError).toBe('Recon failed at URLs'));
  });

  it('does not clear sseError after completed event with stopped status', async () => {
    const { result } = renderHook(() => useJobMonitor('job-1'), {
      wrapper: ({ children }: { children: React.ReactNode }) => <ToastProvider>{children}</ToastProvider>,
    });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(sseEventHandler).toBeTypeOf('function');

    act(() => {
      sseEventHandler?.({
        event_type: 'error',
        id: 'evt-3',
        job_id: 'job-1',
        timestamp: Date.now(),
        data: { error: 'Recon failure remains visible' },
      });
    });

    await waitFor(() => expect(result.current.sseError).toBe('Recon failure remains visible'));

    act(() => {
      sseEventHandler?.({
        event_type: 'completed',
        id: 'evt-4',
        job_id: 'job-1',
        timestamp: Date.now(),
        data: { status: 'stopped', failure_reason: 'Run stopped after recon failure' },
      });
    });

    await waitFor(() => expect(result.current.sseError).toBe('Recon failure remains visible'));
  });
});
