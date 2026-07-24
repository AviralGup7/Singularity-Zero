/**
 * Job Monitor Zustand Store
 *
 * Replaces the local `useReducer` in `useJobMonitor` with a global store
 * keyed by jobId. This means:
 *   - Navigating away from /jobs/:id and back preserves all state
 *   - Log lines, streaming findings, stage progress survive route changes
 *   - Multiple job detail pages can be open in different tabs (each keyed)
 *
 * Memory pressure mitigation:
 *   - getMaxLogLines(): 10,000 (FIFO cap)
 *   - getMaxStreamingFindings(): 5,000 (FIFO cap)
 *   - MAX_CACHED_JOBS: 10 (evicts oldest when exceeded)
 */

import { create } from 'zustand';
import { useDisplayStore } from './displayStore';

import type {
  Job,
  PluginProgressEntry,
  Finding,
  StageProgressEntry,
  ProgressTelemetry,
} from '../types/api';
import {
  mergeStageProgressLists,
  mergeTelemetry,
  normalizeActiveTimeline,
} from '../hooks/useJobMonitorUtils';
import type { DurationForecastData } from '../hooks/useJobMonitorReducer';

function getMaxLogLines(): number {
  return useDisplayStore.getState().display.constrainedDevice ? 5_000 : 10_000;
}

function getMaxStreamingFindings(): number {
  return useDisplayStore.getState().display.constrainedDevice ? 2_500 : 5_000;
}

const MAX_CACHED_JOBS = 10;

export interface JobMonitorState {
  /** The current job payload (null before first fetch). */
  job: Job | null;
  /** True while the initial job data is being fetched. */
  loading: boolean;
  /** Polling fetch error, if any. */
  error: string | null;
  /** Accumulated log lines (FIFO-capped). */
  allLogLines: string[];
  /** Per-plugin progress entries from telemetry. */
  pluginProgress: PluginProgressEntry[];
  /** Findings streamed in via SSE during a running scan. */
  streamingFindings: Finding[];
  /** SSE connection error message. */
  sseError: string | null;
  /** WebSocket connection failure flag. */
  wsFailed: boolean;
  /** ETA / duration forecast from telemetry. */
  durationForecast: DurationForecastData | null;
  /** True while fetching duration forecast. */
  durationLoading: boolean;
  /** Ordered list of stage progress entries for the timeline. */
  stageProgress: StageProgressEntry[];
  /** Raw telemetry key-value map streamed by the backend. */
  sseTelemetry: ProgressTelemetry;
  /** Loading state for action buttons (stop / restart). */
  actionLoading: string | null;
  /** Timestamp of the last state update (used for freshness gating). */
  lastUpdateTs: number;
}

type ActionSource = 'polling' | 'realtime';

type JobMonitorAction =
  | { type: 'START_LOADING' }
  | { type: 'SET_JOB_DATA'; payload: Job; logs?: string[]; source?: ActionSource }
  | { type: 'UPDATE_JOB'; payload: Partial<Job>; source?: ActionSource }
  | { type: 'ADD_LOG_LINE'; payload: string }
  | { type: 'ADD_PLUGIN_PROGRESS'; payload: PluginProgressEntry }
  | { type: 'RESET_PLUGIN_PROGRESS' }
  | { type: 'UPDATE_STAGE_PROGRESS'; payload: StageProgressEntry; source?: ActionSource }
  | { type: 'SET_STAGE_PROGRESS_LIST'; payload: StageProgressEntry[]; source?: ActionSource }
  | { type: 'UPDATE_TELEMETRY'; payload: Record<string, unknown>; source?: ActionSource }
  | { type: 'ADD_FINDINGS'; payload: Finding[] }
  | { type: 'SET_ERROR'; payload: string | null }
  | { type: 'SET_SSE_ERROR'; payload: string | null }
  | { type: 'SET_WS_FAILED'; payload: boolean }
  | { type: 'SET_DURATION_FORECAST'; payload: DurationForecastData | null; loading?: boolean }
  | { type: 'SET_ACTION_LOADING'; payload: string | null }
  | { type: 'RESET_STATE' };

const initialPerJobState: JobMonitorState = {
  job: null,
  loading: true,
  error: null,
  allLogLines: [],
  pluginProgress: [],
  streamingFindings: [],
  sseError: null,
  wsFailed: false,
  durationForecast: null,
  durationLoading: false,
  stageProgress: [],
  sseTelemetry: {},
  actionLoading: null,
  lastUpdateTs: 0,
};

function shouldAcceptUpdate(state: JobMonitorState, source: ActionSource | undefined): boolean {
  if (!source || source === 'realtime') return true;
  const FRESHNESS_THRESHOLD_MS = 2000;
  if (state.lastUpdateTs > 0 && (Date.now() - state.lastUpdateTs < FRESHNESS_THRESHOLD_MS)) {
    return false;
  }
  return true;
}

function reduceJobState(state: JobMonitorState, action: JobMonitorAction): JobMonitorState {
  const now = Date.now();

  switch (action.type) {
    case 'START_LOADING':
      return { ...state, loading: true };

    case 'SET_JOB_DATA': {
      if (!shouldAcceptUpdate(state, action.source)) return state;
      const job = action.payload;
      const logs = action.logs || [];
      return {
        ...state,
        job: {
          ...job,
          progress_telemetry: mergeTelemetry(state.job?.progress_telemetry, job.progress_telemetry),
        },
        loading: false,
        error: null,
        allLogLines: logs.length > 0
          ? [...state.allLogLines, ...logs].slice(-getMaxLogLines())
          : state.allLogLines,
        lastUpdateTs: now,
      };
    }

    case 'UPDATE_JOB':
      if (!state.job || !shouldAcceptUpdate(state, action.source)) return state;
      return {
        ...state,
        job: { ...state.job, ...action.payload },
        lastUpdateTs: now,
      };

    case 'ADD_LOG_LINE':
      return {
        ...state,
        allLogLines: [...state.allLogLines, action.payload].slice(-getMaxLogLines()),
        lastUpdateTs: now,
      };

    case 'ADD_PLUGIN_PROGRESS': {
      const entry = action.payload;
      const idx = state.pluginProgress.findIndex((p) => p.label === entry.label);
      const next = [...state.pluginProgress];
      if (idx >= 0) next.splice(idx, 1, entry);
      else next.push(entry);
      return { ...state, pluginProgress: next, lastUpdateTs: now };
    }

    case 'RESET_PLUGIN_PROGRESS':
      return { ...state, pluginProgress: [], lastUpdateTs: now };

    case 'UPDATE_STAGE_PROGRESS': {
      if (!shouldAcceptUpdate(state, action.source)) return state;
      const entry = action.payload;
      const idx = state.stageProgress.findIndex((s) => s.stage === entry.stage);
      const next = [...state.stageProgress];
      if (idx >= 0) next.splice(idx, 1, { ...(next.at(idx) ?? entry), ...entry });
      else next.push(entry);
      return {
        ...state,
        stageProgress: normalizeActiveTimeline(next, state.job?.stage, state.job?.status),
        lastUpdateTs: now,
      };
    }

    case 'SET_STAGE_PROGRESS_LIST':
      if (!shouldAcceptUpdate(state, action.source)) return state;
      return {
        ...state,
        stageProgress: normalizeActiveTimeline(
          mergeStageProgressLists(action.payload, state.stageProgress),
          state.job?.stage,
          state.job?.status
        ),
        lastUpdateTs: now,
      };

    case 'UPDATE_TELEMETRY':
      if (!shouldAcceptUpdate(state, action.source)) return state;
      return {
        ...state,
        sseTelemetry: mergeTelemetry(state.sseTelemetry, action.payload),
        lastUpdateTs: now,
      };

    case 'ADD_FINDINGS':
      return {
        ...state,
        streamingFindings: action.payload.slice(-getMaxStreamingFindings()),
        lastUpdateTs: now,
      };

    case 'SET_ERROR':
      return { ...state, error: action.payload, loading: false, lastUpdateTs: now };

    case 'SET_SSE_ERROR':
      return { ...state, sseError: action.payload, lastUpdateTs: now };

    case 'SET_WS_FAILED':
      return { ...state, wsFailed: action.payload, lastUpdateTs: now };

    case 'SET_DURATION_FORECAST':
      return {
        ...state,
        durationForecast: action.payload,
        durationLoading: action.loading ?? state.durationLoading,
        lastUpdateTs: now,
      };

    case 'SET_ACTION_LOADING':
      return { ...state, actionLoading: action.payload, lastUpdateTs: now };

    case 'RESET_STATE':
      return { ...initialPerJobState, loading: false, lastUpdateTs: now };

    default:
      return state;
  }
}

/** Per-job monitor store. Caches job state (logs, findings, progress) per jobId with LRU eviction. */
interface JobMonitorStore {
  /** Per-job states, keyed by jobId. */
  jobs: Map<string, JobMonitorState>;
  /** Ordered list of jobIds for LRU eviction. */
  accessOrder: string[];

  /**
   * Get (or create) state for a specific job. Initializes a fresh
   * `JobMonitorState` if the jobId has not been seen before.
   */
  getState: (jobId: string) => JobMonitorState;
  /**
   * Dispatch a reducer action for a specific job. Automatically evicts
   * the least-recently-used job when the cache exceeds `MAX_CACHED_JOBS`.
   */
  dispatch: (jobId: string, action: JobMonitorAction) => void;
  /** Remove a job's state from the cache (e.g. on unmount). */
  evict: (jobId: string) => void;
}

export const useJobStore = create<JobMonitorStore>((set, get) => ({
  jobs: new Map(),
  accessOrder: [],

  getState: (jobId: string) => {
    const existing = get().jobs.get(jobId);
    if (existing) return existing;
    // Initialize on first access
    set((s) => {
      const nextJobs = new Map(s.jobs);
      nextJobs.set(jobId, { ...initialPerJobState });
      return {
        jobs: nextJobs,
        accessOrder: [...s.accessOrder.filter(id => id !== jobId), jobId],
      };
    });
    return get().jobs.get(jobId)!;
  },

  dispatch: (jobId: string, action: JobMonitorAction) => {
    set((s) => {
      const current = s.jobs.get(jobId) ?? { ...initialPerJobState };
      const next = reduceJobState(current, action);
      const nextJobs = new Map(s.jobs);
      nextJobs.set(jobId, next);

      // Update access order and evict if over limit
      const nextAccess = s.accessOrder.filter(id => id !== jobId);
      nextAccess.push(jobId);
      if (nextAccess.length > MAX_CACHED_JOBS) {
        const evictIds = nextAccess.splice(0, nextAccess.length - MAX_CACHED_JOBS);
        for (const id of evictIds) nextJobs.delete(id);
      }

      return { jobs: nextJobs, accessOrder: nextAccess };
    });
  },

  evict: (jobId: string) => {
    set((s) => {
      const nextJobs = new Map(s.jobs);
      nextJobs.delete(jobId);
      return { jobs: nextJobs, accessOrder: s.accessOrder.filter(id => id !== jobId) };
    });
  },
}));

export type { JobMonitorAction };
