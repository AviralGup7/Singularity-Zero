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
} from './useJobMonitorUtils';

export interface DurationForecastData {
  per_stage: Record<string, { mean: number; p50: number; p90: number; count: number }>;
  total_mean_seconds: number;
}

export interface JobMonitorState {
  job: Job | null;
  loading: boolean;
  error: string | null;
  allLogLines: string[];
  pluginProgress: PluginProgressEntry[];
  streamingFindings: Finding[];
  sseError: string | null;
  wsFailed: boolean;
  durationForecast: DurationForecastData | null;
  durationLoading: boolean;
  stageProgress: StageProgressEntry[];
  sseTelemetry: ProgressTelemetry;
  actionLoading: string | null;
  lastUpdateTs: number;
}

export type JobMonitorAction =
  | { type: 'START_LOADING' }
  | { type: 'SET_JOB_DATA'; payload: Job; logs?: string[] }
  | { type: 'UPDATE_JOB'; payload: Partial<Job> }
  | { type: 'ADD_LOG_LINE'; payload: string }
  | { type: 'ADD_PLUGIN_PROGRESS'; payload: PluginProgressEntry }
  | { type: 'RESET_PLUGIN_PROGRESS' }
  | { type: 'UPDATE_STAGE_PROGRESS'; payload: StageProgressEntry }
  | { type: 'SET_STAGE_PROGRESS_LIST'; payload: StageProgressEntry[] }
  | { type: 'UPDATE_TELEMETRY'; payload: Record<string, unknown> }
  | { type: 'ADD_FINDINGS'; payload: Finding[] }
  | { type: 'SET_ERROR'; payload: string | null }
  | { type: 'SET_SSE_ERROR'; payload: string | null }
  | { type: 'SET_WS_FAILED'; payload: boolean }
  | { type: 'SET_DURATION_FORECAST'; payload: DurationForecastData | null; loading?: boolean }
  | { type: 'SET_ACTION_LOADING'; payload: string | null }
  | { type: 'RESET_STATE' };

export const initialState: JobMonitorState = {
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

const MAX_LOG_LINES = 10000;

export function jobMonitorReducer(state: JobMonitorState, action: JobMonitorAction): JobMonitorState {
  const now = Date.now();

  switch (action.type) {
    case 'START_LOADING':
      return { ...state, loading: true };

    case 'SET_JOB_DATA': {
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
   
          ? [...state.allLogLines, ...logs].slice(-MAX_LOG_LINES)
          : state.allLogLines,
        lastUpdateTs: now,
      };
    }

    case 'UPDATE_JOB':
      if (!state.job) return state;
      return {
        ...state,
        job: { ...state.job, ...action.payload },
        lastUpdateTs: now,
      };

    case 'ADD_LOG_LINE':
      return {
        ...state,
   
        allLogLines: [...state.allLogLines, action.payload].slice(-MAX_LOG_LINES),
        lastUpdateTs: now,
      };

    case 'ADD_PLUGIN_PROGRESS': {
      const entry = action.payload;
      const idx = state.pluginProgress.findIndex((p) => p.label === entry.label);
   
      const nextProgress = [...state.pluginProgress];
      if (idx >= 0) {
        nextProgress[idx] = entry;
      } else {
        nextProgress.push(entry);
      }
      return { ...state, pluginProgress: nextProgress, lastUpdateTs: now };
    }

    case 'RESET_PLUGIN_PROGRESS':
      return { ...state, pluginProgress: [], lastUpdateTs: now };

    case 'UPDATE_STAGE_PROGRESS': {
      const entry = action.payload;
      const idx = state.stageProgress.findIndex((s) => s.stage === entry.stage);
   
      const nextStages = [...state.stageProgress];
      if (idx >= 0) {
        nextStages[idx] = { ...nextStages[idx], ...entry };
      } else {
        nextStages.push(entry);
      }
      return {
        ...state,
        stageProgress: normalizeActiveTimeline(nextStages, state.job?.stage, state.job?.status),
        lastUpdateTs: now,
      };
    }

    case 'SET_STAGE_PROGRESS_LIST':
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
      return {
        ...state,
        sseTelemetry: mergeTelemetry(state.sseTelemetry, action.payload),
        lastUpdateTs: now,
      };

    case 'ADD_FINDINGS':
      return {
        ...state,
   
        streamingFindings: [...state.streamingFindings, ...action.payload],
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
      return { ...initialState, loading: false, lastUpdateTs: now };

    default:
      return state;
  }
}
