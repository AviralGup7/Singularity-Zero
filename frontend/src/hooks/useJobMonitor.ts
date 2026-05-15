import { useEffect, useReducer, useRef, useCallback, useState } from 'react';
import {
  getJob,
  getJobLogs,
  stopJob as apiStopJob,
  restartJob as apiRestartJob,
  getHistoricalDurations,
} from '../api/client';
import { useToast } from './useToast';
import { useWebSocket } from './useWebSocket';
import { useSSEProgress } from './useSSEProgress';
import type { SseEvent } from './useSSEProgress';
import { processJobMonitorSseEvent } from './useJobMonitorSse';
import type { Job } from '../types/api';
import {
  mergeStageProgressLists,
  mergeTelemetry,
  normalizeActiveTimeline,
  synthesizeCurrentStageEntry,
} from './useJobMonitorUtils';
import { 
  jobMonitorReducer, 
  initialState, 
  type JobMonitorAction 
} from './useJobMonitorReducer';

const POLL_INTERVAL_MS = 2000;
const BUFFER_FLUSH_MS = 100; // Overhaul: Batch updates every 100ms

export function useJobMonitor(jobId: string | undefined, options: { onRestarted?: (id: string) => void } = {}) {
  const { onRestarted } = options;
  const [state, dispatch] = useReducer(jobMonitorReducer, initialState);
  const toast = useToast();

  // --- Overhaul: Action Buffer Engine ---
  const actionQueueRef = useRef<JobMonitorAction[]>([]);
  const flushTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const bufferDispatch = useCallback((action: JobMonitorAction) => {
    // Immediate dispatch for critical actions (loading, errors, explicit user actions)
    if (action.type === 'START_LOADING' || action.type === 'SET_ERROR' || action.type === 'SET_ACTION_LOADING') {
      dispatch(action);
      return;
    }
    actionQueueRef.current.push(action);
  }, []);

  useEffect(() => {
    flushTimerRef.current = setInterval(() => {
      if (actionQueueRef.current.length === 0) return;

      const batch = [...actionQueueRef.current];
      actionQueueRef.current = [];

      // Atomic multi-dispatch optimization
      // In a more complex setup, we'd have a 'BATCH_UPDATE' action, 
      // but for now, we just flush them sequentially which React 18 batches anyway.
      batch.forEach(dispatch);
    }, BUFFER_FLUSH_MS);

    return () => {
      if (flushTimerRef.current) clearInterval(flushTimerRef.current);
    };
  }, []);

  const seenPollIdsRef = useRef<Set<string>>(new Set());
  const lastErrorToastRef = useRef<{ key: string; ts: number }>({ key: '', ts: 0 });

  // --- REST Polling ---
  const loadData = useCallback(async (signal?: AbortSignal) => {
    if (!jobId) return;
    try {
      const [jobData, logsData] = await Promise.all([
        getJob(jobId, signal),
        getJobLogs(jobId, signal).catch(() => null),
      ]);

      if (!jobData) {
        bufferDispatch({ type: 'SET_ERROR', payload: 'Job not found' });
      } else {
        const logs = logsData?.logs.filter((_, i) => {
          const id = `${logsData.job_id}-${i}`;
          if (seenPollIdsRef.current.has(id)) return false;
          seenPollIdsRef.current.add(id);
          
          if (seenPollIdsRef.current.size > 5000) {
            const iter = seenPollIdsRef.current.values();
            // Fast FIFO prune: delete oldest 2000 entries
            for (let j = 0; j < 2000; j++) {
              const val = iter.next().value;
              if (val !== undefined) seenPollIdsRef.current.delete(val);
              else break;
            }
          }
          return true;
        }) || [];

        dispatch({ type: 'SET_JOB_DATA', payload: jobData, logs });

        const synthesizedCurrent = synthesizeCurrentStageEntry(jobData);
        if (synthesizedCurrent) {
          bufferDispatch({ type: 'UPDATE_STAGE_PROGRESS', payload: synthesizedCurrent });
        }

        if (Array.isArray(jobData.stage_progress)) {
          bufferDispatch({ type: 'SET_STAGE_PROGRESS_LIST', payload: jobData.stage_progress });
        }

        if (jobData.progress_telemetry) {
          bufferDispatch({ type: 'UPDATE_TELEMETRY', payload: jobData.progress_telemetry });
        }
      }
    } catch (err) {
      if (signal?.aborted) return;
      bufferDispatch({ type: 'SET_ERROR', payload: err instanceof Error ? err.message : 'Failed to load job details' });
    }
  }, [jobId, bufferDispatch]);

  useEffect(() => {
    const controller = new AbortController();
    loadData(controller.signal);
    const interval = setInterval(() => {
      if (state.job?.status === 'running') loadData(controller.signal);
    }, POLL_INTERVAL_MS);
    return () => {
      controller.abort();
      clearInterval(interval);
    };
  }, [jobId, state.job?.status, loadData]);

  // --- Duration Forecast ---
  useEffect(() => {
    if (!state.job?.stage) return;
    dispatch({ type: 'SET_DURATION_FORECAST', payload: state.durationForecast, loading: true });
    getHistoricalDurations()
      .then((data) => {
        if (data && data.length > 0) {
          const perStage: Record<string, { mean: number; p50: number; p90: number; count: number }> = {};
          let totalMean = 0;
          for (const entry of data) {
            perStage[entry.module] = {
              mean: entry.avg_duration_sec,
              p50: entry.p50_duration_sec,
              p90: entry.p95_duration_sec,
              count: entry.sample_count,
            };
            totalMean += entry.avg_duration_sec;
          }
          bufferDispatch({ type: 'SET_DURATION_FORECAST', payload: { per_stage: perStage, total_mean_seconds: totalMean }, loading: false });
        } else {
          bufferDispatch({ type: 'SET_DURATION_FORECAST', payload: null, loading: false });
        }
      })
      .catch(() => bufferDispatch({ type: 'SET_DURATION_FORECAST', payload: null, loading: false }));
  }, [state.job?.id, state.job?.stage, bufferDispatch]);

  // --- WebSocket (log streaming) ---
  const handleWsMessage = useCallback(
    (data: unknown) => {
      const msg = data as Record<string, unknown>;
      const msgType = typeof msg.type === 'string' ? msg.type : '';

      if ((msgType === 'log' || msg.log_line) && typeof (msg.line || msg.log_line) === 'string') {
        bufferDispatch({ type: 'ADD_LOG_LINE', payload: (msg.line || msg.log_line) as string });
      }
      if (msg.job_update) {
        bufferDispatch({ type: 'UPDATE_JOB', payload: msg.job_update as Partial<Job> });
      }
    },
    [bufferDispatch]
  );

  const { connectionState } = useWebSocket({
    jobId,
    enabled: state.job?.status === 'running' && !state.wsFailed,
    onMessage: handleWsMessage,
    onFallback: () => bufferDispatch({ type: 'SET_WS_FAILED', payload: true }),
  });

  const stateRef = useRef(state);
  useEffect(() => {
    stateRef.current = state;
  }, [state]);

  // --- SSE (progress, stages, findings, errors) ---
  const handleSSEEvent = useCallback(
    (event: SseEvent) => {
      processJobMonitorSseEvent(event, {
        jobStage: stateRef.current.job?.stage,
        jobStatus: stateRef.current.job?.status,
        setStageProgress: (updater) => {
          const next = typeof updater === 'function' ? updater(stateRef.current.stageProgress) : updater;
          next.forEach(s => bufferDispatch({ type: 'UPDATE_STAGE_PROGRESS', payload: s }));
        },
        setSseTelemetry: (updater) => {
          const next = typeof updater === 'function' ? updater(stateRef.current.sseTelemetry) : updater;
          bufferDispatch({ type: 'UPDATE_TELEMETRY', payload: next });
        },
        setJob: (updater) => {
          const next = typeof updater === 'function' ? updater(stateRef.current.job) : updater;
          if (next) bufferDispatch({ type: 'UPDATE_JOB', payload: next });
        },
        addPluginProgress: (entry) => bufferDispatch({ type: 'ADD_PLUGIN_PROGRESS', payload: entry }),
        resetPluginProgress: () => bufferDispatch({ type: 'RESET_PLUGIN_PROGRESS' }),
        addLogLine: (line) => bufferDispatch({ type: 'ADD_LOG_LINE', payload: line }),
        handleStageProgress: (_d) => {
          // This is redundant with setStageProgress above in some cases, but we'll normalize it in the reducer
        },
        setStreamingFindings: (updater) => {
          const next = typeof updater === 'function' ? updater(stateRef.current.streamingFindings) : updater;
          bufferDispatch({ type: 'ADD_FINDINGS', payload: next });
        },
        setSseError: (err) => bufferDispatch({ type: 'SET_SSE_ERROR', payload: typeof err === 'function' ? err(stateRef.current.sseError) : err }),
        loadData: () => { void loadData(); },
        toastError: (message) => toast.error(message),
        lastErrorToastRef,
      });
    },
    [bufferDispatch, loadData, toast]
  );

  const { connectionState: sseState, isPollingFallback, reconnect } = useSSEProgress({
    jobId,
    enabled: state.job?.status === 'running',
    onEvent: handleSSEEvent,
  });

  // --- Actions ---
  const [showConfirmStop, setShowConfirmStop] = useState(false);
  const [showConfirmRestart, setShowConfirmRestart] = useState(false);

  const executeStop = useCallback(async () => {
    if (!jobId) return;
    dispatch({ type: 'SET_ACTION_LOADING', payload: 'stop' });
    try {
      await apiStopJob(jobId);
      toast.success(`Job ${jobId} stopped`);
      loadData();
    } catch {
      toast.error(`Failed to stop job ${jobId}`);
    } finally {
      dispatch({ type: 'SET_ACTION_LOADING', payload: null });
    }
  }, [jobId, loadData, toast]);

  const executeRestart = useCallback(async () => {
    if (!jobId) return;
    dispatch({ type: 'SET_ACTION_LOADING', payload: 'restart' });
    try {
      const restarted = await apiRestartJob(jobId);
      const restartedJobId = typeof restarted?.id === 'string' ? restarted.id : '';
      toast.success(`Job ${jobId} restarted`);
      dispatch({ type: 'RESET_STATE' });
      if (restartedJobId && restartedJobId !== jobId) {
        onRestarted?.(restartedJobId);
      } else {
        loadData();
      }
    } catch {
      toast.error(`Failed to restart job ${jobId}`);
    } finally {
      dispatch({ type: 'SET_ACTION_LOADING', payload: null });
    }
  }, [jobId, loadData, onRestarted, toast]);

  const mergedStageProgress = normalizeActiveTimeline(
    mergeStageProgressLists(state.job?.stage_progress, state.stageProgress),
    state.job?.stage,
    state.job?.status
  );
  const mergedTelemetry = mergeTelemetry(state.job?.progress_telemetry, state.sseTelemetry);

  const jobWithMergedStages = state.job
    ? { ...state.job, stage_progress: mergedStageProgress, progress_telemetry: mergedTelemetry }
    : null;

  return {
    ...state,
    job: jobWithMergedStages,
    connectionState,
    sseState,
    isPollingFallback,
    showConfirmStop,
    showConfirmRestart,
    setShowConfirmStop,
    setShowConfirmRestart,
    reconnect,
    refetch: loadData,
    stopJob: () => setShowConfirmStop(true),
    executeStop,
    restartJob: () => setShowConfirmRestart(true),
    executeRestart,
    clearSseError: () => dispatch({ type: 'SET_SSE_ERROR', payload: null }),
  };
}
export type UseJobMonitorReturn = ReturnType<typeof useJobMonitor>;
