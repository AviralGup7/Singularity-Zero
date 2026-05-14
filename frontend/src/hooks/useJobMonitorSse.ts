import type { MutableRefObject } from 'react';

import type { SseEvent } from './useSSEProgress';
import type {
  Finding,
  Job,
  PluginProgressEntry,
  ProgressTelemetry,
  StageProgressEntry,
} from '../types/api';

import {
  mergeTelemetry,
  normalizeStageEntry,
  mergeStageProgressLists,
  normalizeActiveTimeline,
  compactPipelineError,
} from './useJobMonitorUtils';

interface JobMonitorSseContext {
  jobStage?: string;
  jobStatus?: Job['status'];
  setStageProgress: (updater: StageProgressEntry[] | ((prev: StageProgressEntry[]) => StageProgressEntry[])) => void;
  setSseTelemetry: (updater: ProgressTelemetry | ((prev: ProgressTelemetry) => ProgressTelemetry)) => void;
  setJob: (updater: Job | null | ((prev: Job | null) => Job | null)) => void;
  addPluginProgress: (entry: PluginProgressEntry) => void;
  resetPluginProgress: () => void;
  addLogLine: (line: string) => void;
  handleStageProgress: (data: Record<string, unknown>) => void;
  setStreamingFindings: (updater: Finding[] | ((prev: Finding[]) => Finding[])) => void;
  setSseError: (updater: string | null | ((prev: string | null) => string | null)) => void;
  loadData: () => void;
  toastError: (message: string) => void;
  lastErrorToastRef: MutableRefObject<{ key: string; ts: number }>;
}

export function processJobMonitorSseEvent(event: SseEvent, ctx: JobMonitorSseContext): void {
  if (event.event_type === 'progress_update') {
    const data = event.data as Record<string, unknown>;
    if (Array.isArray(data.stage_progress)) {
      const incomingStages = (data.stage_progress as Record<string, unknown>[])
        .filter((entry) => entry && typeof entry === 'object' && typeof entry.stage === 'string')
        .map((entry) => normalizeStageEntry(entry as unknown as StageProgressEntry));
      ctx.setStageProgress((prev) =>
        normalizeActiveTimeline(
          mergeStageProgressLists(incomingStages, prev),
          typeof data.stage === 'string' ? data.stage : ctx.jobStage,
          typeof data.status === 'string' ? (data.status as Job['status']) : ctx.jobStatus
        )
      );
    }
    if (data.progress_telemetry && typeof data.progress_telemetry === 'object') {
      ctx.setSseTelemetry((prev) =>
        mergeTelemetry(prev, data.progress_telemetry as Record<string, unknown>)
      );
    }
    ctx.setJob((prev) => {
      if (!prev) return prev;
      const updated = { ...prev };
      if (typeof data.progress_percent === 'number') updated.progress_percent = data.progress_percent;
      if (typeof data.message === 'string') updated.status_message = data.message;
      if (typeof data.stage === 'string' && data.stage) updated.stage = data.stage;
      if (typeof data.stage_label === 'string' && data.stage_label) updated.stage_label = data.stage_label;
      if (typeof data.status === 'string' && data.status) updated.status = data.status as Job['status'];
      if (typeof data.stage_processed === 'number') updated.stage_processed = data.stage_processed;
      if (typeof data.stage_total === 'number') updated.stage_total = data.stage_total;
      if (typeof data.failed_stage === 'string' && data.failed_stage) updated.failed_stage = data.failed_stage;
      if (typeof data.failure_reason_code === 'string' && data.failure_reason_code) {
        updated.failure_reason_code = data.failure_reason_code;
      }
      if (typeof data.failure_step === 'string' && data.failure_step) updated.failure_step = data.failure_step;
      if (typeof data.failure_reason === 'string' && data.failure_reason) {
        updated.failure_reason = data.failure_reason;
      }
      updated.progress_telemetry = mergeTelemetry(
        updated.progress_telemetry,
        (data.progress_telemetry as Record<string, unknown>) || undefined
      );
      return updated;
    });

    if (data.plugin_group && typeof data.plugin_group === 'string') {
      ctx.addPluginProgress({
        group: data.plugin_group as string,
        label: (data.plugin_label as string) || (data.plugin_group as string),
        processed: typeof data.processed === 'number' ? data.processed : 0,
        total: typeof data.total === 'number' ? data.total : 0,
        percent: typeof data.percent === 'number' ? data.percent : 0,
        current_plugin: typeof data.current_plugin === 'string' ? data.current_plugin : undefined,
        status: (data.status as PluginProgressEntry['status']) || 'running',
        error_message:
          typeof data.error_message === 'string' ? data.error_message : undefined,
      });
    }

    ctx.handleStageProgress(data);
  }

  if (event.event_type === 'stage_change') {
    const data = event.data as Record<string, unknown>;
    ctx.setJob((prev) => {
      if (!prev) return prev;
      return { ...prev, stage: data.new_stage as string, stage_label: data.stage_label as string };
    });
    ctx.resetPluginProgress();

    ctx.setStageProgress((prev) =>
      prev.map((stage) => {
        if (stage.stage === (data.new_stage as string)) {
          return stage;
        }
        return stage.status === 'running'
          ? { ...stage, status: 'completed' as const, percent: 100 }
          : stage;
      })
    );
  }

  if (event.event_type === 'iteration_change') {
    const data = event.data as Record<string, unknown>;
    ctx.setJob((prev) => {
      if (!prev) return prev;
      const updated = { ...prev };
      if (typeof data.current_iteration === 'number') updated.iteration_current = data.current_iteration;
      if (typeof data.max_iterations === 'number') updated.iteration_total = data.max_iterations;
      if (typeof data.stage_percent === 'number') updated.stage_percent = data.stage_percent;
      return updated;
    });
  }

  if (event.event_type === 'finding_batch') {
    const data = event.data as Record<string, unknown>;
    if (Array.isArray(data.findings)) {
      ctx.setStreamingFindings((prev) => [...prev, ...(data.findings as Finding[])]);
    }
  }

  if (event.event_type === 'error') {
    const data = event.data as Record<string, unknown>;
    if (Array.isArray(data.stage_progress)) {
      const incomingStages = (data.stage_progress as Record<string, unknown>[])
        .filter((entry) => entry && typeof entry === 'object' && typeof entry.stage === 'string')
        .map((entry) => normalizeStageEntry(entry as unknown as StageProgressEntry));
      ctx.setStageProgress((prev) =>
        normalizeActiveTimeline(
          mergeStageProgressLists(incomingStages, prev),
          typeof data.stage === 'string' ? data.stage : ctx.jobStage,
          typeof data.status === 'string' ? (data.status as Job['status']) : 'failed'
        )
      );
    }
    if (data.progress_telemetry && typeof data.progress_telemetry === 'object') {
      ctx.setSseTelemetry((prev) =>
        mergeTelemetry(prev, data.progress_telemetry as Record<string, unknown>)
      );
    }
    const errorMessage = compactPipelineError(
      data?.error || data?.failure_reason || 'Unknown pipeline error'
    );
    ctx.setSseError(errorMessage);
    ctx.setJob((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        status: 'failed',
        failed_stage:
          typeof data?.failed_stage === 'string' ? data.failed_stage : prev.failed_stage,
        failure_reason_code:
          typeof data?.failure_reason_code === 'string'
            ? data.failure_reason_code
            : prev.failure_reason_code,
        failure_step:
          typeof data?.failure_step === 'string' ? data.failure_step : prev.failure_step,
        failure_reason:
          typeof data?.failure_reason === 'string' ? data.failure_reason : errorMessage,
        progress_telemetry: mergeTelemetry(
          prev.progress_telemetry,
          (data.progress_telemetry as Record<string, unknown>) || undefined
        ),
      };
    });
    const toastKey = [
      String(data?.failed_stage || ''),
      String(data?.failure_reason_code || ''),
      errorMessage,
    ].join('|');
    const now = Date.now();
    if (
      ctx.lastErrorToastRef.current.key !== toastKey ||
      now - ctx.lastErrorToastRef.current.ts > 15000
    ) {
      ctx.lastErrorToastRef.current = { key: toastKey, ts: now };
      ctx.toastError(errorMessage);
    }
    ctx.loadData();
  }

  if (event.event_type === 'completed') {
    const data = event.data as Record<string, unknown>;
    if (Array.isArray(data.stage_progress)) {
      const incomingStages = (data.stage_progress as Record<string, unknown>[])
        .filter((entry) => entry && typeof entry === 'object' && typeof entry.stage === 'string')
        .map((entry) => normalizeStageEntry(entry as unknown as StageProgressEntry));
      ctx.setStageProgress((prev) =>
        normalizeActiveTimeline(
          mergeStageProgressLists(incomingStages, prev),
          typeof data.stage === 'string' ? data.stage : ctx.jobStage,
          typeof data.status === 'string' ? (data.status as Job['status']) : ctx.jobStatus
        )
      );
    }
    if (data.progress_telemetry && typeof data.progress_telemetry === 'object') {
      ctx.setSseTelemetry((prev) =>
        mergeTelemetry(prev, data.progress_telemetry as Record<string, unknown>)
      );
    }
    const terminalStatus = typeof data?.status === 'string' ? data.status : '';
    if (terminalStatus === 'completed') {
      ctx.setSseError(null);
    } else if (terminalStatus === 'failed' || terminalStatus === 'stopped') {
      const terminalError = compactPipelineError(
        data?.failure_reason || data?.error || 'Run ended before successful completion'
      );
      ctx.setSseError((prev) => prev || terminalError);
      ctx.setJob((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          status: terminalStatus as Job['status'],
          failed_stage:
            typeof data?.failed_stage === 'string' ? data.failed_stage : prev.failed_stage,
          failure_reason_code:
            typeof data?.failure_reason_code === 'string'
              ? data.failure_reason_code
              : prev.failure_reason_code,
          failure_step:
            typeof data?.failure_step === 'string' ? data.failure_step : prev.failure_step,
          failure_reason:
            typeof data?.failure_reason === 'string'
              ? data.failure_reason
              : prev.failure_reason,
          progress_telemetry: mergeTelemetry(
            prev.progress_telemetry,
            (data.progress_telemetry as Record<string, unknown>) || undefined
          ),
        };
      });
    }
    ctx.loadData();
  }

  if (event.event_type === 'log' && typeof event.data?.line === 'string') {
    ctx.addLogLine(event.data.line as string);
  }
}
