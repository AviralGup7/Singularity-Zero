import type { Job } from '@/types/api';
import { clamp01, DEFAULT_VISUAL_STATE, type VisualState } from './visualState';

interface MapVisualStateOptions {
  sseError?: string | null;
}

function num(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

export function mapToVisualState(
  job: Partial<Job> | null | undefined,
  options: MapVisualStateOptions = {}
): VisualState {
  if (!job) return DEFAULT_VISUAL_STATE;

  const telemetry = job.progress_telemetry;
  const retries = num(telemetry?.retry_count);
  const failures = num(telemetry?.failure_count);
  const stageErrors = (job.stage_progress ?? []).filter((s) => s.status === 'error').length;
  const findings = num(job.findings_count) + num(telemetry?.high_value_target_count) * 2;
  const throughput = Math.max(
    num(telemetry?.requests_per_second),
    num(telemetry?.throughput_per_second)
  );
  const stageProgress = num(job.stage_percent) / 100;
  const globalProgress = num(job.progress_percent) / 100;
  const likelihood = clamp01(num(telemetry?.vulnerability_likelihood_score));
  const telemetryConfidence = clamp01(
    typeof telemetry?.confidence_score === 'number' ? telemetry.confidence_score : 0.85
  );

  const statusUrgency =
    job.status === 'failed' ? 1 :
    job.status === 'stopped' ? 0.8 :
    job.status === 'running' ? 0.45 :
    0.2;

  const urgency = clamp01(
    Math.max(
      statusUrgency,
      likelihood,
      clamp01(findings / 20),
      job.failed_stage ? 0.92 : 0
    )
  );

  const instability = clamp01(
    (retries + failures + stageErrors + (job.stalled ? 1 : 0)) / 6
  );

  const flow = clamp01(
    clamp01(throughput / 25) * 0.7 + Math.max(stageProgress, globalProgress) * 0.3
  );

  const intensity = clamp01(
    clamp01(findings / 30) * 0.55 +
      flow * 0.3 +
      (job.status === 'running' ? 0.15 : 0)
  );

  const confidencePenalty =
    (options.sseError ? 0.45 : 0) +
    instability * 0.22 +
    (job.stalled ? 0.2 : 0);

  const confidence = clamp01(telemetryConfidence - confidencePenalty);

  return {
    intensity,
    urgency,
    instability,
    flow,
    confidence,
  };
}

export function mapJobsToVisualState(jobs: Job[] | null | undefined): VisualState {
  if (!jobs || jobs.length === 0) return DEFAULT_VISUAL_STATE;

  const states = jobs.map((job) => mapToVisualState(job));
  const count = states.length;

  return {
    intensity: clamp01(states.reduce((sum, s) => sum + s.intensity, 0) / count),
    urgency: clamp01(Math.max(...states.map((s) => s.urgency))),
    instability: clamp01(states.reduce((sum, s) => sum + s.instability, 0) / count),
    flow: clamp01(states.reduce((sum, s) => sum + s.flow, 0) / count),
    confidence: clamp01(states.reduce((sum, s) => sum + s.confidence, 0) / count),
  };
}

