/**
 * F-019 — single telemetry state normalizer.
 *
 * REST, SSE, and WebSocket payloads all become the same job / stage /
 * finding / telemetry shapes before Zustand stores see them.
 */
import { canonicalizeJobStatus, normalizeFindingRecord } from '../api/contract';
import { normalizeJobRecord } from '../api/jobs';
import {
  mergeStageProgressLists,
  mergeTelemetry,
  normalizeStageEntry,
} from '../hooks/useJobMonitorUtils';
import type { Finding, Job, ProgressTelemetry, StageProgressEntry } from '../types/api';

export type TelemetrySource = 'rest' | 'sse' | 'ws';

export interface NormalizedTelemetry {
  source: TelemetrySource;
  job: Job | null;
  stages: StageProgressEntry[];
  telemetry: ProgressTelemetry;
  findings: Finding[];
  logLines: string[];
}

function emptyEnvelope(source: TelemetrySource): NormalizedTelemetry {
  return { source, job: null, stages: [], telemetry: {}, findings: [], logLines: [] };
}

function asObject(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export function normalizeFinding(raw: unknown): Finding | null {
  const rec = normalizeFindingRecord(raw);
  if (!rec) return null;
  return rec as unknown as Finding;
}

export function normalizeJob(raw: unknown): Job | null {
  const job = normalizeJobRecord(raw);
  if (!job) return null;
  return { ...job, status: canonicalizeJobStatus(job.status) };
}

export function normalizeStages(raw: unknown): StageProgressEntry[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((entry) => entry && typeof entry === 'object' && typeof (entry as { stage?: unknown }).stage === 'string')
    .map((entry) => normalizeStageEntry(entry as StageProgressEntry & { stage: string }));
}

export function normalizeTelemetryPayload(source: TelemetrySource, payload: unknown): NormalizedTelemetry {
  const out = emptyEnvelope(source);
  const rec = asObject(payload);
  if (!rec) return out;

  const jobRaw = rec.job && typeof rec.job === 'object' ? rec.job : rec.job_update ? rec.job_update : rec;
  const job = normalizeJob(jobRaw);
  if (job && (asObject(jobRaw)?.id || asObject(jobRaw)?.status || asObject(jobRaw)?.base_url)) {
    out.job = job;
  }

  out.stages = normalizeStages(rec.stage_progress ?? job?.stage_progress);
  out.telemetry = mergeTelemetry(
    {},
    (rec.progress_telemetry as Record<string, unknown> | undefined) ?? job?.progress_telemetry,
  );

  const findingsRaw = rec.findings ?? rec.streaming_findings;
  if (Array.isArray(findingsRaw)) {
    out.findings = findingsRaw.map(normalizeFinding).filter((item): item is Finding => Boolean(item?.id));
  }

  if (typeof rec.line === 'string') out.logLines.push(rec.line);
  if (typeof rec.log_line === 'string') out.logLines.push(rec.log_line);
  if (Array.isArray(rec.latest_logs)) {
    out.logLines.push(...rec.latest_logs.map((line) => String(line)));
  }
  return out;
}

export function mergeNormalizedTelemetry(
  rest: NormalizedTelemetry | null | undefined,
  live: NormalizedTelemetry | null | undefined,
): NormalizedTelemetry {
  const left = rest ?? emptyEnvelope('rest');
  const right = live ?? emptyEnvelope('sse');
  const job = right.job && left.job ? { ...left.job, ...right.job } : right.job ?? left.job;
  return {
    source: right.source,
    job,
    stages: mergeStageProgressLists(left.stages, right.stages),
    telemetry: mergeTelemetry(left.telemetry, right.telemetry),
    findings: [...left.findings, ...right.findings],
    logLines: [...left.logLines, ...right.logLines],
  };
}
