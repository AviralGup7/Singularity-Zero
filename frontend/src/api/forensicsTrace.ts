import { apiClient } from './core';

export interface ForensicsTraceStage {
  run_id: string;
  stage_name: string;
  trace_dir: string;
  events: Array<{
    timestamp: string;
    event_type: string;
    message: string;
    metadata?: Record<string, unknown>;
  }>;
  summary?: Record<string, unknown>;
}

export interface ForensicsTrace {
  run_id: string;
  stages: ForensicsTraceStage[];
  trace_dir: string;
}

export interface CausalChainLink {
  finding_id: string;
  stage: string;
  event_id: string;
  trigger: string;
  effect: string;
  confidence: number;
}

export interface CausalChain {
  run_id: string;
  stage_name: string;
  finding_id: string;
  chain: CausalChainLink[];
}

export async function getForensicsTrace(
  runId: string,
  traceDir?: string,
  signal?: AbortSignal,
): Promise<ForensicsTrace> {
  const { data } = await apiClient.get<ForensicsTrace>(
    `/api/forensics/trace/${encodeURIComponent(runId)}`,
    { params: traceDir ? { trace_dir: traceDir } : undefined, signal },
  );
  return data;
}

export async function getForensicsTraceStage(
  runId: string,
  stageName: string,
  traceDir?: string,
  signal?: AbortSignal,
): Promise<ForensicsTraceStage> {
  const { data } = await apiClient.get<ForensicsTraceStage>(
    `/api/forensics/trace/${encodeURIComponent(runId)}/${encodeURIComponent(stageName)}`,
    { params: traceDir ? { trace_dir: traceDir } : undefined, signal },
  );
  return data;
}

export async function getForensicsCausalChain(
  runId: string,
  stageName: string,
  findingId: string,
  traceDir?: string,
  signal?: AbortSignal,
): Promise<CausalChain> {
  const { data } = await apiClient.get<CausalChain>(
    `/api/forensics/trace/${encodeURIComponent(runId)}/${encodeURIComponent(stageName)}/causal-chain/${encodeURIComponent(findingId)}`,
    { params: traceDir ? { trace_dir: traceDir } : undefined, signal },
  );
  return data;
}
