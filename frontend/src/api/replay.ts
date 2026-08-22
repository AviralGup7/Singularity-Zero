import type { ReplayResult } from '@/types/api';
import { cachedGet } from './core';

export interface ReplayParams {
  target: string;
  run: string;
  replay_id: string;
  auth_mode?: string;
  authorization?: string;
  cookie?: string;
}

export function isUsableReplayParams(params: ReplayParams): boolean {
  return Boolean(params.target?.trim() && params.run?.trim() && params.replay_id?.trim());
}

export async function replayRequest(params: ReplayParams, signal?: AbortSignal): Promise<ReplayResult> {
  if (!isUsableReplayParams(params)) {
    throw new Error('Target, run, and replay id are required');
  }
  return cachedGet<ReplayResult>('/api/replay', {
    signal,
    params: params as unknown as Record<string, unknown>,
  });
}
