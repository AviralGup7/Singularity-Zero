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

export async function replayRequest(params: ReplayParams, signal?: AbortSignal): Promise<ReplayResult> {
  return cachedGet<ReplayResult>('/api/replay', {
    signal,
    params: params as unknown as Record<string, unknown>,
  });
}
