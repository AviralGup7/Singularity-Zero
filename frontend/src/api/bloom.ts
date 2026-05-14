import type { BloomHealthResponse, BloomReconcileResponse } from '@/types/api';
import { cachedGet, cachedPost } from './core';

export function getBloomHealth(signal?: AbortSignal): Promise<BloomHealthResponse> {
  return cachedGet<BloomHealthResponse>('/api/bloom/health', {
    signal,
    ttl: 5000,
    bypassCache: true,
  });
}

export function forceBloomReconcile(signal?: AbortSignal): Promise<BloomReconcileResponse> {
  return cachedPost<BloomReconcileResponse>('/api/bloom/reconcile', {}, { signal });
}
