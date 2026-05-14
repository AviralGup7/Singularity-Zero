import type {
  CacheKeyDeleteResponse,
  CacheKeysResponse,
  CachePerformanceHistoryResponse,
  CacheStats,
  CacheCleanupResponse,
  CacheNamespaceResponse,
  CacheStatusResponse,
} from '@/types/extended';
import { apiClient, cachedGet } from './core';
import { apiCache } from './cache';

export async function getCacheStats(signal?: AbortSignal): Promise<CacheStats> {
  return cachedGet<CacheStats>('/api/cache/stats', { signal, bypassCache: true });
}

export async function getCacheStatus(signal?: AbortSignal): Promise<CacheStatusResponse> {
  return cachedGet<CacheStatusResponse>('/api/cache/status', { signal, bypassCache: true });
}

export async function getCacheKeys(
  pattern = '*',
  limit = 100,
  signal?: AbortSignal
): Promise<CacheKeysResponse> {
  return cachedGet<CacheKeysResponse>('/api/cache/keys', {
    signal,
    bypassCache: true,
    params: { pattern, limit },
  });
}

export async function deleteCacheKeys(pattern: string, signal?: AbortSignal): Promise<CacheKeyDeleteResponse> {
  const { data } = await apiClient.delete<CacheKeyDeleteResponse>('/api/cache/keys', {
    data: { pattern },
    signal,
  });
  apiCache.invalidateAll();
  return data;
}

export async function getCachePerformanceHistory(signal?: AbortSignal): Promise<CachePerformanceHistoryResponse> {
  return cachedGet<CachePerformanceHistoryResponse>('/api/cache/performance-history', {
    signal,
    bypassCache: true,
  });
}

export async function triggerCacheCleanup(signal?: AbortSignal): Promise<CacheCleanupResponse> {
  const { data } = await apiClient.post<CacheCleanupResponse>('/api/cache/cleanup', undefined, { signal });
  apiCache.invalidateAll();
  return data;
}

export async function clearAllCaches(signal?: AbortSignal): Promise<CacheNamespaceResponse> {
  const { data } = await apiClient.post<CacheNamespaceResponse>('/api/cache/clear', undefined, { signal });
  apiCache.invalidateAll();
  return data;
}

export async function invalidateCacheNamespace(namespace: string, signal?: AbortSignal): Promise<CacheNamespaceResponse> {
  const { data } = await apiClient.delete<CacheNamespaceResponse>(`/api/cache/${namespace}`, { signal });
  apiCache.invalidateAll();
  return data;
}
