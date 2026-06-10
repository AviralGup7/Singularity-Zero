import { useState, useEffect, useCallback, useRef } from 'react';
import type { AxiosRequestConfig } from 'axios';
import { apiCache } from '../api/cache';
import { onRefresh } from '../lib/events';
import api from '../api/client';

export interface UseApiOptions<T> {
  enabled?: boolean;
  ttl?: number;
  bypassCache?: boolean;
  params?: Record<string, unknown>;
  onSuccess?: (data: T) => void;
  onError?: (error: UseApiError) => void;
  refetchInterval?: number;
  schema?: import('zod').ZodSchema;
}

export interface UseApiError {
  message: string;
  status?: number;
  original: unknown;
}

export interface UseApiResult<T> {
  data: T | null;
  loading: boolean;
  error: UseApiError | null;
  refetch: () => Promise<void>;
  isStale: boolean;
}

const pendingRequests = new Map<string, { promise: Promise<unknown>; signal?: AbortSignal }>();

function deduplicateRequest<T>(key: string, fn: () => Promise<T>, signal?: AbortSignal): Promise<T> {
  const existing = pendingRequests.get(key);
  if (existing) {
    if (existing.signal?.aborted) {
      pendingRequests.delete(key);
    } else {
      return existing.promise as Promise<T>;
    }
  }

  const promise = fn().finally(() => {
    pendingRequests.delete(key);
  });

  pendingRequests.set(key, { promise, signal });
  return promise;
}

/* eslint-disable security/detect-object-injection */
// ``isDeepEqual`` was previously exported for callers that needed
// reference-equality-style value comparison, but no in-tree consumer
// remains. The hook now relies on ``URLSearchParams``/JSON.stringify
// based cache keys. The helper is kept here as a tree-shakeable
// internal utility so future diffing needs can re-use it without
// re-introducing the security/detect-object-injection disable.
function _isDeepEqual(obj1: unknown, obj2: unknown): boolean {
  if (obj1 === obj2) return true;
  if (obj1 === null || obj2 === null || typeof obj1 !== 'object' || typeof obj2 !== 'object') {
    return false;
  }

  if (Array.isArray(obj1)) {
    if (!Array.isArray(obj2) || obj1.length !== obj2.length) return false;
    for (let i = 0; i < obj1.length; i++) {
      if (!_isDeepEqual(obj1[i], obj2[i])) return false;
    }
    return true;
  }

  if (Array.isArray(obj2)) return false;

  const keys1 = Object.keys(obj1 as Record<string, unknown>);
  const keys2 = Object.keys(obj2 as Record<string, unknown>);
  if (keys1.length !== keys2.length) return false;

  for (const key of keys1) {
    if (!Object.prototype.hasOwnProperty.call(obj2, key) || !_isDeepEqual((obj1 as Record<string, unknown>)[key], (obj2 as Record<string, unknown>)[key])) {
      return false;
    }
  }
  return true;
}
/* eslint-enable security/detect-object-injection */

export function useApi<T>(
  url: string | null,
  options?: UseApiOptions<T>
): UseApiResult<T> {
  const {
    enabled = true,
    ttl,
    bypassCache = false,
    params,
    onSuccess,
    onError,
    refetchInterval,
  } = options ?? {};

  // ``params`` is read from the latest closure each time ``fetchData``
  // is invoked. Because ``params`` is already in the dep array of
  // ``fetchData`` and the effect that triggers fetches, we don't need
  // a ref indirection - the value is always fresh.
  const stableParams = params;

  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState<boolean>(enabled && !!url);
  const [error, setError] = useState<UseApiError | null>(null);
  const [refetchKey, setRefetchKey] = useState<number>(0);

  const abortRef = useRef<AbortController | null>(null);
  const mountedRef = useRef<boolean>(true);

  const onSuccessRef = useRef(onSuccess);
  const onErrorRef = useRef(onError);

  useEffect(() => {
    onSuccessRef.current = onSuccess;
    onErrorRef.current = onError;
  }, [onSuccess, onError]);

  const schema = options?.schema;
  const schemaRef = useRef(schema);
  useEffect(() => {
    schemaRef.current = schema;
  }, [schema]);

  const fetchData = useCallback(async (forceRefetch = false): Promise<void> => {
    if (!enabled || !url) {
      if (mountedRef.current) setLoading(false);
      return;
    }

    if (abortRef.current) {
      abortRef.current.abort();
    }

    const controller = new AbortController();
    abortRef.current = controller;

    const cacheKey = apiCache.generateKey(url, stableParams);

    if (!forceRefetch && !bypassCache) {
      const cached = apiCache.get<T>(cacheKey);
      if (cached !== null && !apiCache.isStale(cacheKey)) {
        if (mountedRef.current) {
          setData(cached);
          setLoading(false);
        }
        return;
      }
    }

    if (mountedRef.current) {
      setLoading(true);
      setError(null);
    }

    try {
      if (controller.signal.aborted) return;

      const requestFn = (): Promise<T> =>
        api.get<T>(url, { signal: controller.signal, params: stableParams, schema: schemaRef.current } as AxiosRequestConfig).then((res) => res.data);

      const result = await deduplicateRequest<T>(`${cacheKey}:${refetchKey}`, requestFn, controller.signal);

      if (mountedRef.current) {
        setData(result);
        setLoading(false);
        if (ttl !== undefined) {
          if (ttl > 0) {
            apiCache.set(cacheKey, result, ttl);
          }
        } else {
          apiCache.set(cacheKey, result);
        }
        onSuccessRef.current?.(result);
      }
    } catch (err: unknown) {
      if (controller.signal.aborted) return;

      const lastError: UseApiError = {
        message: err instanceof Error ? err.message : (err as { message?: string })?.message || 'An unexpected error occurred',
        status: (err as { status?: number })?.status,
        original: err,
      };

      if (mountedRef.current) {
        setError(lastError);
        setLoading(false);
        onErrorRef.current?.(lastError);
      }
    }
  }, [url, enabled, bypassCache, stableParams, refetchKey, ttl]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    // Initial fetch: the body of this effect synchronizes the hook's
    // local state with the external API endpoint, which is the
    // documented use case for ``useEffect``. Subsequent updates flow
    // through event handlers (focus, refresh, interval) and do not
    // hit this code path.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void fetchData();

    // --- Overhaul: Revalidate on Focus ---
    const handleFocus = () => {
      if (enabled && url) fetchData(false);
    };

    window.addEventListener('focus', handleFocus);

    const unbindRefresh = onRefresh(() => {
      fetchData(true);
    });

    let interval: ReturnType<typeof setInterval> | undefined;
    if (refetchInterval && enabled) {
      interval = setInterval(() => {
        fetchData();
      }, refetchInterval);
    }

    return () => {
      abortRef.current?.abort();
      window.removeEventListener('focus', handleFocus);
      unbindRefresh();
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [fetchData, refetchInterval, enabled, url]);

  const refetch = useCallback(async (): Promise<void> => {
    setRefetchKey((k) => k + 1);
  }, []);

  const isStale = url ? apiCache.isStale(apiCache.generateKey(url, stableParams)) : false;

  return { data, loading, error, refetch, isStale };
}

export default useApi;
