import { useState, useEffect, useCallback, useRef } from 'react';
import type { AxiosRequestConfig } from 'axios';
import { apiCache } from '../api/cache';
import { onRefresh } from '../lib/events';
import api from '../api/client';

interface UseApiOptions<T> {
  enabled?: boolean;
  ttl?: number;
  bypassCache?: boolean;
  params?: Record<string, unknown>;
  onSuccess?: (data: T) => void;
  onError?: (error: UseApiError) => void;
  refetchInterval?: number;
  schema?: import('zod').ZodSchema;
}

interface UseApiError {
  message: string;
  status?: number;
  original: unknown;
}

interface UseApiResult<T> {
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

  const paramsStr = JSON.stringify(params);
  const schema = options?.schema;

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

    const cacheKey = apiCache.generateKey(url, params);

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
        api.get<T>(url, { signal: controller.signal, params, schema } as AxiosRequestConfig).then((res) => res.data);

      const result = await deduplicateRequest<T>(`${cacheKey}:${refetchKey}`, requestFn, controller.signal);

      if (mountedRef.current) {
        setData(result);
        setLoading(false);
        if (ttl) {
          apiCache.set(cacheKey, result, ttl);
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
  }, [url, enabled, bypassCache, paramsStr, params, refetchKey, schema, ttl]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
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

  const isStale = url ? apiCache.isStale(apiCache.generateKey(url, params)) : false;

  return { data, loading, error, refetch, isStale };
}

export default useApi;
