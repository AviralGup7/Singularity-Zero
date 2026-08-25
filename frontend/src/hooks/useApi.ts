import { useState, useEffect, useCallback, useRef } from 'react';
import type { AxiosRequestConfig } from 'axios';
import { apiCache } from '../api/cache';
import { onRefresh } from '../lib/events';
import api from '../api/client';
import { showErrorToast } from '../utils/extractErrorMessage';

export interface UseApiOptions<T> {
  enabled?: boolean;
  ttl?: number;
  bypassCache?: boolean;
  params?: Record<string, unknown>;
  onSuccess?: (data: T) => void;
  onError?: (error: UseApiError) => void;
  refetchInterval?: number;
  schema?: import('zod').ZodSchema;
  autoToast?: boolean;
  errorContext?: string;
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

function isExpectedBackendMiss(error: UseApiError): boolean {
  const status = error.status;
  if (status && (status === 401 || status === 403 || status === 404 || status >= 500)) return true;
  const msg = (error.message || '').toLowerCase();
  return /failed to fetch|networkerror|econnrefused|err_network|mesh offline|internal system error|retrying|canceled|abort/.test(msg);
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
    autoToast = false,
    errorContext,
  } = options ?? {};

  // Identity-stable params: callers often pass a fresh object each
  // render with the same values. Depending on the object itself
  // retriggers fetchData → abort → refetch → 429 on read endpoints.
  const paramsKey = JSON.stringify(params ?? null);
  const paramsRef = useRef(params);
  paramsRef.current = params;
  const rateLimitedUntilRef = useRef(0);

  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState<boolean>(enabled && !!url);
  const [error, setError] = useState<UseApiError | null>(null);

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

    if (!forceRefetch && Date.now() < rateLimitedUntilRef.current) {
      if (mountedRef.current) setLoading(false);
      return;
    }

    const currentParams = paramsRef.current;
    const cacheKey = apiCache.generateKey(url, currentParams);

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
        api.get<T>(url, { signal: controller.signal, params: currentParams, schema: schemaRef.current } as AxiosRequestConfig).then((res) => res.data);

      const result = await deduplicateRequest<T>(cacheKey, requestFn, controller.signal);

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
      if (lastError.status === 429) {
        const retryAfter = (err as { retryAfterMs?: number })?.retryAfterMs;
        rateLimitedUntilRef.current = Date.now() + (typeof retryAfter === 'number' ? retryAfter : 5000);
      }

      if (mountedRef.current) {
        setError(lastError);
        setLoading(false);
        onErrorRef.current?.(lastError);
        if (autoToast && !isExpectedBackendMiss(lastError)) {
          showErrorToast(err, errorContext);
        }
      }
    }
  }, [url, enabled, bypassCache, paramsKey, ttl, autoToast, errorContext]);

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
    await fetchData(true);
  }, [fetchData]);

  const isStale = url ? apiCache.isStale(apiCache.generateKey(url, paramsRef.current)) : false;

  return { data, loading, error, refetch, isStale };
}

export default useApi;
