import { useState, useEffect, useCallback, type ReactNode } from 'react';

export function useLogFetcher<T>(
  fetchFn: (signal: AbortSignal) => Promise<T[]>,
  deps: unknown[] = []
) {
  const [data, setData] = useState<T[]>([]);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    try {
      const result = await fetchFn(signal || new AbortController().signal);
      if (!signal?.aborted) setData(result);
    } catch {
      // silent
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, deps);

  useEffect(() => {
    const controller = new AbortController();
    fetch(controller.signal);
    return () => controller.abort();
  }, [fetch]);

  return { data, loading, refetch: () => fetch() };
}

interface LogTableShellProps {
  loading: boolean;
  isEmpty: boolean;
  loadingLabel?: string;
  emptyLabel?: string;
  children: ReactNode;
}

export function LogTableShell({
  loading,
  isEmpty,
  loadingLabel = 'Loading...',
  emptyLabel = 'No entries found.',
  children,
}: LogTableShellProps) {
  if (loading) {
    return <div className="p-12 text-center text-muted animate-pulse">{loadingLabel}</div>;
  }

  if (isEmpty) {
    return <div className="p-12 text-center text-muted">{emptyLabel}</div>;
  }

  return <>{children}</>;
}
