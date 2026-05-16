import { useEffect, useRef } from 'react';

export function useDebouncedPersist<T>(
  data: T,
  saveFn: (data: T) => void,
  debounceMs = 500
): void {
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    saveTimerRef.current = setTimeout(() => {
      saveFn(data);
    }, debounceMs);

    return () => {
      if (saveTimerRef.current) {
        clearTimeout(saveTimerRef.current);
      }
    };
   
  }, [data, saveFn, debounceMs]);
}
