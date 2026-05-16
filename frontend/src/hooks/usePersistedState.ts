import { useState, useEffect, useRef, type Dispatch, type SetStateAction } from 'react';

/**
 * A hook that syncs state to localStorage with debounced writes.
 * Replaces the redundant localStorage logic across ThemeContext, DisplayContext, and SettingsContext.
 *
 * Usage:
 *   const [theme, setTheme] = usePersistedState('cyber-pipeline-theme', defaultTheme, { ttl: 300 });
 */
export function usePersistedState<T>(
  key: string,
  defaultValue: T,
  options?: {
    /** Debounce delay in ms for localStorage writes (default: 300) */
    debounceMs?: number;
    /** Transform value before saving to localStorage */
    serialize?: (value: T) => string;
    /** Transform value after reading from localStorage */
    deserialize?: (text: string) => T;
  }
   
): [T, Dispatch<SetStateAction<T>>] {
  const debounceMs = options?.debounceMs ?? 300;
  const serialize = options?.serialize ?? JSON.stringify;
  const deserialize = options?.deserialize ?? JSON.parse;

   
  const [value, setValue] = useState<T>(() => {
    try {
      const stored = localStorage.getItem(key);
      if (stored !== null) {
        return deserialize(stored);
      }
    } catch {
      /* ignore parse errors, use default */
    }
    return defaultValue;
  });

  const pendingWriteRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    // Clear any pending write
    if (pendingWriteRef.current !== null) {
      clearTimeout(pendingWriteRef.current);
    }

    // Debounce the write
    pendingWriteRef.current = setTimeout(() => {
      try {
        localStorage.setItem(key, serialize(value));
      } catch {
        /* ignore quota errors */
      }
      pendingWriteRef.current = null;
    }, debounceMs);

    return () => {
      if (pendingWriteRef.current !== null) {
        clearTimeout(pendingWriteRef.current);
        pendingWriteRef.current = null;
      }
    };
   
  }, [key, value, debounceMs, serialize]);

   
  return [value, setValue];
}
