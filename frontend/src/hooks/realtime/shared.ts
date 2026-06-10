/**
 * Shared building blocks for real-time stream hooks (SSE + WebSocket).
 *
 * R6 (Frontend Architectural Analysis) observed that `useSSEProgress` and
 * `useWebSocket` each re-implemented the same primitives — a `mountedRef`,
 * an exponential backoff with cap, a FIFO deduplication set, and a
 * heartbeat watchdog — with subtle drift between them. This module pulls
 * each primitive into a single, testable composable so both transports
 * (and the `useRealtimeStream` facade on top of them) stay in lock-step.
 *
 * The primitives are *intentionally* small and stateless beyond the refs
 * they manage. They never call setState directly — that's the consumer's
 * job. The `mountedRef` guard, in particular, is what every async event
 * handler in every stream hook should consult before touching React state,
 * which is exactly the gap that `useCockpitData`'s raw `EventSource` was
 * missing.
 */

import { useEffect, useRef, useCallback, useState } from 'react';

export type ConnectionState = 'connecting' | 'connected' | 'reconnecting' | 'disconnected' | 'failed' | 'closed';

/**
 * Mount-tracking ref. Stays `true` for the lifetime of the component (or
 * the surrounding `useEffect` cleanup scope) and flips to `false` on
 * unmount. Every async callback that might fire after unmount MUST guard
 * itself with `if (!mountedRef.current) return;` before calling setState.
 *
 * Returns both a stable ref *and* a stateful boolean so consumers that
 * want a render-time check (e.g. to disable a "reconnect" button) can
 * read the boolean without writing `if (mountedRef.current)` everywhere.
 */
export function useMountedRef(): { mountedRef: React.MutableRefObject<boolean>; isMounted: boolean } {
  const mountedRef = useRef(true);
  const [isMounted, setIsMounted] = useState(true);

  useEffect(() => {
    // Ref is already `true` on first render; the cleanup is the only place
    // we touch it. `isMounted` already starts as `true` via `useState(true)`,
    // so we only need to flip it on unmount.
    return () => {
      mountedRef.current = false;
      setIsMounted(false);
    };
  }, []);

  return { mountedRef, isMounted };
}

/**
 * Exponential backoff with a cap and jitter. Returns:
 *   - `delayMs()` — the current delay in ms (caller is responsible for
 *     calling `setTimeout(..., delayMs())` and then `bump()` on retry)
 *   - `bump()` — multiply the current delay by the backoff factor
 *   - `reset()` — return the delay to `minDelayMs`
 *   - `setFactor()` — override the multiplier (e.g. for SSE's 1.5×
 *     gentler curve vs WS's 2×)
 */
export interface ReconnectBackoff {
  delayMs: () => number;
  bump: () => void;
  reset: () => void;
  setFactor: (factor: number) => void;
}

export function useReconnectBackoff({
  minDelayMs = 1000,
  maxDelayMs = 60000,
  factor = 1.5,
}: {
  minDelayMs?: number;
  maxDelayMs?: number;
  factor?: number;
} = {}): ReconnectBackoff {
  const currentRef = useRef(minDelayMs);
  const factorRef = useRef(factor);

  const delayMs = useCallback(() => currentRef.current, []);

  const bump = useCallback(() => {
    currentRef.current = Math.min(currentRef.current * factorRef.current, maxDelayMs);
  }, [maxDelayMs]);

  const reset = useCallback(() => {
    currentRef.current = minDelayMs;
  }, [minDelayMs]);

  const setFactor = useCallback((next: number) => {
    factorRef.current = next;
  }, []);

  return { delayMs, bump, reset, setFactor };
}

export interface DedupSetOptions {
  maxSize?: number;
  pruneChunk?: number;
}

/**
 * FIFO deduplication set with a soft cap. When the set exceeds `maxSize`,
 * the oldest `pruneChunk` entries are dropped. Used by both SSE and WS
 * to avoid re-dispatching the same event ID when the server replays
 * buffered frames after a reconnect.
 */
export class DedupSet {
  private ids: Set<string>;
  private readonly maxSize: number;
  private readonly pruneChunk: number;

  constructor({ maxSize = 2500, pruneChunk = 500 }: DedupSetOptions = {}) {
    this.ids = new Set();
    this.maxSize = maxSize;
    this.pruneChunk = pruneChunk;
  }

  /** Returns true if the id is new and was added; false if it was already seen. */
  add(id: string): boolean {
    if (this.ids.has(id)) return false;
    this.ids.add(id);
    if (this.ids.size > this.maxSize) {
      const iter = this.ids.values();
      for (let i = 0; i < this.pruneChunk; i++) {
        const val = iter.next().value;
        if (val !== undefined) this.ids.delete(val);
        else break;
      }
    }
    return true;
  }

  clear(): void {
    this.ids.clear();
  }

  get size(): number {
    return this.ids.size;
  }
}

/**
 * React-friendly wrapper around `DedupSet` — the underlying instance is
 * stable across renders because we hold it in a ref via lazy initializer.
 */
export function useDedupSet(options?: DedupSetOptions): DedupSet {
  const [instance] = useState(() => new DedupSet(options));
  return instance;
}

/**
 * Heartbeat watchdog. The consumer calls `arm(timeoutMs, onTimeout)` after
 * every successful message; if no message arrives within `timeoutMs`, the
 * `onTimeout` callback fires. `disarm()` cancels the pending timer.
 *
 * This is the SSE equivalent of a TCP keep-alive. The EventSource spec
 * has no built-in liveness signal, so we have to infer it from message
 * timing. Without this, a half-open connection (e.g. NAT timeout on a
 * 12-hour scan) would silently starve the UI.
 */
export function useHeartbeat() {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const disarm = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const arm = useCallback((timeoutMs: number, onTimeout: () => void) => {
    disarm();
    timerRef.current = setTimeout(() => {
      timerRef.current = null;
      onTimeout();
    }, timeoutMs);
  }, [disarm]);

  // Always disarm on unmount; otherwise an arm() from a still-in-flight
  // event handler could fire `onTimeout` against a torn-down component.
  useEffect(() => disarm, [disarm]);

  return { arm, disarm };
}
