export function shouldRestartPausedPoll(ms: number): boolean {
  return Number.isFinite(ms) && ms > 0;
}

type VisibilityState = 'visible' | 'hidden' | 'prerender';

interface VisibilityCallbacks {
  onVisible?: () => void;
  onHidden?: () => void;
  onStateChange?: (state: VisibilityState) => void;
}

class VisibilityManager {
  // FIX: Use arrays to store multiple callbacks per event type
  private callbacks: {
    onVisible: (() => void)[];
    onHidden: (() => void)[];
    onStateChange: ((state: VisibilityState) => void)[];
  } = {
    onVisible: [],
    onHidden: [],
    onStateChange: [],
  };
  private isPaused = false;
  private pollIntervals = new Map<ReturnType<typeof setInterval>, { fn: () => void; ms: number }>();

  constructor() {
    this.bindVisibilityChange();
  }

  private bindVisibilityChange(): void {
    document.addEventListener('visibilitychange', this.handleVisibilityChange);
  }

  private handleVisibilityChange = (): void => {
    const state = document.visibilityState as VisibilityState;

    if (state === 'visible') {
      this.isPaused = false;
      this.callbacks.onVisible.forEach(cb => cb());
      this.resumeAllPolling();
    } else if (state === 'hidden') {
      this.isPaused = true;
      this.callbacks.onHidden.forEach(cb => cb());
      this.pauseAllPolling();
    }

    this.callbacks.onStateChange.forEach(cb => cb(state));
  };

  // FIX: Accept single callbacks, store them in arrays internally
  registerCallbacks(callbacks: VisibilityCallbacks): () => void {
   
    const unsubscribers: (() => void)[] = [];

    if (callbacks.onVisible) {
      const cb = callbacks.onVisible;
      this.callbacks.onVisible.push(cb);
      unsubscribers.push(() => {
        const idx = this.callbacks.onVisible.indexOf(cb);
        if (idx !== -1) this.callbacks.onVisible.splice(idx, 1);
      });
    }
    if (callbacks.onHidden) {
      const cb = callbacks.onHidden;
      this.callbacks.onHidden.push(cb);
      unsubscribers.push(() => {
        const idx = this.callbacks.onHidden.indexOf(cb);
        if (idx !== -1) this.callbacks.onHidden.splice(idx, 1);
      });
    }
    if (callbacks.onStateChange) {
      const cb = callbacks.onStateChange;
      this.callbacks.onStateChange.push(cb);
      unsubscribers.push(() => {
        const idx = this.callbacks.onStateChange.indexOf(cb);
        if (idx !== -1) this.callbacks.onStateChange.splice(idx, 1);
      });
    }

    return () => unsubscribers.forEach(fn => fn());
  }

  isDocumentVisible(): boolean {
    return document.visibilityState === 'visible';
  }

  getIsPaused(): boolean {
    return this.isPaused;
  }

  registerPolling(interval: ReturnType<typeof setInterval>, fn?: () => void, ms?: number): void {
    this.pollIntervals.set(interval, { fn: fn ?? (() => {}), ms: ms ?? 0 });
  }

  unregisterPolling(interval: ReturnType<typeof setInterval>): void {
    this.pollIntervals.delete(interval);
  }

  private pauseAllPolling(): void {
    this.pollIntervals.forEach((_meta, interval) => {
      clearInterval(interval);
    });
  }

  private resumeAllPolling(): void {
    const next = new Map<ReturnType<typeof setInterval>, { fn: () => void; ms: number }>();
    this.pollIntervals.forEach((meta) => {
      if (meta.ms > 0) {
        next.set(setInterval(meta.fn, meta.ms), meta);
      }
    });
    this.pollIntervals = next;
  }

  destroy(): void {
    document.removeEventListener('visibilitychange', this.handleVisibilityChange);
    this.pollIntervals.clear();
  }
}

let visibilityManagerInstance: VisibilityManager | null = null;

export function getVisibilityManager(): VisibilityManager {
  if (!visibilityManagerInstance) {
    visibilityManagerInstance = new VisibilityManager();
  }
  return visibilityManagerInstance;
}

export function isDocumentVisible(): boolean {
  return document.visibilityState === 'visible';
}
