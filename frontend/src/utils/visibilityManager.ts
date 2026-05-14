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
  private pollIntervals: Set<ReturnType<typeof setInterval>> = new Set();

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

  registerPolling(interval: ReturnType<typeof setInterval>): void {
    this.pollIntervals.add(interval);
  }

  unregisterPolling(interval: ReturnType<typeof setInterval>): void {
    this.pollIntervals.delete(interval);
  }

  private pauseAllPolling(): void {
    this.pollIntervals.forEach((interval) => {
      clearInterval(interval);
    });
  }

  private resumeAllPolling(): void {
    this.pollIntervals.clear();
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

export function useVisibilityPause(
  pollFn: () => void,
  intervalMs: number,
  enabled = true
): (() => void) | undefined {
  if (!enabled) return undefined;

  const manager = getVisibilityManager();

  if (manager.isDocumentVisible()) {
    const interval = setInterval(pollFn, intervalMs);
    manager.registerPolling(interval);

    const cleanup = manager.registerCallbacks({
      onVisible: () => {
        pollFn();
      },
    });

    return () => {
      clearInterval(interval);
      manager.unregisterPolling(interval);
      cleanup();
    };
  }

  return undefined;
}

export function isDocumentVisible(): boolean {
  return document.visibilityState === 'visible';
}

export function onDocumentVisible(callback: () => void): () => void {
  const manager = getVisibilityManager();
  return manager.registerCallbacks({ onVisible: callback });
}

export function onDocumentHidden(callback: () => void): () => void {
  const manager = getVisibilityManager();
  return manager.registerCallbacks({ onHidden: callback });
}
