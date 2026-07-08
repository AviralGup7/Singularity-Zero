interface QueuedMutation<T = unknown> {
  id: string;
  execute: () => Promise<T>;
  rollback: () => void;
  timestamp: number;
  description: string;
}

type QueueListener = (queue: QueuedMutation[]) => void;

class OfflineMutationQueue {
  private queue: QueuedMutation[] = [];
  private processing = false;
  private listeners = new Set<QueueListener>();
  private onlineHandler: (() => void) | null = null;

  private notify() {
    this.listeners.forEach((fn) => fn([...this.queue]));
  }

  subscribe(listener: QueueListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  get length(): number {
    return this.queue.length;
  }

  enqueue<T>(mutation: Omit<QueuedMutation<T>, 'id' | 'timestamp'>): void {
    const entry: QueuedMutation<T> = {
      ...mutation,
      id: crypto.randomUUID(),
      timestamp: Date.now(),
    };
    this.queue.push(entry as QueuedMutation);
    this.notify();
    // Execute immediately if online; otherwise queue for replay
    if (navigator.onLine) {
      this.process();
    } else {
      this.ensureOnlineHandler();
    }
  }

  private ensureOnlineHandler() {
    if (this.onlineHandler) return;
    this.onlineHandler = () => {
      this.process();
    };
    window.addEventListener('online', this.onlineHandler);
  }

  private cleanupOnlineHandler() {
    if (this.onlineHandler) {
      window.removeEventListener('online', this.onlineHandler);
      this.onlineHandler = null;
    }
  }

  async process(): Promise<void> {
    if (this.processing || this.queue.length === 0) return;
    this.processing = true;

    while (this.queue.length > 0) {
      if (!navigator.onLine) {
        this.processing = false;
        return;
      }

      const mutation = this.queue[0];
      try {
        await mutation.execute();
        this.queue.shift();
        this.notify();
      } catch {
        // Failed — keep in queue for retry
        this.processing = false;
        return;
      }
    }

    this.processing = false;
    this.cleanupOnlineHandler();
    this.notify();
  }

  clear(): void {
    this.queue = [];
    this.processing = false;
    this.notify();
  }

  rollbackAll(): void {
    [...this.queue].reverse().forEach((m) => m.rollback());
    this.queue = [];
    this.processing = false;
    this.notify();
  }

  getQueue(): QueuedMutation[] {
    return [...this.queue];
  }
}

export const offlineQueue = new OfflineMutationQueue();
export type { QueuedMutation };
