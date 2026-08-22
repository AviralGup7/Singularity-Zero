import { createMutationId, nextOfflineRetryCount, offlineRetryDelayMs } from './offlineQueuePolicy';

interface QueuedMutation<T = unknown> {
  id: string;
  execute: () => Promise<T>;
  rollback: () => void;
  timestamp: number;
  description: string;
  retries: number;
}

type QueueListener = (queue: QueuedMutation[]) => void;

class OfflineMutationQueue {
  private queue: QueuedMutation[] = [];
  private processing = false;
  private listeners = new Set<QueueListener>();
  private onlineHandler: (() => void) | null = null;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private epoch = 0;

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

  enqueue<T>(mutation: Omit<QueuedMutation<T>, 'id' | 'timestamp' | 'retries'>): void {
    const entry: QueuedMutation<T> = {
      ...mutation,
      id: createMutationId(),
      timestamp: Date.now(),
      retries: 0,
    };
    this.queue.push(entry as QueuedMutation);
    this.notify();
    // Execute immediately if online; otherwise queue for replay
    if (navigator.onLine) {
      void this.process();
    } else {
      this.ensureOnlineHandler();
    }
  }

  private ensureOnlineHandler() {
    if (this.onlineHandler) return;
    this.onlineHandler = () => {
      void this.process();
    };
    window.addEventListener('online', this.onlineHandler);
  }

  private cleanupOnlineHandler() {
    if (this.onlineHandler) {
      window.removeEventListener('online', this.onlineHandler);
      this.onlineHandler = null;
    }
  }

  private stillCurrent(epoch: number, mutationId?: string): boolean {
    if (epoch !== this.epoch) return false;
    if (mutationId && this.queue[0]?.id !== mutationId) return false;
    return true;
  }

  async process(): Promise<void> {
    if (this.processing || this.queue.length === 0) return;
    this.processing = true;
    const epoch = this.epoch;

    while (this.queue.length > 0) {
      if (epoch !== this.epoch) {
        return;
      }
      if (!navigator.onLine) {
        this.processing = false;
        return;
      }

      const mutation = this.queue[0];
      try {
        await mutation.execute();
        if (!this.stillCurrent(epoch, mutation.id)) return;
        this.queue.shift();
        this.notify();
      } catch (error) {
        if (!this.stillCurrent(epoch, mutation.id)) return;
        console.warn('offline mutation failed', mutation.description, error);
        const retries = nextOfflineRetryCount(mutation.retries);
        if (retries === null) {
          this.queue.shift();
          this.notify();
          continue;
        }
        this.queue[0] = { ...mutation, retries };
        this.processing = false;
        this.ensureOnlineHandler();
        if (this.retryTimer) clearTimeout(this.retryTimer);
        this.retryTimer = setTimeout(() => {
          this.retryTimer = null;
          void this.process();
        }, offlineRetryDelayMs(retries));
        return;
      }
    }

    if (epoch !== this.epoch) return;
    this.processing = false;
    this.cleanupOnlineHandler();
    this.notify();
  }

  clear(): void {
    this.epoch += 1;
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    this.queue = [];
    this.processing = false;
    this.notify();
  }

  rollbackAll(): void {
    this.epoch += 1;
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    const pending = [...this.queue];
    this.queue = [];
    this.processing = false;
    pending.reverse().forEach((m) => {
      try {
        m.rollback();
      } catch (error) {
        console.warn('offline mutation rollback failed', m.description, error);
      }
    });
    this.notify();
  }

  getQueue(): QueuedMutation[] {
    return [...this.queue];
  }
}

export const offlineQueue = new OfflineMutationQueue();
export { OfflineMutationQueue };
export type { QueuedMutation };
