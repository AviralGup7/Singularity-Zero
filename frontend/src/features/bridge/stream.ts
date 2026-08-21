import { ConsoleClient } from './client';

export interface StreamFrame {
  id: string;
  type: string;
  topic: string;
  timestamp: number;
  payload: Record<string, unknown>;
}

export class ConsoleStream {
  private afterId: string | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private readonly client: ConsoleClient;
  private readonly onFrame: (frame: StreamFrame) => void;
  private readonly intervalMs: number;

  constructor(client: ConsoleClient, onFrame: (frame: StreamFrame) => void, intervalMs = 2500) {
    this.client = client;
    this.onFrame = onFrame;
    this.intervalMs = intervalMs;
  }

  start(): void {
    if (this.timer) return;
    void this.poll();
    this.timer = setInterval(() => {
      void this.poll();
    }, this.intervalMs);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private async poll(): Promise<void> {
    const query: Record<string, unknown> = { limit: 50 };
    if (this.afterId) query.after = this.afterId;
    const response = await this.client.call<{ events?: StreamFrame[] }>('stream.poll', {}, { query });
    if (!response.ok) return;
    const events = response.data.events ?? [];
    for (const frame of events) {
      if (frame.type === 'heartbeat') continue;
      this.onFrame(frame);
      this.afterId = frame.id;
    }
  }
}
