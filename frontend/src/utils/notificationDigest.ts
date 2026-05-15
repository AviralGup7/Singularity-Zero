/**
 * NotificationDigest - Buffers notifications and flushes them as digests
 * after a throttle period to reduce notification spam.
 */
interface NotificationItem {
  id: string;
  type: 'scan_complete' | 'scan_failed' | 'new_finding' | 'error' | 'info';
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  message: string;
  timestamp: number;
}

interface DigestConfig {
  throttleMs?: number;
  maxItems?: number;
  enabled?: boolean;
  onFlush?: (digests: NotificationItem[]) => void;
}

class NotificationDigest {
  private buffer: NotificationItem[] = [];
  private throttleMs: number;
  private maxItems: number;
  private enabled: boolean;
  private lastFlushTime: number = 0;
  private pendingFlushTimer: ReturnType<typeof setTimeout> | null = null;
  private onFlush: (digests: NotificationItem[]) => void;

  constructor(config?: DigestConfig) {
    this.throttleMs = config?.throttleMs ?? 30000;
    this.maxItems = config?.maxItems ?? 50;
    this.enabled = config?.enabled ?? true;
    this.onFlush = config?.onFlush ?? (() => {});
  }

  /**
   * Update the flush callback (e.g., when component re-renders with a new callback).
   */
  setFlushCallback(callback: (digests: NotificationItem[]) => void): void {
    this.onFlush = callback;
  }

  add(item: NotificationItem): void {
    if (!this.enabled) {
      return;
    }

    this.buffer.push(item);
    this.scheduleFlush();
  }

  flush(): void {
    if (!this.enabled) {
      return;
    }

    if (this.pendingFlushTimer !== null) {
      clearTimeout(this.pendingFlushTimer);
      this.pendingFlushTimer = null;
    }

    if (this.buffer.length === 0) {
      return;
    }

    const digests = this.createDigests();
    this.buffer = [];
    this.lastFlushTime = Date.now();

    this.onFlush(digests);
  }

  get bufferSize(): number {
    return this.buffer.length;
  }

  reset(): void {
    if (this.pendingFlushTimer !== null) {
      clearTimeout(this.pendingFlushTimer);
      this.pendingFlushTimer = null;
    }
    this.buffer = [];
    this.lastFlushTime = 0;
  }

  private scheduleFlush(): void {
    if (this.pendingFlushTimer !== null) {
      return;
    }

    const now = Date.now();
    const timeSinceLastFlush = now - this.lastFlushTime;
    const delay = Math.max(0, this.throttleMs - timeSinceLastFlush);

    this.pendingFlushTimer = setTimeout(() => {
      this.pendingFlushTimer = null;
      // Flush the buffer using the registered callback
      if (this.buffer.length > 0) {
        const digests = this.createDigests();
        this.buffer = [];
        this.lastFlushTime = Date.now();
        this.onFlush(digests);
      }
    }, delay);
  }

  private createDigests(): NotificationItem[] {
    if (this.buffer.length === 1) {
      return [this.buffer[0]];
    }

    const overflowCount = Math.max(0, this.buffer.length - this.maxItems);
    // Keep the MOST recent items (not oldest)
    const itemsToDigest = overflowCount > 0
      ? this.buffer.slice(-this.maxItems)
      : [...this.buffer];

    const severityCounts = this.countSeverities(itemsToDigest);
    const elapsedSeconds = Math.round((Date.now() - itemsToDigest[0].timestamp) / 1000);
    const totalIncluded = itemsToDigest.length;

    const summaryParts = [];
    if (severityCounts.critical > 0) summaryParts.push(`${severityCounts.critical} Critical`);
    if (severityCounts.high > 0) summaryParts.push(`${severityCounts.high} High`);
    if (severityCounts.medium > 0) summaryParts.push(`${severityCounts.medium} Medium`);

    const severitySummary = summaryParts.length > 0
      ? ` \u2014 ${summaryParts.join(', ')}`
      : '';

    const overflowSuffix = overflowCount > 0 ? ` (+${overflowCount} more)` : '';

    const digestItem: NotificationItem = {
      id: `digest-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      type: 'new_finding',
      severity: this.getHighestSeverity(severityCounts),
      message: `${totalIncluded} new findings in the last ${elapsedSeconds} seconds${severitySummary}${overflowSuffix}`,
      timestamp: Date.now(),
    };

    return [digestItem];
  }

  private countSeverities(items: NotificationItem[]): Record<string, number> {
    const counts: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const item of items) {
      if (item.severity && Object.prototype.hasOwnProperty.call(counts, item.severity)) {
        counts[item.severity]++;
      }
    }

    return counts;
  }

  private getHighestSeverity(counts: Record<string, number>): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const priority: Array<'critical' | 'high' | 'medium' | 'low' | 'info'> = [
      'critical',
      'high',
      'medium',
      'low',
      'info',
    ];

    for (const level of priority) {
      if (counts[level] > 0) {
        return level;
      }
    }

    return 'info';
  }
}

export { NotificationDigest };
export type { NotificationItem, DigestConfig };
