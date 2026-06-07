/**
 * High-Performance Findings Processor Web Worker
 * Handles heavy sorting, filtering, and deduplication off the main UI thread.
 *
 * Sort keys supported: `severity`, `bounty_value`, `date`, `confidence`,
 * `true_positive_probability`, `type`, `target`, `status`. Anything else falls
 * back to the field's natural ordering.
 */

export type FindingSortKey =
  | 'severity'
  | 'bounty_value'
  | 'date'
  | 'confidence'
  | 'true_positive_probability'
  | 'type'
  | 'target'
  | 'status'
  | (string & {});

export type SortDirection = 'asc' | 'desc';

export interface ProcessRequest<F = unknown> {
  type: 'PROCESS_FINDINGS';
  findings: F[];
  filters: {
    severity?: string[];
    search?: string;
    target?: string;
  };
  sort: {
    key: FindingSortKey;
    direction: SortDirection;
  };
}

export interface FindingLike {
  id: string;
  type: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  timestamp: number | string;
  target?: string;
  status?: string;
  bounty_value?: number;
  true_positive_probability?: number;
  url?: string;
}

const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function findingTimestampMs(f: FindingLike): number {
  if (typeof f.timestamp === 'number') {
    return f.timestamp > 9999999999 ? f.timestamp : f.timestamp * 1000;
  }
  return new Date(f.timestamp || 0).getTime();
}

function getSortableValue(f: FindingLike, key: string): number | string {
  switch (key) {
    case 'severity':
      return SEVERITY_WEIGHTS[f.severity] ?? 0;
    case 'bounty_value':
      return typeof f.bounty_value === 'number' ? f.bounty_value : 0;
    case 'confidence':
      return typeof f.confidence === 'number' ? f.confidence : 0;
    case 'true_positive_probability':
      return typeof f.true_positive_probability === 'number'
        ? f.true_positive_probability
        : 0;
    case 'date':
      return findingTimestampMs(f);
    default: {
      // `key` is constrained to `FindingSortKey` (a known union of safe fields).
      // eslint-disable-next-line security/detect-object-injection
      const v = (f as unknown as Record<string, unknown>)[key];
      if (typeof v === 'number') return v;
      if (typeof v === 'string') return v;
      if (v == null) return '';
      return String(v);
    }
  }
}

function compareFindings(a: FindingLike, b: FindingLike, key: string, dir: SortDirection): number {
  const va = getSortableValue(a, key);
  const vb = getSortableValue(b, key);
  let cmp: number;
  if (typeof va === 'number' && typeof vb === 'number') {
    cmp = va - vb;
  } else {
    cmp = String(va).localeCompare(String(vb));
  }
  return dir === 'asc' ? cmp : -cmp;
}

let storedFindings: FindingLike[] = [];

self.onmessage = (event: MessageEvent<ProcessRequest<FindingLike> & { findings?: FindingLike[] }>) => {
  try {
    const { type, findings, filters, sort } = event.data;

    if (type === 'PROCESS_FINDINGS') {
      if (findings) {
        storedFindings = findings;
      }
      let result = [...storedFindings];

      // 1. Filtering
      if (filters.severity && filters.severity.length > 0) {
        result = result.filter((f) => filters.severity!.includes(f.severity));
      }

      if (filters.target) {
        result = result.filter((f) => f.target === filters.target);
      }

      if (filters.search) {
        const q = filters.search.toLowerCase();
        result = result.filter((f) =>
          (f.title || '').toLowerCase().includes(q) ||
          (f.type || '').toLowerCase().includes(q) ||
          (f.description || '').toLowerCase().includes(q) ||
          (f.url || '').toLowerCase().includes(q)
        );
      }

      // 2. Deduplication (use finding ID for accurate identity)
      const seen = new Set<string>();
      result = result.filter((f) => {
        if (!f.id) return true;
        if (seen.has(f.id)) return false;
        seen.add(f.id);
        return true;
      });

      // 3. Sort
      const sortKey = sort.key;
      const sortDir = sort.direction;
      result.sort((a, b) => compareFindings(a, b, sortKey, sortDir));

      (self as unknown as Worker).postMessage({ type: 'PROCESS_COMPLETE', result });
    }
  } catch (error) {
    (self as unknown as Worker).postMessage({
      type: 'PROCESS_ERROR',
      error: error instanceof Error ? error.message : String(error),
    });
  }
};
