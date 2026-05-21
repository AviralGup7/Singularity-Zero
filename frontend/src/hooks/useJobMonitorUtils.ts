import type {
  Job,
  ProgressTelemetry,
  StageProgressEntry,
} from '../types/api';

const STAGE_ORDER = [
  'startup',
  'subdomains',
  'live_hosts',
  'urls',
  'parameters',
  'ranking',
  'priority',
  'passive_scan',
  'active_scan',
  'nuclei',
  'access_control',
  'validation',
  'intelligence',
  'reporting',
  'completed',
];

function stageIndex(stage: string | undefined): number {
  if (!stage) return -1;
  return STAGE_ORDER.indexOf(stage);
}

export function estimateStagePercent(stage: string | undefined, progressPercent: number | undefined): number {
  if (!stage || typeof progressPercent !== 'number') {
    return 0;
  }
  const idx = stageIndex(stage);
  if (idx < 0) {
    return 0;
  }
  const total = STAGE_ORDER.length;
  const start = (idx / total) * 100;
  const end = ((idx + 1) / total) * 100;
  if (progressPercent <= start) return 0;
  if (progressPercent >= end) return 100;
  return Math.max(0, Math.min(100, Math.round(((progressPercent - start) / (end - start)) * 100)));
}

export function normalizeActiveTimeline(
  entries: StageProgressEntry[],
  currentStage: string | undefined,
   
  status: Job['status'] | undefined
): StageProgressEntry[] {
  if (!entries.length) return entries;
  const activeIndex = stageIndex(currentStage);
  return entries.map((entry) => {
    if (activeIndex < 0) {
      return entry;
    }
    const idx = stageIndex(entry.stage);
    if (idx >= 0 && idx < activeIndex && status === 'running' && entry.status === 'running') {
      return { ...entry, status: 'completed', percent: 100 };
    }
    if (
      status === 'running' &&
      idx > activeIndex &&
      (entry.status === 'completed' || entry.status === 'running' || entry.status === 'error')
    ) {
      return {
        ...entry,
        status: 'pending',
        percent: 0,
        reason: '',
        error: '',
      };
    }
    return entry;
  });
}

export function compactPipelineError(raw: unknown): string {
  const input = String(raw || '').trim();
  if (!input) return 'Unknown pipeline error';
  const importIdx = input.indexOf('Import failed:');
  if (importIdx >= 0) {
    return input.slice(importIdx).trim();
  }
  let collapsed = input.replace(/\s+/g, ' ');
  
  // Find all NVD rate limit messages using a simple literal pattern to avoid any regex warnings
  const pattern = /Rate limited by NVD CVE, retrying after /gi;
  const matches = [...collapsed.matchAll(pattern)];
  const validMatches: Array<{ index: number; length: number }> = [];
  
  for (const m of matches) {
    const startIndex = m.index;
    if (typeof startIndex !== 'number') continue;
    const matchStr = m[0];
    const afterIndex = startIndex + matchStr.length;
    
    let i = afterIndex;
    while (i < collapsed.length && collapsed.charCodeAt(i) >= 48 && collapsed.charCodeAt(i) <= 57) {
      i++;
    }
    if (i > afterIndex) {
      if (collapsed.charAt(i) === '.') {
        i++;
        const decimalStart = i;
        while (i < collapsed.length && collapsed.charCodeAt(i) >= 48 && collapsed.charCodeAt(i) <= 57) {
          i++;
        }
        if (i === decimalStart) {
          continue;
        }
      }
      if (collapsed.charAt(i) === 's' || collapsed.charAt(i) === 'S') {
        i++;
        validMatches.push({
          index: startIndex,
          length: i - startIndex
        });
      }
    }
  }

  if (validMatches.length >= 2) {
    let isConsecutive = true;
    for (let i = 0; i < validMatches.length - 1; i++) {
      const current = validMatches.at(i);
      const next = validMatches.at(i + 1);
      if (!current || !next) continue;
      const between = collapsed.slice(current.index + current.length, next.index).trim();
      if (between !== '') {
        isConsecutive = false;
        break;
      }
    }
    if (isConsecutive) {
      const first = validMatches.at(0);
      const last = validMatches.at(validMatches.length - 1);
      if (first && last) {
        collapsed = collapsed.slice(0, first.index) + 'Rate limited by NVD CVE; backing off retries ' + collapsed.slice(last.index + last.length);
      }
    }
  }
  return collapsed.trim() || 'Unknown pipeline error';
}

export function synthesizeCurrentStageEntry(jobLike: Partial<Job>): StageProgressEntry | null {
  if (!jobLike.stage) {
    return null;
  }
  const basePercent =
    typeof jobLike.stage_percent === 'number'
      ? jobLike.stage_percent
      : typeof jobLike.stage_processed === 'number' &&
          typeof jobLike.stage_total === 'number' &&
          jobLike.stage_total > 0
        ? Math.round((jobLike.stage_processed / jobLike.stage_total) * 100)
        : estimateStagePercent(jobLike.stage, jobLike.progress_percent);

   
  const normalizedStatus: StageProgressEntry['status'] =
    jobLike.status === 'failed' || jobLike.status === 'stopped'
      ? 'error'
      : jobLike.status === 'completed'
        ? 'completed'
        : 'running';

  return {
    stage: jobLike.stage,
    stage_label: jobLike.stage_label || jobLike.stage,
    status: normalizedStatus,
    processed: typeof jobLike.stage_processed === 'number' ? jobLike.stage_processed : 0,
    total: typeof jobLike.stage_total === 'number' ? jobLike.stage_total : null,
    percent: Math.max(0, Math.min(100, basePercent)),
    reason: typeof jobLike.status_message === 'string' ? jobLike.status_message : '',
    error: normalizedStatus === 'error' ? String(jobLike.error || '') : '',
    updated_at: Date.now() / 1000,
  };
}

export function normalizeStageEntry(input: Partial<StageProgressEntry> & { stage: string }): StageProgressEntry {
  const rawStatus = String(input.status || 'running').toLowerCase();
   
  const normalizedStatus: StageProgressEntry['status'] =
    rawStatus === 'error' || rawStatus === 'failed' || rawStatus === 'timeout'
      ? 'error'
      : rawStatus === 'completed' || rawStatus === 'success'
        ? 'completed'
        : rawStatus === 'pending'
          ? 'pending'
          : rawStatus === 'skipped' || rawStatus === 'skip'
            ? 'skipped'
            : 'running';

  return {
    stage: input.stage,
    stage_label: input.stage_label || input.stage,
    status: normalizedStatus,
    processed: typeof input.processed === 'number' ? input.processed : 0,
    total: typeof input.total === 'number' ? input.total : null,
    percent: typeof input.percent === 'number' ? Math.max(0, Math.min(100, input.percent)) : 0,
    reason: typeof input.reason === 'string' ? input.reason : '',
    error: typeof input.error === 'string' ? input.error : '',
    retry_count: typeof input.retry_count === 'number' ? input.retry_count : 0,
    last_event: typeof input.last_event === 'string' ? input.last_event : '',
    started_at: typeof input.started_at === 'number' ? input.started_at : undefined,
    updated_at: typeof input.updated_at === 'number' ? input.updated_at : undefined,
  };
}

export function mergeTelemetry(
  base: ProgressTelemetry | undefined,
  incoming: Record<string, unknown> | ProgressTelemetry | undefined
): ProgressTelemetry {
  const merged = new Map<string, unknown>(Object.entries(base || {}));
  if (!incoming) return Object.fromEntries(merged) as ProgressTelemetry;
   
  for (const [key, value] of Object.entries(incoming)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      merged.set(key, value.slice());
      continue;
    }
    if (typeof value === 'object') {
      const previous = merged.get(key);
      if (previous && typeof previous === 'object' && !Array.isArray(previous)) {
        merged.set(key, { ...(previous as object), ...(value as object) });
      } else {
        merged.set(key, { ...(value as object) });
      }
      continue;
    }
    merged.set(key, value);
  }
  return Object.fromEntries(merged) as ProgressTelemetry;
}

export function mergeStageProgressLists(
  restStages: StageProgressEntry[] | undefined,
  sseStages: StageProgressEntry[]
): StageProgressEntry[] {
  const merged = new Map<string, StageProgressEntry>();
  for (const stage of restStages || []) {
    merged.set(stage.stage, normalizeStageEntry(stage));
  }
  for (const stage of sseStages) {
    const normalized = normalizeStageEntry(stage);
    const existing = merged.get(normalized.stage);
    if (!existing) {
      merged.set(normalized.stage, normalized);
      continue;
    }
    const existingTime = existing.updated_at ?? existing.started_at ?? 0;
    const incomingTime = normalized.updated_at ?? normalized.started_at ?? 0;
    const incomingWins =
      incomingTime >= existingTime ||
      (existing.percent === 0 && normalized.percent > 0) ||
      (existing.status === 'running' &&
        (normalized.status === 'error' || normalized.status === 'completed' || normalized.status === 'skipped'));
    merged.set(
      normalized.stage,
      incomingWins
        ? { ...existing, ...normalized }
        : { ...normalized, ...existing }
    );
  }
  return Array.from(merged.values()).sort((a, b) => {
    const aIndex = STAGE_ORDER.indexOf(a.stage);
    const bIndex = STAGE_ORDER.indexOf(b.stage);
    if (aIndex === -1 && bIndex === -1) return a.stage.localeCompare(b.stage);
    if (aIndex === -1) return 1;
    if (bIndex === -1) return -1;
    return aIndex - bIndex;
  });
}
