/**
 * Frontend ↔ backend contract helpers.
 *
 * The dashboard API mixes camelCase console fields with snake_case disk
 * payloads and two status vocabularies (open/closed vs active/resolved).
 * Every list/detail/update path should go through these helpers so a
 * finding the table just mutated is readable when it comes back.
 */

export type FindingStatusApi = 'open' | 'closed' | 'accepted' | 'false_positive';

export const FINDING_STATUS_TO_API: Record<string, FindingStatusApi> = {
  open: 'open',
  active: 'open',
  new: 'open',
  closed: 'closed',
  resolved: 'closed',
  accepted: 'accepted',
  ignored: 'accepted',
  false_positive: 'false_positive',
  'false-positive': 'false_positive',
  fp: 'false_positive',
};

export const FINDING_FIELD_TO_API: Record<string, string> = {
  assignedTo: 'assignee',
  assignee: 'assignee',
  falsePositive: 'false_positive',
  false_positive: 'false_positive',
  fpStatus: 'fp_status',
  fp_status: 'fp_status',
  fpJustification: 'fp_justification',
  fp_justification: 'fp_justification',
  kanbanStatus: 'kanban_status',
  kanban_status: 'kanban_status',
  bounty_value: 'bounty_value',
  bountyValue: 'bounty_value',
  bounty_currency: 'bounty_currency',
  bountyCurrency: 'bounty_currency',
  bounty_source: 'bounty_source',
  bountySource: 'bounty_source',
  already_reported: 'already_reported',
  alreadyReported: 'already_reported',
  duplicates: 'duplicates',
  status: 'status',
  severity: 'severity',
  notes: 'notes',
  tags: 'tags',
  decision: 'decision',
  title: 'title',
  description: 'description',
  lifecycle_state: 'lifecycle_state',
  lifecycleState: 'lifecycle_state',
  scope_match: 'scope_match',
  scopeMatch: 'scope_match',
  remediation_status: 'remediation_status',
  remediationStatus: 'remediation_status',
  remediation_notes: 'remediation_notes',
  remediationNotes: 'remediation_notes',
  _deleted: '_deleted',
};

export const JOB_STATUSES = ['running', 'completed', 'failed', 'stopped', 'paused', 'queued'] as const;
export type JobStatusApi = (typeof JOB_STATUSES)[number];

export function canonicalizeJobStatus(value: unknown): JobStatusApi {
  const raw = asString(value || 'queued').trim().toLowerCase();
  return (JOB_STATUSES as readonly string[]).includes(raw) ? (raw as JobStatusApi) : 'queued';
}

export interface PageEnvelope<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  hasNext: boolean;
  hasPrev: boolean;
}

export function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export function asString(value: unknown, fallback = ''): string {
  if (value == null) return fallback;
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return fallback;
}

export function asNumber(value: unknown, fallback = 0): number {
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(n) ? n : fallback;
}

export function asBoolean(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  if (typeof value === 'string') return value === 'true' || value === '1' || value === 'yes';
  return false;
}

export function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => asString(item)).filter(Boolean);
}

export function canonicalizeFindingStatus(value: unknown): FindingStatusApi {
  const key = asString(value).trim().toLowerCase();
  return FINDING_STATUS_TO_API[key] ?? 'open';
}

export function mapFindingUpdate(input: Record<string, unknown>): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    const apiKey = FINDING_FIELD_TO_API[key];
    if (!apiKey) continue;
    if (apiKey === 'status') {
      body.status = canonicalizeFindingStatus(value);
      continue;
    }
    if (apiKey === 'false_positive') {
      body.false_positive = asBoolean(value);
      if (asBoolean(value) && body.fp_status == null) body.fp_status = 'approved';
      continue;
    }
    body[apiKey] = value;
  }
  return body;
}

export function normalizeFindingRecord(raw: unknown): Record<string, unknown> | null {
  const rec = asRecord(raw);
  if (!rec) return null;
  const id = asString(rec.id || rec.finding_id);
  if (!id) return null;
  const status = canonicalizeFindingStatus(
    rec.status || (asBoolean(rec.false_positive) || asBoolean(rec.falsePositive) ? 'false_positive' : 'open'),
  );
  const timestamp = rec.timestamp ?? rec.date ?? rec.generated_at ?? '';
  return {
    ...rec,
    id,
    job_id: asString(rec.job_id || rec.run_name || rec.runId),
    target_id: asString(rec.target_id || rec.target || rec.target_name),
    target: asString(rec.target || rec.target_name || rec.target_id),
    type: asString(rec.type || rec.category || 'finding') || 'finding',
    title: asString(rec.title || rec.description || rec.type || 'Finding'),
    description: asString(rec.description || rec.title),
    severity: asString(rec.severity || 'info').toLowerCase(),
    status,
    timestamp,
    confidence: asNumber(rec.confidence, 0),
    assignedTo: rec.assignedTo ?? rec.assignee ?? '',
    assignee: rec.assignee ?? rec.assignedTo ?? '',
    falsePositive: asBoolean(rec.falsePositive ?? rec.false_positive),
    false_positive: asBoolean(rec.false_positive ?? rec.falsePositive),
    fpStatus: rec.fpStatus ?? rec.fp_status ?? 'none',
    fpJustification: rec.fpJustification ?? rec.fp_justification ?? '',
    kanbanStatus: rec.kanbanStatus ?? rec.kanban_status,
    duplicates: asStringArray(rec.duplicates),
    bounty_value: rec.bounty_value != null ? asNumber(rec.bounty_value) : rec.bountyValue != null ? asNumber(rec.bountyValue) : undefined,
    url: rec.url != null ? asString(rec.url) : undefined,
    host: rec.host != null ? asString(rec.host) : undefined,
  };
}

export function readPageEnvelope<T>(
  raw: unknown,
  itemKey: string,
  normalizeItem: (value: unknown) => T | null,
): PageEnvelope<T> {
  const rec = asRecord(raw);
  const source = rec
    ? Array.isArray(rec[itemKey])
      ? rec[itemKey]
      : Array.isArray(rec.items)
        ? rec.items
        : []
    : Array.isArray(raw)
      ? raw
      : [];
  const items = (source as unknown[]).map(normalizeItem).filter((item): item is T => item != null);
  const total = rec ? asNumber(rec.total, items.length) : items.length;
  const page = rec ? Math.max(1, asNumber(rec.page, 1)) : 1;
  const pageSize = rec ? Math.max(1, asNumber(rec.page_size ?? rec.pageSize, items.length || 1)) : items.length || 1;
  return {
    items,
    total,
    page,
    pageSize,
    hasNext: rec ? asBoolean(rec.has_next ?? rec.hasNext) || page * pageSize < total : false,
    hasPrev: rec ? asBoolean(rec.has_prev ?? rec.hasPrev) || page > 1 : page > 1,
  };
}

export function parseRetryAfterMs(headers: unknown, fallbackMs = 5000): number {
  const bag = headers as { get?: (name: string) => string | null; ['retry-after']?: string; ['Retry-After']?: string } | undefined;
  const raw =
    (typeof bag?.get === 'function' ? bag.get('retry-after') : undefined) ??
    bag?.['retry-after'] ??
    bag?.['Retry-After'];
  if (!raw) return fallbackMs;
  const seconds = Number(raw);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(60_000, Math.max(500, seconds * 1000));
  const when = Date.parse(raw);
  if (Number.isFinite(when)) return Math.min(60_000, Math.max(500, when - Date.now()));
  return fallbackMs;
}

export function flattenApiDetail(detail: unknown): string {
  if (typeof detail === 'string' && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((entry) => {
        const rec = asRecord(entry);
        if (!rec) return asString(entry);
        return asString(rec.message || rec.msg || rec.detail);
      })
      .filter(Boolean)
      .join('; ');
  }
  const rec = asRecord(detail);
  if (!rec) return '';
  return asString(rec.message || rec.detail || rec.error);
}

export interface JobListQuery {
  page?: number;
  page_size?: number;
  status?: string;
  search?: string;
  sort_by?: string;
  sort_dir?: 'asc' | 'desc';
}

export function toJobListParams(query: JobListQuery = {}): Record<string, unknown> {
  const params: Record<string, unknown> = {
    page: query.page ?? 1,
    page_size: Math.min(200, Math.max(1, query.page_size ?? 100)),
    sort_by: query.sort_by ?? 'started_at',
    sort_order: query.sort_dir ?? 'desc',
  };
  if (query.status && query.status !== 'all') params.status = query.status;
  if (query.search?.trim()) params.search = query.search.trim();
  return params;
}

export interface FindingListQuery {
  page?: number;
  page_size?: number;
  severity?: string;
  search?: string;
  target?: string;
  sort_by?: string;
  sort_dir?: 'asc' | 'desc';
}

export function toFindingListParams(query: FindingListQuery = {}): Record<string, unknown> {
  const params: Record<string, unknown> = {
    page: query.page ?? 1,
    page_size: Math.min(1000, Math.max(1, query.page_size ?? 100)),
  };
  if (query.severity) params.severity = query.severity;
  if (query.search?.trim()) params.search = query.search.trim();
  if (query.target?.trim()) params.target = query.target.trim();
  return params;
}

/**
 * Walk every remaining page until the envelope says there is no next page.
 * A high circuit-breaker only exists to stop a broken API from looping;
 * it is not a silent data cap — if it trips we throw instead of dropping rows.
 */
export async function collectAllPages<T, Q extends { page_size?: number }>(
  fetchPage: (query: Q & { page: number; page_size: number }, signal?: AbortSignal) => Promise<PageEnvelope<T>>,
  query: Q,
  signal?: AbortSignal,
  maxPages = 500,
): Promise<T[]> {
  const pageSize = Math.max(1, query.page_size ?? 100);
  const items: T[] = [];
  for (let page = 1; page <= maxPages; page += 1) {
    const envelope = await fetchPage({ ...query, page, page_size: pageSize }, signal);
    items.push(...envelope.items);
    const exhausted =
      !envelope.hasNext ||
      envelope.items.length === 0 ||
      items.length >= envelope.total;
    if (exhausted) return items;
  }
  throw new Error(`List pagination exceeded ${maxPages} pages without completing`);
}
