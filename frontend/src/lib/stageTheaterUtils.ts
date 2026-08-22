import type { Job, StageProgressEntry } from '@/types/api';

export type StageTheaterStatus = 'pending' | 'ready' | 'running' | 'completed' | 'error' | 'skipped';

export interface StageGraph {
  nodes: string[];
  edges: Array<[string, string] | string[]>;
  levels?: string[][];
  labels?: Record<string, string>;
}

/** Fallback DAG matching the orchestrator _BASE_NODES edges. */
export const DEFAULT_STAGE_EDGES: Array<[string, string]> = [
  ['startup', 'subdomains'],
  ['subdomains', 'live_hosts'],
  ['subdomains', 'subdomain_takeover'],
  ['live_hosts', 'waf'],
  ['live_hosts', 'urls'],
  ['urls', 'git_diff_crawl'],
  ['urls', 'parameters'],
  ['urls', 'ranking'],
  ['parameters', 'ranking'],
  ['waf', 'ranking'],
  ['urls', 'recon_validation'],
  ['ranking', 'passive_scan'],
  ['live_hosts', 'passive_scan'],
  ['urls', 'passive_scan'],
  ['passive_scan', 'active_scan'],
  ['passive_scan', 'semgrep'],
  ['passive_scan', 'nuclei'],
  ['passive_scan', 'access_control'],
  ['ranking', 'access_control'],
  ['passive_scan', 'validation'],
  ['active_scan', 'validation'],
  ['passive_scan', 'intelligence'],
  ['active_scan', 'intelligence'],
  ['nuclei', 'intelligence'],
  ['validation', 'intelligence'],
  ['intelligence', 'threat_modeling'],
  ['intelligence', 'reporting'],
  ['nuclei', 'reporting'],
  ['access_control', 'reporting'],
  ['validation', 'reporting'],
  ['passive_scan', 'reporting'],
  ['threat_modeling', 'reporting'],
  ['reporting', 'sarif_export'],
];

export interface StageTheaterNode {
  id: string;
  label: string;
  status: StageTheaterStatus;
  percent: number;
  activeCount?: number;
  completedCount?: number;
  errorCount?: number;
}

const DEFAULT_STAGE_ORDER = [
  'startup',
  'subdomains',
  'live_hosts',
  'urls',
  'parameters',
  'ranking',
  'passive_scan',
  'active_scan',
  'semgrep',
  'nuclei',
  'access_control',
  'validation',
  'intelligence',
  'reporting',
];

const STAGE_LABELS: Record<string, string> = {
  startup: 'Preparing',
  subdomains: 'Subdomains',
  live_hosts: 'Live Hosts',
  urls: 'URLs',
  recon_validation: 'Recon Validation',
  waf: 'WAF',
  git_diff_crawl: 'Diff Crawl',
  parameters: 'Parameters',
  ranking: 'Ranking',
  passive_scan: 'Passive',
  active_scan: 'Active Scan',
  semgrep: 'Semgrep',
  nuclei: 'Nuclei',
  subdomain_takeover: 'Takeover',
  access_control: 'Access',
  validation: 'Validation',
  intelligence: 'Intel',
  threat_modeling: 'Threat Model',
  reporting: 'Report',
  sarif_export: 'SARIF',
};

const STAGE_ALIASES: Record<string, string> = {
  priority: 'ranking',
};

export function normalizeStageName(stageName: string | undefined): string {
  const normalized = String(stageName || '').trim().toLowerCase();
  if (!normalized) return '';
  return Object.prototype.hasOwnProperty.call(STAGE_ALIASES, normalized) ? Reflect.get(STAGE_ALIASES, normalized) : normalized;
}

function normalizeStageProgress(entries: StageProgressEntry[]): Map<string, StageProgressEntry> {
  const stageMap = new Map<string, StageProgressEntry>();
  for (const entry of entries) {
    const normalizedStage = normalizeStageName(entry.stage);
    if (!normalizedStage) continue;
    stageMap.set(normalizedStage, {
      ...entry,
      stage: normalizedStage,
    });
  }
  return stageMap;
}

   
function resolveStageOrder(jobs: Job[]): string[] {
   
  const order = [...DEFAULT_STAGE_ORDER];
  const seen = new Set(order);

  const addStage = (stageName: string | undefined) => {
    const normalized = normalizeStageName(stageName);
    if (!normalized || seen.has(normalized)) return;
    if (normalized === 'recon_validation') {
      const urlsIndex = order.indexOf('urls');
      if (urlsIndex >= 0) {
        order.splice(urlsIndex + 1, 0, normalized);
      } else {
        order.push(normalized);
      }
      seen.add(normalized);
      return;
    }
    order.push(normalized);
    seen.add(normalized);
  };

  for (const job of jobs) {
    addStage(job.stage);
    addStage(job.failed_stage);
    for (const entry of job.stage_progress ?? []) {
      addStage(entry.stage);
    }
  }

  return order;
}

function findStageLabelFromJobs(jobs: Job[], stageName: string): string {
  for (const job of jobs) {
    const normalizedStage = normalizeStageName(job.stage);
    if (normalizedStage === stageName && (job.stage_label || '').trim()) {
      return String(job.stage_label).trim();
    }
    for (const entry of job.stage_progress ?? []) {
      if (normalizeStageName(entry.stage) === stageName && (entry.stage_label || '').trim()) {
        return String(entry.stage_label).trim();
      }
    }
  }
  return Object.prototype.hasOwnProperty.call(STAGE_LABELS, stageName)
    ? Reflect.get(STAGE_LABELS, stageName)
    : stageName.replace(/_/g, ' ');
}

function clampPercent(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function resolveSingleStageStatus(
  job: Job,
  stageName: string,
  index: number,
  currentIndex: number,
  existing: StageProgressEntry | undefined
): StageTheaterStatus {
  if (existing?.status === 'error') return 'error';
  if (existing?.status === 'skipped') return 'skipped';
  if (existing?.status === 'completed') return 'completed';
  if (existing?.status === 'running') return 'running';
  if (existing?.status === 'pending') return 'pending';
  if (existing?.status === 'ready') return 'ready';

  if (job.status === 'failed' && normalizeStageName(job.failed_stage) === stageName) return 'error';
  if (index === currentIndex && job.status === 'running') return 'running';
  return 'pending';
}

function estimateStagePercent(
  job: Job,
  stageName: string,
  stageIndex: number,
  currentIndex: number,
  stageOrder: string[]
): number {
  if (stageName === normalizeStageName(job.stage)) {
    if (typeof job.stage_percent === 'number') {
      return clampPercent(job.stage_percent);
    }
    if (typeof job.progress_percent === 'number') {
      const span = 100 / Math.max(1, stageOrder.length);
      const lower = stageIndex * span;
      const upper = lower + span;
      if (job.progress_percent <= lower) return 0;
      if (job.progress_percent >= upper) return 100;
      return clampPercent(((job.progress_percent - lower) / span) * 100);
    }
  }
  if (stageIndex < currentIndex) return 100;
  return 0;
}

function hasStageStatus(job: Job, stageName: string, status: StageTheaterStatus): boolean {
  return normalizeStageProgress(job.stage_progress ?? []).get(stageName)?.status === status;
}

function findStagePercent(job: Job, stageName: string): number | undefined {
  const fromProgress = normalizeStageProgress(job.stage_progress ?? []).get(stageName)?.percent;
  if (typeof fromProgress === 'number') return clampPercent(fromProgress);
  if (normalizeStageName(job.stage) === stageName && typeof job.stage_percent === 'number') return clampPercent(job.stage_percent);
  return undefined;
}

export function buildStageTheaterNodesFromJob(job: Job): StageTheaterNode[] {
   
  const stageOrder = resolveStageOrder([job]);
  const stageMap = normalizeStageProgress(job.stage_progress ?? []);
  const currentStage = normalizeStageName(job.stage);
  const currentIndex = stageOrder.indexOf(currentStage);
  const failedStage = normalizeStageName(job.failed_stage);

  return stageOrder.map((stageName, index) => {
    const existing = stageMap.get(stageName);
    const estimated = estimateStagePercent(job, stageName, index, currentIndex, stageOrder);
    const baseStatus = resolveSingleStageStatus(job, stageName, index, currentIndex, existing);
    const status: StageTheaterStatus = failedStage === stageName ? 'error' : baseStatus;
    const percent = status === 'completed'
      ? 100
      : clampPercent(existing?.percent ?? (status === 'pending' || status === 'ready' ? 0 : estimated));
    const label =
      (existing?.stage_label || '').trim() ||
      (currentStage === stageName ? (job.stage_label || '').trim() : '') ||
      (Object.prototype.hasOwnProperty.call(STAGE_LABELS, stageName) ? Reflect.get(STAGE_LABELS, stageName) : '') ||
      stageName.replace(/_/g, ' ');

    return {
      id: stageName,
      label,
      status,
      percent,
      activeCount: status === 'running' ? 1 : 0,
      completedCount: status === 'completed' ? 1 : 0,
      errorCount: status === 'error' ? 1 : 0,
    };
  });
}

   
export function buildStageTheaterNodesFromJobs(jobs: Job[]): StageTheaterNode[] {
  const stageOrder = resolveStageOrder(jobs);
  return stageOrder.map((stageName) => {
    const activeCount = jobs.filter((job) => normalizeStageName(job.stage) === stageName && job.status === 'running').length;
    const completedCount = jobs.filter((job) => hasStageStatus(job, stageName, 'completed')).length;
    const errorCount = jobs.filter((job) => hasStageStatus(job, stageName, 'error') || normalizeStageName(job.failed_stage) === stageName).length;
    const stagePercents = jobs
      .map((job) => findStagePercent(job, stageName))
      .filter((value): value is number => typeof value === 'number');

    const avgPercent = stagePercents.length > 0
      ? stagePercents.reduce((sum, value) => sum + value, 0) / stagePercents.length
      : completedCount > 0 ? 100 : 0;

    const status: StageTheaterStatus = errorCount > 0
      ? 'error'
      : activeCount > 0
        ? 'running'
        : completedCount > 0
          ? 'completed'
          : 'pending';

    const label = findStageLabelFromJobs(jobs, stageName);

    return {
      id: stageName,
      label,
      status,
      percent: clampPercent(avgPercent),
      activeCount,
      completedCount,
      errorCount,
    };
  });
}

export function normalizeStageEdges(edges: Array<[string, string] | string[]> | undefined): Array<[string, string]> {
  const source = edges && edges.length > 0 ? edges : DEFAULT_STAGE_EDGES;
  const seen = new Set<string>();
  const out: Array<[string, string]> = [];
  for (const edge of source) {
    if (!edge || edge.length < 2) continue;
    const from = normalizeStageName(edge[0]);
    const to = normalizeStageName(edge[1]);
    if (!from || !to || from === to) continue;
    const key = `${from}->${to}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push([from, to]);
  }
  return out;
}

export function layoutStageDag(
  nodeIds: string[],
  edges: Array<[string, string] | string[]> | undefined,
): { levels: string[][]; edges: Array<[string, string]> } {
  const ids = nodeIds.map((id) => normalizeStageName(id)).filter(Boolean);
  const present = new Set(ids);
  const filtered = normalizeStageEdges(edges).filter(([from, to]) => present.has(from) && present.has(to));
  const preds = new Map<string, string[]>();
  for (const id of ids) preds.set(id, []);
  for (const [from, to] of filtered) {
    preds.get(to)?.push(from);
  }
  const levelOf = new Map<string, number>();
  const visit = (id: string, stack: Set<string>): number => {
    const cached = levelOf.get(id);
    if (cached != null) return cached;
    if (stack.has(id)) return 0;
    stack.add(id);
    const parents = preds.get(id) ?? [];
    const level = parents.length === 0 ? 0 : 1 + Math.max(...parents.map((parent) => visit(parent, stack)));
    stack.delete(id);
    levelOf.set(id, level);
    return level;
  };
  for (const id of ids) visit(id, new Set());
  const buckets = new Map<number, string[]>();
  for (const id of ids) {
    const level = levelOf.get(id) ?? 0;
    const bucket = buckets.get(level) ?? [];
    bucket.push(id);
    buckets.set(level, bucket);
  }
  const levels = [...buckets.keys()].sort((a, b) => a - b).map((key) => buckets.get(key) ?? []);
  return { levels, edges: filtered };
}

export function stageGraphForJob(job: Job | null | undefined): StageGraph {
  const backend = job?.stage_graph;
  const nodes = (backend?.nodes?.length ? backend.nodes : resolveStageOrder(job ? [job] : [])).map(normalizeStageName).filter(Boolean);
  const edges = normalizeStageEdges(backend?.edges);
  const layout = layoutStageDag(nodes, edges);
  return {
    nodes,
    edges: layout.edges,
    levels: backend?.levels?.length ? backend.levels : layout.levels,
    labels: backend?.labels,
  };
}
