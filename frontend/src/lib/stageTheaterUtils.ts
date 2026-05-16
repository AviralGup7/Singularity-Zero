import type { Job, StageProgressEntry } from '@/types/api';

export type StageTheaterStatus = 'pending' | 'running' | 'completed' | 'error' | 'skipped';

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
  parameters: 'Parameters',
  ranking: 'Ranking',
  passive_scan: 'Passive',
  active_scan: 'Active Scan',
  semgrep: 'Semgrep',
  nuclei: 'Nuclei',
  access_control: 'Access',
  validation: 'Validation',
  intelligence: 'Intel',
  reporting: 'Report',
};

const STAGE_ALIASES: Record<string, string> = {
  priority: 'ranking',
};

function normalizeStageName(stageName: string | undefined): string {
  const normalized = String(stageName || '').trim().toLowerCase();
  if (!normalized) return '';
  return Object.prototype.hasOwnProperty.call(STAGE_ALIASES, normalized) ? STAGE_ALIASES[normalized] : normalized;
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
    ? STAGE_LABELS[stageName]
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

  if (job.status === 'failed' && normalizeStageName(job.failed_stage) === stageName) return 'error';
  if (job.status === 'completed') return 'completed';
  if (index < currentIndex) return 'completed';
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
    const percent = clampPercent(existing?.percent ?? estimated);
    const label =
      (existing?.stage_label || '').trim() ||
      (currentStage === stageName ? (job.stage_label || '').trim() : '') ||
      (Object.prototype.hasOwnProperty.call(STAGE_LABELS, stageName) ? STAGE_LABELS[stageName] : '') ||
      stageName.replace(/_/g, ' ');

    return {
      id: stageName,
      label,
      status,
      percent: status === 'completed' ? 100 : percent,
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
