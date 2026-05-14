import { linkVertical } from 'd3-shape';
import { motion } from 'framer-motion';
import type { Transition } from 'framer-motion';
import type { CSSProperties } from 'react';
import { useMemo } from 'react';
import { useVisual } from '@/context/VisualContext';
import type { VisualState } from '@/lib/visualState';
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

interface StageTheaterProps {
  nodes: StageTheaterNode[];
  className?: string;
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

const TREE_LEVELS: string[][] = [
  ['startup'],
  ['subdomains'],
  ['live_hosts'],
  ['urls'],
  ['recon_validation'],
  ['parameters'],
  ['ranking'],
  ['passive_scan'],
  ['active_scan', 'semgrep', 'nuclei', 'access_control'],
  ['validation'],
  ['intelligence'],
  ['reporting'],
];

const TREE_EDGES: Array<[string, string]> = [
  ['startup', 'subdomains'],
  ['subdomains', 'live_hosts'],
  ['live_hosts', 'urls'],
  ['urls', 'recon_validation'],
  ['recon_validation', 'parameters'],
  ['parameters', 'ranking'],
  ['ranking', 'passive_scan'],
  ['passive_scan', 'active_scan'],
  ['passive_scan', 'semgrep'],
  ['passive_scan', 'nuclei'],
  ['passive_scan', 'access_control'],
  ['active_scan', 'validation'],
  ['passive_scan', 'validation'],
  ['active_scan', 'intelligence'],
  ['nuclei', 'intelligence'],
  ['validation', 'intelligence'],
  ['passive_scan', 'intelligence'],
  ['validation', 'reporting'],
  ['access_control', 'reporting'],
  ['nuclei', 'reporting'],
  ['intelligence', 'reporting'],
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

const STAGE_ACTIVITY_LABELS: Record<string, string> = {
  startup: 'INITIALIZING',
  subdomains: 'ENUMERATING',
  live_hosts: 'PROBING',
  urls: 'COLLECTING',
  recon_validation: 'VERIFYING RECON',
  parameters: 'MUTATING',
  ranking: 'RANKING',
  passive_scan: 'PASSIVE SWEEP',
  active_scan: 'ACTIVE PROBE',
  semgrep: 'STATIC ANALYSIS',
  nuclei: 'SIGNATURE SCAN',
  access_control: 'ACCESS CHECK',
  validation: 'VALIDATING',
  intelligence: 'CORRELATING',
  reporting: 'COMPILING',
};

const STAGE_ALIASES: Record<string, string> = {
  priority: 'ranking',
};

const AMBIENT_LOG_LINES = [
  '[INFO] scanning host batch...',
  '[PASSIVE] collecting endpoints...',
  '[FLOW] stage graph synchronized',
  '[QUEUE] retry monitor online',
  '[TRACE] telemetry stream active',
  '[STATE] processing node transitions',
];

const NODE_COLORS: Record<StageTheaterStatus, string> = {
  pending: 'var(--muted, #8ea4bf)',
  running: 'var(--accent, #37f6ff)',
  completed: 'var(--ok, #1fe28a)',
  error: 'var(--bad, #ff5568)',
  skipped: 'var(--warn, #ffc74f)',
};

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
      STAGE_LABELS[stageName] ||
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

export function StageTheater({ nodes, className }: StageTheaterProps) {
  const { state: visualState } = useVisual();
  const dimensions = useMemo(() => {
    const maxBreadth = Math.max(...TREE_LEVELS.map((level) => level.length), 1);
    const levelCount = Math.max(TREE_LEVELS.length, 1);
    const paddingX = 150;
    const paddingY = 118;
    const width = Math.max(1720, 1180 + maxBreadth * 260);
    const height = Math.max(760, paddingY * 2 + Math.max(levelCount - 1, 1) * 96);
    return { width, height, paddingX, paddingY };
  }, []);

  const stageTheaterStyle = useMemo(() => ({
    '--stage-theater-height': `${dimensions.height}px`,
    '--stage-theater-min-width': `${dimensions.width}px`,
  } as CSSProperties), [dimensions.height, dimensions.width]);

  const positionedNodes = useMemo(() => {
    const ordered = [...nodes];
    const nodeById = new Map(ordered.map((node) => [node.id, node]));
    const levelCount = Math.max(TREE_LEVELS.length, 1);
    const laneHeight = levelCount > 1
      ? (dimensions.height - dimensions.paddingY * 2) / (levelCount - 1)
      : 0;

    const layoutNodes: Array<StageTheaterNode & { x: number; y: number; level: number; order: number }> = [];

    TREE_LEVELS.forEach((level, levelIndex) => {
      const levelWidth = dimensions.width - dimensions.paddingX * 2;
      const gap = level.length > 0 ? levelWidth / (level.length + 1) : levelWidth;
      level.forEach((stageId, orderIndex) => {
        const node = nodeById.get(stageId);
        if (!node) return;
        layoutNodes.push({
          ...node,
          x: Math.round(dimensions.paddingX + gap * (orderIndex + 1)),
          y: Math.round(dimensions.paddingY + laneHeight * levelIndex),
          level: levelIndex,
          order: orderIndex,
        });
      });
    });

    const laidOutIds = new Set(layoutNodes.map((node) => node.id));
    const orphans = ordered.filter((node) => !laidOutIds.has(node.id));
    if (orphans.length > 0) {
      const orphanGap = (dimensions.width - dimensions.paddingX * 2) / (orphans.length + 1);
      orphans.forEach((node, orphanIndex) => {
        layoutNodes.push({
          ...node,
          x: Math.round(dimensions.paddingX + orphanGap * (orphanIndex + 1)),
          y: dimensions.height - dimensions.paddingY,
          level: levelCount,
          order: orphanIndex,
        });
      });
    }

    return layoutNodes.sort((a, b) => a.level - b.level || a.order - b.order);
  }, [nodes]);

  const links = useMemo(() => {
    const connector = linkVertical<{ source: [number, number]; target: [number, number] }, [number, number]>()
      .x((point) => point[0])
      .y((point) => point[1]);
    const nodeById = new Map(positionedNodes.map((node) => [node.id, node]));

    return TREE_EDGES
      .map(([sourceId, targetId]) => {
        const source = nodeById.get(sourceId);
        const target = nodeById.get(targetId);
        if (!source || !target) return null;
        const d = connector({ source: [source.x, source.y], target: [target.x, target.y] }) ?? '';
        return {
          id: `${sourceId}-${targetId}`,
          d,
          isFlowing: source.status === 'running' || target.status === 'running',
          hasFailure: source.status === 'error' || target.status === 'error',
        };
      })
      .filter((edge): edge is { id: string; d: string; isFlowing: boolean; hasFailure: boolean } => edge !== null);
  }, [positionedNodes]);

  const focusNodeId = useMemo(() => {
    const running = positionedNodes.filter((node) => node.status === 'running');
    if (running.length > 0) {
      return [...running].sort((a, b) => b.percent - a.percent)[0].id;
    }
    const errored = positionedNodes.find((node) => node.status === 'error');
    return errored?.id ?? null;
  }, [positionedNodes]);

  return (
    <div className={`stage-theater ${className ?? ''}`} style={stageTheaterStyle}>
      <div className="stage-theater-ambient" aria-hidden="true">
        <div className="stage-theater-grid-overlay" />
        <div className="stage-theater-scanlines-overlay" />
        <div className="stage-theater-ghost-logs">
          {AMBIENT_LOG_LINES.map((line, index) => (
            <span
              key={`${line}-${index}`}
              className="stage-theater-ghost-line"
              style={{ animationDelay: `${index * 0.32}s` }}
            >
              {line}
            </span>
          ))}
        </div>
      </div>
      <svg
        className="stage-theater-svg"
        viewBox={`0 0 ${dimensions.width} ${dimensions.height}`}
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label="Live pipeline stage theater"
      >
        <defs>
          <linearGradient id="stageTheaterFlow" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="var(--accent, #37f6ff)" stopOpacity="0.35" />
            <stop offset="55%" stopColor="var(--accent, #37f6ff)" stopOpacity="0.95" />
            <stop offset="100%" stopColor="var(--accent-2, #57a7ff)" stopOpacity="0.35" />
          </linearGradient>
          <linearGradient id="stageTheaterFailure" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="var(--bad, #ff5568)" stopOpacity="0.25" />
            <stop offset="50%" stopColor="var(--bad, #ff5568)" stopOpacity="0.95" />
            <stop offset="100%" stopColor="var(--bad, #ff5568)" stopOpacity="0.25" />
          </linearGradient>
        </defs>

        {links.map((link) => (
          <g key={link.id}>
            <path
              d={link.d}
              className="stage-theater-edge"
              stroke={link.hasFailure ? 'url(#stageTheaterFailure)' : 'url(#stageTheaterFlow)'}
            />
            {link.isFlowing && (
              <>
                <motion.path
                  d={link.d}
                  className="stage-theater-edge stage-theater-edge--active"
                  stroke={link.hasFailure ? 'var(--bad, #ff5568)' : 'var(--accent, #37f6ff)'}
                  initial={{ pathLength: 0, opacity: 0.4 }}
                  animate={{ pathLength: 1, opacity: [0.5, 1, 0.5], strokeDashoffset: [0, -36] }}
                  transition={{
                    duration: Math.max(0.55, 1.35 - visualState.flow * 0.65),
                    repeat: Number.POSITIVE_INFINITY,
                    ease: 'linear',
                  }}
                />
                <g className="stage-theater-edge-particles">
                  <circle
                    r={2.8}
                    className="stage-theater-edge-particle"
                    fill={link.hasFailure ? 'var(--bad, #ff5568)' : 'var(--accent, #37f6ff)'}
                  >
                    <animateMotion
                      path={link.d}
                      dur={`${Math.max(0.85, 1.8 - visualState.flow * 0.9)}s`}
                      repeatCount="indefinite"
                    />
                  </circle>
                  <circle
                    r={2.1}
                    className="stage-theater-edge-particle stage-theater-edge-particle--secondary"
                    fill={link.hasFailure ? 'rgba(255, 85, 104, 0.75)' : 'rgba(87, 167, 255, 0.75)'}
                  >
                    <animateMotion
                      path={link.d}
                      dur={`${Math.max(1.05, 2.2 - visualState.flow)}s`}
                      begin="0.36s"
                      repeatCount="indefinite"
                    />
                  </circle>
                </g>
              </>
            )}
          </g>
        ))}

        {positionedNodes.map((node) => {
          const color = NODE_COLORS[node.status];
          const isRunning = node.status === 'running';
          const isFocused = focusNodeId === node.id;
          const nodeRadius = isFocused ? (isRunning ? 30 : 26) : (isRunning ? 26 : 22);
          const visualMode = resolveNodeVisualMode(node, visualState);
          const nodeTransition = resolveNodeTransition(visualMode, visualState);
          const nodeVisualAnimation = resolveNodeVisualAnimation(visualMode, visualState);
          return (
            <motion.g
              key={node.id}
              className={`stage-theater-node stage-theater-node--${node.status} ${isFocused ? 'stage-theater-node--focus' : ''}`}
              initial={false}
              animate={nodeVisualAnimation}
              transition={nodeTransition}
              style={{
                transformBox: 'fill-box',
                transformOrigin: `${node.x}px ${node.y}px`,
              }}
            >
              <motion.circle
                cx={node.x}
                cy={node.y}
                r={nodeRadius}
                fill={isRunning ? 'rgba(55, 246, 255, 0.12)' : 'rgba(10, 17, 28, 0.7)'}
                stroke={color}
                strokeWidth={isFocused ? 3.4 : isRunning ? 2.8 : 1.8}
                animate={
                  isRunning
                    ? { scale: [1, 1.12, 1], opacity: [0.6, 1, 0.6] }
                    : node.status === 'error'
                      ? { opacity: [0.85, 1, 0.85] }
                      : undefined
                }
                transition={
                  isRunning
                    ? {
                      duration: Math.max(0.5, 1.25 - visualState.intensity * 0.55),
                      repeat: Number.POSITIVE_INFINITY,
                      ease: 'easeInOut',
                    }
                    : node.status === 'error'
                      ? {
                        duration: Math.max(0.3, 0.7 - visualState.urgency * 0.25),
                        repeat: Number.POSITIVE_INFINITY,
                        ease: 'easeInOut',
                      }
                      : undefined
                }
              />

              {(isRunning || isFocused) && (
                <g
                  className="stage-theater-rotor"
                  transform={`translate(${node.x} ${node.y})`}
                >
                  <circle
                    cx={0}
                    cy={0}
                    r={nodeRadius + 12}
                    className="stage-theater-rotor-ring"
                  />
                </g>
              )}

              {isRunning && (
                <motion.circle
                  cx={node.x}
                  cy={node.y}
                  r={nodeRadius + 6}
                  fill="transparent"
                  stroke={color}
                  strokeWidth={1.2}
                  animate={{ scale: [0.9, 1.25], opacity: [0.8, 0] }}
                  transition={{
                    duration: Math.max(0.5, 1.2 - visualState.flow * 0.5),
                    repeat: Number.POSITIVE_INFINITY,
                    ease: 'easeOut',
                  }}
                />
              )}

              {isFocused && (
                <motion.circle
                  cx={node.x}
                  cy={node.y}
                  r={nodeRadius + 20}
                  fill="transparent"
                  stroke={color}
                  strokeWidth={1.3}
                  animate={{ scale: [0.9, 1.34], opacity: [0.52, 0] }}
                  transition={{
                    duration: Math.max(0.62, 1.15 - visualState.intensity * 0.35),
                    repeat: Number.POSITIVE_INFINITY,
                    ease: 'easeOut',
                  }}
                />
              )}

              <circle
                cx={node.x}
                cy={node.y}
                r={8}
                fill={color}
                className="stage-theater-node-core"
              />
              <text x={node.x} y={node.y + 52} textAnchor="middle" className="stage-theater-node-label">
                {node.label}
              </text>
              <text x={node.x} y={node.y + 70} textAnchor="middle" className="stage-theater-node-meta">
                {formatStageStatus(node)}
              </text>
              {(node.activeCount || node.completedCount || node.errorCount) && (
                <text x={node.x} y={node.y - 38} textAnchor="middle" className="stage-theater-node-stats">
                  A {node.activeCount ?? 0} | C {node.completedCount ?? 0} | E {node.errorCount ?? 0}
                </text>
              )}
            </motion.g>
          );
        })}
      </svg>
    </div>
  );
}

function resolveNodeVisualMode(
  node: StageTheaterNode,
  visualState: VisualState
): 'idle' | 'active' | 'unstable' | 'critical' {
  if (node.status === 'error' || visualState.urgency > 0.95) {
    return 'critical';
  }
  if (node.status === 'running' && visualState.instability > 0.5) {
    return 'unstable';
  }
  if (node.status === 'running' || node.status === 'completed') {
    return 'active';
  }
  return 'idle';
}

function resolveNodeVisualAnimation(
  mode: 'idle' | 'active' | 'unstable' | 'critical',
  visualState: VisualState
): { scale: number; opacity: number; filter: string } {
  if (mode === 'critical') {
    return {
      scale: 1.08 + visualState.urgency * 0.16,
      opacity: 1,
      filter: 'drop-shadow(0 0 10px rgba(255, 59, 59, 0.6))',
    };
  }
  if (mode === 'unstable') {
    return {
      scale: 1 + visualState.intensity * 0.12,
      opacity: 0.88,
      filter: `blur(${(visualState.instability * 1.2).toFixed(2)}px)`,
    };
  }
  if (mode === 'active') {
    return {
      scale: 1 + visualState.intensity * 0.18,
      opacity: 0.82 + visualState.flow * 0.18,
      filter: 'blur(0px)',
    };
  }
  return {
    scale: 1,
    opacity: 0.72,
    filter: 'blur(0px)',
  };
}

function resolveNodeTransition(
  mode: 'idle' | 'active' | 'unstable' | 'critical',
  visualState: VisualState
): Transition {
  if (mode === 'critical') {
    return {
      duration: Math.max(0.18, 0.34 - visualState.urgency * 0.12),
      repeat: Number.POSITIVE_INFINITY,
      ease: 'easeInOut' as const,
    };
  }
  if (mode === 'unstable') {
    return {
      duration: Math.max(0.22, 0.42 - visualState.instability * 0.15),
      repeat: Number.POSITIVE_INFINITY,
      ease: 'easeInOut' as const,
    };
  }
  if (mode === 'active') {
    return {
      duration: Math.max(0.28, 0.5 - visualState.flow * 0.2),
      ease: 'easeOut' as const,
    };
  }
  return { duration: 0.35, ease: 'easeOut' as const };
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

function normalizeStageName(stageName: string | undefined): string {
  const normalized = String(stageName || '').trim().toLowerCase();
  if (!normalized) return '';
  return STAGE_ALIASES[normalized] ?? normalized;
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
  return STAGE_LABELS[stageName] ?? stageName.replace(/_/g, ' ');
}

function clampPercent(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function formatStageStatus(node: StageTheaterNode): string {
  const activity = STAGE_ACTIVITY_LABELS[node.id] ?? 'PROCESSING';
  if (node.status === 'running') {
    const pct = clampPercent(node.percent);
    if (pct <= 0) return `${activity}...`;
    return `${pct}% · ${activity}`;
  }
  if (node.status === 'completed') return '100% · COMPLETE';
  if (node.status === 'error') return 'FAULT DETECTED';
  if (node.status === 'skipped') return 'SKIPPED';
  return 'WAITING INPUT';
}
