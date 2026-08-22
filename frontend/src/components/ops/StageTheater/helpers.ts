import type { VisualState } from '@/lib/visualState';
import type { StageTheaterNode } from '@/lib/stageTheaterUtils';
import { STAGE_ACTIVITY_LABELS } from './constants';

export function resolveNodeVisualMode(
  node: StageTheaterNode,
  visualState: VisualState,
): 'idle' | 'active' | 'unstable' | 'critical' {
  if (node.status === 'error' || visualState.urgency > 0.95) return 'critical';
  if (node.status === 'running' && visualState.instability > 0.5) return 'unstable';
  if (node.status === 'running' || node.status === 'completed') return 'active';
  return 'idle';
}

export function resolveNodeVisualAnimation(
  mode: 'idle' | 'active' | 'unstable' | 'critical',
  visualState: VisualState,
): { scale: number; opacity: number; filter: string } {
  switch (mode) {
    case 'critical':
      return { scale: 1.08 + visualState.urgency * 0.16, opacity: 1, filter: 'drop-shadow(0 0 10px rgba(255, 59, 59, 0.6))' };
    case 'unstable':
      return { scale: 1 + visualState.intensity * 0.12, opacity: 0.88, filter: `blur(${(visualState.instability * 1.2).toFixed(2)}px)` };
    case 'active':
      return { scale: 1 + visualState.intensity * 0.18, opacity: 0.82 + visualState.flow * 0.18, filter: 'blur(0px)' };
    default:
      return { scale: 1, opacity: 0.72, filter: 'blur(0px)' };
  }
}

export function resolveNodeTransition(
  mode: 'idle' | 'active' | 'unstable' | 'critical',
  visualState: VisualState,
): { duration: number; repeat?: number; ease: string } {
  switch (mode) {
    case 'critical':
      return { duration: Math.max(0.18, 0.34 - visualState.urgency * 0.12), repeat: Number.POSITIVE_INFINITY, ease: 'easeInOut' };
    case 'unstable':
      return { duration: Math.max(0.22, 0.42 - visualState.instability * 0.15), repeat: Number.POSITIVE_INFINITY, ease: 'easeInOut' };
    case 'active':
      return { duration: Math.max(0.28, 0.5 - visualState.flow * 0.2), ease: 'easeOut' };
    default:
      return { duration: 0.35, ease: 'easeOut' };
  }
}

export function formatStageStatus(node: StageTheaterNode): string {
  const activity = Object.prototype.hasOwnProperty.call(STAGE_ACTIVITY_LABELS, node.id)
    ? STAGE_ACTIVITY_LABELS[node.id]
    : 'PROCESSING';
  if (node.status === 'running') {
    const pct = Math.max(0, Math.min(100, Math.round(node.percent)));
    if (pct <= 0) return `${activity}...`;
    return `${pct}% · ${activity}`;
  }
  if (node.status === 'completed') return '100% · COMPLETE';
  if (node.status === 'error') return 'FAULT DETECTED';
  if (node.status === 'skipped') return 'SKIPPED';
  if (node.status === 'ready') return 'READY';
  return 'WAITING INPUT';
}
