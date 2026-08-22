import { motion } from 'framer-motion';
import { useAutoAnimate } from '@formkit/auto-animate/react';
import type { StageProgressEntry } from '../types/api';
import { useMotionPolicy } from '../hooks/useMotionPolicy';

const STAGE_ICONS: Record<string, string> = {
  startup: 'START',
  subdomains: 'DNS',
  live_hosts: 'LIVE',
  urls: 'URL',
  parameters: 'PARAM',
  ranking: 'RANK',
  passive_scan: 'PASS',
  active_scan: 'ACT',
  semgrep: 'SAST',
  nuclei: 'VULN',
  access_control: 'AUTH',
  validation: 'VAL',
  intelligence: 'INTEL',
  reporting: 'RPT',
  completed: 'DONE',
};

function getStatusClass(status: string): string {
  switch (status) {
    case 'running':
      return 'stage-running';
    case 'completed':
      return 'stage-completed';
    case 'skipped':
      return 'stage-skipped';
    case 'error':
      return 'stage-error';
    default:
      return 'stage-pending';
  }
}

function getStageIcon(stage: string): string {
  const aliased = stage === 'priority' ? 'ranking' : stage;
  return Reflect.get(STAGE_ICONS, aliased) || 'STEP';
}

const CLASSIFICATION_LABELS: Record<string, string> = {
  oom_error: 'Out of memory (OOM)',
  executable_not_found: 'Tool not found (exit 127)',
  permission_denied: 'Permission denied (exit 126)',
  sigint_or_sigterm: 'Interrupted (SIGINT/SIGTERM)',
};

export function getClassificationLabel(classification: string | undefined): string {
  if (!classification) return '';
  return Reflect.get(CLASSIFICATION_LABELS, classification) || classification;
}

export function formatCount(processed: number, total: number | null): string {
  const safeProcessed = Number.isFinite(processed) ? Math.max(0, processed) : 0;
  const safeTotal = typeof total === 'number' && Number.isFinite(total) ? total : null;
  if (safeTotal && safeTotal > 0) {
    return `${safeProcessed}/${safeTotal}`;
  }
  if (safeProcessed > 0) {
    return `${safeProcessed}`;
  }
  return '';
}

export function clampStagePercent(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(n) ? Math.min(100, Math.max(0, n)) : 0;
}

interface StageProgressBarsProps {
  stages: StageProgressEntry[];
}

export function StageProgressBars({ stages }: StageProgressBarsProps) {
  const safeStages = stages ?? [];
  const { policy, strategy } = useMotionPolicy('list');
   
  const [gridRef] = useAutoAnimate({
    duration: Math.max(120, Math.round(strategy.duration * 1000)),
    easing: 'ease-out',
    disrespectUserMotionPreference: policy.tier === 'full',
  });

  if (safeStages.length === 0) {
    return null;
  }

  const activeStages = safeStages.filter((s) => s.status === 'running');
  const completedStages = safeStages.filter((s) => s.status === 'completed');
  const skippedStages = safeStages.filter((s) => s.status === 'skipped');
  const errorStages = safeStages.filter((s) => s.status === 'error');

  if (
    activeStages.length === 0 &&
    completedStages.length === 0 &&
    skippedStages.length === 0 &&
    errorStages.length === 0
  ) {
    return null;
  }

  return (
    <div className="stage-progress-container" role="region" aria-label="Stage progress">
      <div className="stage-progress-header">
        <span className="stage-progress-title">Stage Progress</span>
        <span className="stage-progress-count" role="status" aria-live="polite">
          {activeStages.length} active · {completedStages.length} completed
          {errorStages.length > 0 && ` · ${errorStages.length} error`}
          {skippedStages.length > 0 && ` · ${skippedStages.length} skipped`}
          {activeStages.length > 1 && (
            <span className="parallel-badge" title="Running in parallel">
              {' '}
              {activeStages.length} concurrent
            </span>
          )}
        </span>
      </div>
      <div ref={gridRef} className="stage-progress-grid" role="list" aria-label="Pipeline stages">
        {safeStages.map((stage) => {
          const icon = getStageIcon(stage.stage);
          const statusClass = getStatusClass(stage.status);
          const percent = clampStagePercent(stage.percent);
          const countLabel = formatCount(stage.processed, stage.total);

          const card = (
            <div className={`stage-progress-item ${statusClass}`} role="listitem" aria-label={`${stage.stage_label}: ${stage.status}, ${percent}%`}>
              <div className="stage-progress-item-header">
                <span className="stage-icon" aria-hidden="true">{icon}</span>
                <span className="stage-name">{stage.stage_label}</span>
                <span className="stage-status-badge" role="status">{stage.status}</span>
              </div>
              <div
                className="stage-progress-bar-track"
                role="progressbar"
                aria-valuenow={percent}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-label={`${stage.stage_label} progress: ${percent}%`}
              >
                <div
                  className="stage-progress-bar-fill"
                  style={{ width: `${percent}%` }}
                />
              </div>
              <div className="stage-progress-item-footer">
                <span className="stage-percent tabular-nums">{percent}%</span>
                {countLabel && <span className="stage-count tabular-nums">{countLabel}</span>}
              </div>
              {(stage.reason || stage.error || stage.last_event || stage.classification || (stage.retry_count || 0) > 0) && (
                <div className="stage-progress-meta">
                  {stage.reason && <div className="stage-reason">{stage.reason}</div>}
                  {stage.error && <div className="stage-error-text">{stage.error}</div>}
                  {stage.classification && (
                    <div className="stage-classification text-warn">
                      {getClassificationLabel(stage.classification)}
                    </div>
                  )}
                  {stage.last_event && <div className="stage-last-event">{stage.last_event}</div>}
                  {(stage.retry_count || 0) > 0 && (
                    <div className="stage-retry-count">
                      Retries: {stage.retry_count}
                      {stage.retry_max_attempts ? ` / ${stage.retry_max_attempts} max` : ''}
                    </div>
                  )}
                </div>
              )}
            </div>
          );

          if (!policy.allowFramer) {
            return card;
          }

          return (
            <motion.div
              key={`${stage.stage}-${stage.status}-${stage.processed}-${stage.total}-${stage.updated_at ?? stage.started_at}`}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: strategy.duration, ease: 'easeOut' }}
            >
              {card}
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}

