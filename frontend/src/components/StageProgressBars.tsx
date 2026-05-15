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
  priority: 'RANK',
  passive_scan: 'PASS',
  active_scan: 'ACT',
  nuclei: 'NUC',
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
  return STAGE_ICONS[stage] || 'STEP';
}

function formatCount(processed: number, total: number | null): string {
  if (total && total > 0) {
    return `${processed}/${total}`;
  }
  if (processed > 0) {
    return `${processed}`;
  }
  return '';
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
    <div className="stage-progress-container">
      <div className="stage-progress-header">
        <span className="stage-progress-title">Stage Progress</span>
        <span className="stage-progress-count">
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
      <div ref={gridRef} className="stage-progress-grid">
        {safeStages.map((stage) => {
          const icon = getStageIcon(stage.stage);
          const statusClass = getStatusClass(stage.status);
          const countLabel = formatCount(stage.processed, stage.total);

          const card = (
            <div className={`stage-progress-item ${statusClass}`}>
              <div className="stage-progress-item-header">
                <span className="stage-icon">{icon}</span>
                <span className="stage-name">{stage.stage_label}</span>
                <span className="stage-status-badge">{stage.status}</span>
              </div>
              <div className="stage-progress-bar-track">
                <div
                  className="stage-progress-bar-fill"
                  style={{ width: `${Math.min(100, stage.percent)}%` }}
                />
              </div>
              <div className="stage-progress-item-footer">
                <span className="stage-percent">{stage.percent}%</span>
                {countLabel && <span className="stage-count">{countLabel}</span>}
              </div>
              {(stage.reason || stage.error || stage.last_event || (stage.retry_count || 0) > 0) && (
                <div className="stage-progress-meta">
                  {stage.reason && <div className="stage-reason">{stage.reason}</div>}
                  {stage.error && <div className="stage-error-text">{stage.error}</div>}
                  {stage.last_event && <div className="stage-last-event">{stage.last_event}</div>}
                  {(stage.retry_count || 0) > 0 && (
                    <div className="stage-retry-count">Retries: {stage.retry_count}</div>
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
              key={`${stage.stage}-${stage.status}-${stage.updated_at ?? stage.started_at}`}
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

