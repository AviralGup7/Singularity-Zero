import { motion } from 'framer-motion';
import { InfoItem } from '@/components/jobs/JobInfoItem';
import { GlassCard } from '@/components/ui/GlassCard';
import { itemVariants } from './helpers';
import type { Job } from '@/types/api';

interface ProgressTelemetrySectionProps {
  telemetry: NonNullable<Job['progress_telemetry']>;
}

export function ProgressTelemetrySection({ telemetry }: ProgressTelemetrySectionProps) {
  return (
    <motion.div variants={itemVariants} className="card">
      <div className="pt-4 space-y-4">
        <div className="info-grid">
          <InfoItem label="Active Tasks" value={String(telemetry.active_task_count ?? 0)} />
          {typeof telemetry.requests_per_second === 'number' && (
            <InfoItem label="Requests/sec" value={telemetry.requests_per_second.toFixed(2)} />
          )}
          {typeof telemetry.throughput_per_second === 'number' && (
            <InfoItem label="Throughput/sec" value={telemetry.throughput_per_second.toFixed(2)} />
          )}
          {typeof telemetry.vulnerability_likelihood_score === 'number' && (
            <InfoItem label="Vuln Likelihood" value={`${Math.round(telemetry.vulnerability_likelihood_score * 100)}%`} />
          )}
          {typeof telemetry.confidence_score === 'number' && (
            <InfoItem label="Confidence" value={`${Math.round(telemetry.confidence_score * 100)}%`} />
          )}
          {typeof telemetry.high_value_target_count === 'number' && (
            <InfoItem label="High-Value Targets" value={String(telemetry.high_value_target_count)} />
          )}
          {typeof telemetry.retry_count === 'number' && (
            <InfoItem label="Retries" value={String(telemetry.retry_count)} />
          )}
          {typeof telemetry.failure_count === 'number' && (
            <InfoItem label="Failures Seen" value={String(telemetry.failure_count)} />
          )}
          {telemetry.targets && (
            <InfoItem
              label="Target State"
              value={`queued ${telemetry.targets.queued ?? 0} · scanning ${telemetry.targets.scanning ?? 0} · done ${telemetry.targets.done ?? 0}`}
            />
          )}
          {telemetry.drop_off && (
            <InfoItem
              label="Drop-Off"
              value={`input ${telemetry.drop_off.input} · kept ${telemetry.drop_off.kept} · dropped ${telemetry.drop_off.dropped}`}
            />
          )}
          {telemetry.deduplication && (
            <InfoItem
              label="Dedup"
              value={`removed ${telemetry.deduplication.removed} · remaining ${telemetry.deduplication.remaining}`}
            />
          )}
          {typeof telemetry.signal_noise_ratio === 'number' && (
            <InfoItem label="Signal/Noise Ratio" value={telemetry.signal_noise_ratio.toFixed(2)} />
          )}
          {telemetry.bottleneck_stage && (
            <InfoItem
              label="Bottleneck"
              value={`${telemetry.bottleneck_stage}${typeof telemetry.bottleneck_seconds === 'number' ? ` (${Math.round(telemetry.bottleneck_seconds)}s)` : ''}`}
            />
          )}
          {telemetry.next_best_action && (
            <InfoItem label="Next Best Action" value={telemetry.next_best_action} />
          )}
        </div>

        {telemetry.learning_feedback && (
          <GlassCard variant="glow" delay={0.1} className="mt-4 p-4 border border-[var(--accent)]/30">
            <h4 className="text-xs font-bold uppercase tracking-widest text-[var(--accent)] mb-2 font-mono">Remediation Analysis</h4>
            <p className="text-xs italic text-[var(--text-secondary)] leading-relaxed font-sans">
              {typeof telemetry.learning_feedback === 'string'
                ? telemetry.learning_feedback
                : JSON.stringify(telemetry.learning_feedback)}
            </p>
          </GlassCard>
        )}

        {telemetry.skipped_stages && telemetry.skipped_stages.length > 0 && (
          <div className="mt-4">
            <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)] font-mono mb-2">Skipped Stages</h4>
            <div className="flex flex-wrap gap-2">
              {telemetry.skipped_stages.map((s) => (
                <span key={s.stage} className="px-2 py-1 bg-white/5 border border-white/10 rounded text-[10px] font-mono" title={s.reason}>
                  {s.stage}
                </span>
              ))}
            </div>
          </div>
        )}

        {telemetry.top_active_targets && telemetry.top_active_targets.length > 0 && (
          <div className="modules-list mt-4 flex flex-wrap gap-2">
            {telemetry.top_active_targets.map((item) => (
              <span key={item} className="module-tag">{item}</span>
            ))}
          </div>
        )}
        {telemetry.event_triggers && telemetry.event_triggers.length > 0 && (
          <ul className="warnings-list mt-4 space-y-1">
            {telemetry.event_triggers.slice(-5).map((trigger) => (
              <li key={trigger}>{trigger}</li>
            ))}
          </ul>
        )}
      </div>
    </motion.div>
  );
}
