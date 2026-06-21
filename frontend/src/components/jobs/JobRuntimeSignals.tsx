import { memo } from 'react';
import { motion } from 'framer-motion';
import { InfoItem, formatDurationLabel } from '@/components/jobs/JobInfoItem';

interface JobRuntimeSignalsProps {
  warningCount: number;
  fatalSignalCount: number;
  degradedProviders: string[];
  timeoutEvents: string[];
  effectiveTimeoutSeconds?: number | null;
  hasRuntimeSignals: boolean;
}

function JobRuntimeSignalsBase({
  warningCount,
  fatalSignalCount,
  degradedProviders,
  timeoutEvents,
  effectiveTimeoutSeconds,
  hasRuntimeSignals,
}: JobRuntimeSignalsProps) {
  if (!hasRuntimeSignals) return null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      className="card"
    >
      <h3>Runtime Signals</h3>
      <div className="info-grid">
        {warningCount > 0 && (
          <InfoItem label="Warnings" value={`${warningCount}`} />
        )}
        {fatalSignalCount > 0 && (
          <InfoItem label="Fatal Signals" value={`${fatalSignalCount}`} />
        )}
        {typeof effectiveTimeoutSeconds === 'number' && (
          <InfoItem
            label="Effective Timeout"
            value={formatDurationLabel(effectiveTimeoutSeconds)}
          />
        )}
        {degradedProviders.length > 0 && (
          <InfoItem label="Degraded Providers" value={`${degradedProviders.length}`} />
        )}
        {timeoutEvents.length > 0 && (
          <InfoItem label="Timeout Events" value={`${timeoutEvents.length}`} />
        )}
      </div>
      {degradedProviders.length > 0 && (
        <>
          <h4 className="mt-4 text-xs font-bold text-[var(--text-secondary)] font-mono uppercase tracking-wider">Degraded Providers</h4>
          <div className="modules-list flex flex-wrap gap-2 mt-2">
            {degradedProviders.map((provider) => (
              <span key={provider} className="module-tag">{provider}</span>
            ))}
          </div>
        </>
      )}
      {timeoutEvents.length > 0 && (
        <>
          <h4 className="mt-4 text-xs font-bold text-[var(--text-secondary)] font-mono uppercase tracking-wider">Timeout Events</h4>
          <ul className="warnings-list mt-2 space-y-1">
            {timeoutEvents.map((event) => (
              <li key={event}>{event}</li>
            ))}
          </ul>
        </>
      )}
    </motion.div>
  );
}

export const JobRuntimeSignals = memo(JobRuntimeSignalsBase);
