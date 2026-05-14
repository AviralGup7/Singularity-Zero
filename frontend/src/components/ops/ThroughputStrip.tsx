import { motion } from 'framer-motion';
import { useEffect, useMemo, useState } from 'react';
import { useVisual } from '@/context/VisualContext';
import type { CSSProperties } from 'react';

interface ThroughputStripProps {
  jobsPerSecond?: number;
  findingsPerSecond?: number;
  scanVelocity?: number;
  activeTasks?: number;
  className?: string;
}

export function ThroughputStrip({
  jobsPerSecond = 0,
  findingsPerSecond = 0,
  scanVelocity = 0,
  activeTasks = 0,
  className,
}: ThroughputStripProps) {
  const { state: visualState } = useVisual();
  const safeJobs = sanitizeMetric(jobsPerSecond);
  const safeFindings = sanitizeMetric(findingsPerSecond);
  const safeVelocity = sanitizeMetric(scanVelocity);
  const [history, setHistory] = useState<number[]>(() => Array.from({ length: 32 }, () => 0));

  useEffect(() => {
    let mounted = true;
    Promise.resolve().then(() => {
      if (mounted) {
        setHistory((previous) => [...previous.slice(-31), safeVelocity]);
      }
    });
    return () => { mounted = false; };
  }, [safeVelocity]);

  const maxHistory = useMemo(() => {
    const maxValue = Math.max(1, ...history, safeJobs, safeFindings, safeVelocity);
    return maxValue;
  }, [history, safeJobs, safeFindings, safeVelocity]);

  return (
    <div className={`throughput-strip ${className ?? ''}`}>
      <div className="throughput-strip-head">
        <span className="throughput-strip-title">Realtime Throughput</span>
        <span className="throughput-strip-active">
          Active Tasks: {Math.round(activeTasks)} | Confidence {Math.round(visualState.confidence * 100)}%
        </span>
      </div>
      <div className="throughput-strip-grid">
        <Metric label="Jobs/Sec" value={safeJobs} accent="var(--accent, #37f6ff)" />
        <Metric label="Findings/Sec" value={safeFindings} accent="var(--warn, #ffc74f)" />
        <Metric label="Scan Velocity" value={safeVelocity} accent="var(--ok, #1fe28a)" />
      </div>
      <div className="throughput-strip-wave" aria-hidden="true">
        {history.map((value, index) => {
          const normalized = maxHistory > 0 ? value / maxHistory : 0;
          const amplitudeBoost = 0.75 + visualState.flow * 0.45 + visualState.intensity * 0.2;
          return (
            <motion.span
              key={`throughput-${index}`}
              className="throughput-strip-wave-bar"
              style={{ height: `${Math.max(6, normalized * 100 * amplitudeBoost)}%` }}
              animate={{ opacity: [0.3, 0.9 + visualState.urgency * 0.1, 0.35] }}
              transition={{
                duration: Math.max(0.45, 1.15 + (index % 6) * 0.08 - visualState.flow * 0.35),
                repeat: Number.POSITIVE_INFINITY,
                ease: 'easeInOut',
              }}
            />
          );
        })}
      </div>
    </div>
  );
}

function Metric({ label, value, accent }: { label: string; value: number; accent: string }) {
  return (
    <motion.div
      className="throughput-strip-metric"
      initial={{ opacity: 0.8, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: 'easeOut' }}
      style={{ '--metric-accent': accent } as CSSProperties}
    >
      <span className="throughput-strip-metric-label">{label}</span>
      <motion.strong
        className="throughput-strip-metric-value"
        key={`${label}-${value}`}
        initial={{ scale: 0.94, opacity: 0.55 }}
        animate={{ scale: [0.95, 1.08, 1], opacity: [0.55, 1, 1] }}
        transition={{ duration: 0.4, ease: 'easeOut' }}
      >
        {value.toFixed(2)}
      </motion.strong>
    </motion.div>
  );
}

function sanitizeMetric(value: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return value;
}
