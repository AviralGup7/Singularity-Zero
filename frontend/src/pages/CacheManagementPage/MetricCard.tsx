import type { ReactNode } from 'react';
import { Progress } from '@/components/ui/Progress';
import { clampPercent } from './helpers';

interface MetricCardProps {
  icon: ReactNode;
  label: string;
  value: string;
  helper?: string;
  progress?: number;
  tone?: 'accent' | 'success' | 'warning';
}

export function MetricCard({ icon, label, value, helper, progress, tone = 'accent' }: MetricCardProps) {
  const variant = tone === 'success' ? 'completed' : tone === 'warning' ? 'running' : 'default';
  return (
    <section className="card p-4 min-h-[132px]">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs text-muted font-mono uppercase tracking-wider">{label}</p>
          <p className="mt-2 text-2xl font-bold text-text">{value}</p>
        </div>
        <div className="rounded border border-line p-2 text-accent" aria-hidden="true">
          {icon}
        </div>
      </div>
      {progress !== undefined && <Progress className="mt-4" value={clampPercent(progress)} variant={variant} size="sm" />}
      {helper && <p className="mt-3 text-xs text-muted">{helper}</p>}
    </section>
  );
}
