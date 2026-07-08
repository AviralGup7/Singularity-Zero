import { formatRatio, clampPercent } from './helpers';

export function HitRateGauge({ value }: { value?: number | null }) {
  const percent = clampPercent((value ?? 0) * 100);
  return (
    <div className="flex items-center gap-4">
      <div
        className="grid h-24 w-24 place-items-center rounded-full border border-[var(--line)]"
        style={{ background: `conic-gradient(var(--ok) ${percent * 3.6}deg, var(--panel) 0deg)` }}
        aria-label={`Hit rate ${Math.round(percent)} percent`}
      >
        <div className="grid h-16 w-16 place-items-center rounded-full bg-[var(--bg)] text-lg font-bold">
          {formatRatio(value)}
        </div>
      </div>
      <div className="min-w-0">
        <p className="font-mono text-xs uppercase tracking-wider text-[var(--muted)]">Hit Rate</p>
        <p className="mt-1 text-sm text-[var(--text)]">Miss rate {formatRatio(value === null || value === undefined ? null : 1 - value)}</p>
      </div>
    </div>
  );
}
