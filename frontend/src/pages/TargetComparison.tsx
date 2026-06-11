import { useState, useMemo, useEffect } from 'react';
import { motion } from 'framer-motion';
import { ArrowLeftRight, TrendingUp, TrendingDown, Minus } from 'lucide-react';
import type { Target } from '../types/api';
import { useTargets } from '../hooks';
import { compareTargets } from '@/api/client';
import { GlassCard } from '@/components/ui/GlassCard';
import { AnimatedCounter } from '@/components/ui/AnimatedCounter';
import { PageHeader } from '@/components/ui/PageHeader';

interface TargetComparisonProps {
  targets?: Target[];
}

/* ── Shared column renderer to eliminate duplication ────────── */
interface ComparisonColumnProps {
  target: Target;
  otherTarget: Target;
  severityTotal: number | null;
  otherSeverityTotal: number | null;
  highestSev: string | null;
  delay: number;
}

const STAT_LABELS = [
  'Risk Index (CSI)', 'Findings', 'Highest Severity', 'URLs',
  'Parameters', 'Attack Chains', 'Scan Runs', 'Last Scan',
] as const;

function DeltaIndicator({ a, b, invert }: { a: number; b: number; invert?: boolean }) {
  const better = invert ? a > b : a < b;
  const worse = invert ? a < b : a > b;
  if (better) return <TrendingDown size={14} className="text-ok ml-1 inline" />;
  if (worse) return <TrendingUp size={14} className="text-bad ml-1 inline" />;
  return <Minus size={12} className="text-muted ml-1 inline" />;
}

function ComparisonColumn({ target, otherTarget, severityTotal, otherSeverityTotal, highestSev, delay }: ComparisonColumnProps) {
  const riskA = target.risk_score;
  const riskB = otherTarget.risk_score;

  return (
    <GlassCard delay={delay} hoverable>
      <h3 className="text-lg font-semibold text-[var(--text-primary)] mb-4 pb-3 border-b border-[var(--border)]">
        {target.name}
      </h3>
      <div className="space-y-3">
        {/* Risk Index */}
        <div className="flex items-center justify-between py-2">
          <span className="text-xs uppercase tracking-wider text-muted">{STAT_LABELS[0]}</span>
          <span className="font-semibold text-[var(--text-primary)] flex items-center">
            {riskA != null ? <AnimatedCounter value={riskA} decimals={1} /> : '—'}
            {riskA != null && riskB != null && <DeltaIndicator a={riskA} b={riskB} />}
          </span>
        </div>
        {/* Findings */}
        <div className="flex items-center justify-between py-2">
          <span className="text-xs uppercase tracking-wider text-muted">{STAT_LABELS[1]}</span>
          <span className="font-semibold text-[var(--text-primary)] flex items-center">
            <AnimatedCounter value={target.finding_count} />
            {severityTotal != null && otherSeverityTotal != null && (
              <DeltaIndicator a={severityTotal} b={otherSeverityTotal} />
            )}
          </span>
        </div>
        {/* Highest Severity */}
        <div className="flex items-center justify-between py-2">
          <span className="text-xs uppercase tracking-wider text-muted">{STAT_LABELS[2]}</span>
          <span className={`font-mono text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded severity-badge sev-${highestSev}`}>
            {highestSev ?? '—'}
          </span>
        </div>
        {/* URLs */}
        <div className="flex items-center justify-between py-2">
          <span className="text-xs uppercase tracking-wider text-muted">{STAT_LABELS[3]}</span>
          <span className="font-semibold text-[var(--text-primary)]">
            <AnimatedCounter value={target.url_count} />
          </span>
        </div>
        {/* Parameters */}
        <div className="flex items-center justify-between py-2">
          <span className="text-xs uppercase tracking-wider text-muted">{STAT_LABELS[4]}</span>
          <span className="font-semibold text-[var(--text-primary)]">
            <AnimatedCounter value={target.parameter_count} />
          </span>
        </div>
        {/* Attack Chains */}
        <div className="flex items-center justify-between py-2">
          <span className="text-xs uppercase tracking-wider text-muted">{STAT_LABELS[5]}</span>
          <span className="font-semibold text-[var(--text-primary)]">
            <AnimatedCounter value={target.attack_chain_count} />
          </span>
        </div>
        {/* Scan Runs */}
        <div className="flex items-center justify-between py-2">
          <span className="text-xs uppercase tracking-wider text-muted">{STAT_LABELS[6]}</span>
          <span className="font-semibold text-[var(--text-primary)]">
            <AnimatedCounter value={target.run_count} />
          </span>
        </div>
        {/* Last Scan */}
        <div className="flex items-center justify-between py-2">
          <span className="text-xs uppercase tracking-wider text-muted">{STAT_LABELS[7]}</span>
          <span className="text-sm text-[var(--text-secondary)]">{target.latest_run || '—'}</span>
        </div>
      </div>

      {/* Severity Breakdown */}
      <div className="mt-4 pt-4 border-t border-[var(--border)]">
        <h4 className="text-xs uppercase tracking-wider text-muted mb-3">Severity Breakdown</h4>
        <div className="space-y-2">
          {Object.entries(target.severity_counts ?? {}).map(([sev, count]) => (
            <div key={sev} className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full severity-dot severity-${sev}`} />
                <span className="text-xs capitalize text-[var(--text-secondary)]">{sev}</span>
              </div>
              <span className="text-sm font-medium text-[var(--text-primary)]">{count}</span>
            </div>
          ))}
        </div>
      </div>
    </GlassCard>
  );
}

const selectClass = 'w-full bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-2.5 text-sm text-[var(--text-primary)] focus:border-[var(--accent)] focus:shadow-[0_0_0_2px_var(--accent-soft)] focus:outline-none transition-all duration-200 appearance-none cursor-pointer';

export function TargetComparison({ targets: propTargets }: TargetComparisonProps) {
   
  const [targetA, setTargetA] = useState('');
  const [targetB, setTargetB] = useState('');
  const [comparisonData, setComparisonData] = useState<{ target_a: Target; target_b: Target } | null>(null);
  const [compareLoading, setCompareLoading] = useState(false);
  const [compareError, setCompareError] = useState<string | null>(null);

  // Fetch targets if not provided via props
  const { data: fetchedTargets } = useTargets({ enabled: !propTargets });
  const safeTargets = useMemo(() => {
    return Array.isArray(propTargets) ? propTargets : (fetchedTargets?.targets ?? []);
  }, [propTargets, fetchedTargets?.targets]);

  useEffect(() => {
    if (!targetA || !targetB) {
      return;
    }

    const controller = new AbortController();

    compareTargets(targetA, targetB, controller.signal)
      .then((data) => {
        setComparisonData(data);
      })
      .catch((err: { message?: string; name?: string }) => {
        if (err.name !== 'AbortError') {
          setCompareError(err.message || 'Failed to fetch comparison data');
        }
      })
      .finally(() => {
        setCompareLoading(false);
      });

    return () => {
      controller.abort();
    };
  }, [targetA, targetB]);

  const selectedA = comparisonData?.target_a;
  const selectedB = comparisonData?.target_b;

  const severityTotals = useMemo(() => {
    const calc = (t: Target) => {
      return Object.values(t.severity_counts ?? {}).reduce((sum, v) => sum + (v || 0), 0);
    };
    return { a: selectedA ? calc(selectedA) : null, b: selectedB ? calc(selectedB) : null };
   
  }, [selectedA, selectedB]);

  const highestSeverity = useMemo(() => {
   
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const calc = (t: Target): string => {
      const counts = t.severity_counts ?? {};
      for (const sev of order) {
        if ((counts[sev as keyof typeof counts] || 0) > 0) return sev;
      }
      return 'info';
    };
    return { a: selectedA ? calc(selectedA) : null, b: selectedB ? calc(selectedB) : null };
   
  }, [selectedA, selectedB]);

  if (safeTargets.length < 2) {
    return (
      <GlassCard className="text-center py-16">
        <ArrowLeftRight size={48} className="mx-auto mb-4 text-[var(--text-tertiary)]" />
        <p className="text-[var(--text-secondary)]">At least 2 targets are needed for comparison.</p>
      </GlassCard>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<ArrowLeftRight size={20} />}
        title="Target Comparison"
        subtitle="Compare security posture between scan targets"
      />

      {/* ── Selectors ──────────────────────────────────────────── */}
      <motion.div
        className="grid grid-cols-1 md:grid-cols-2 gap-4"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
      >
        <GlassCard hoverable={false}>
          <label htmlFor="target-comparison-a" className="block text-xs font-semibold uppercase tracking-wider text-accent mb-2">Target A</label>
          <select
            id="target-comparison-a"
            className={selectClass}
            value={targetA}
            onChange={e => {
              const val = e.target.value;
              setTargetA(val);
              if (val && targetB) {
                setCompareLoading(true);
                setCompareError(null);
              } else {
                setComparisonData(null);
                setCompareError(null);
                setCompareLoading(false);
              }
            }}
          >
            <option value="">Select target...</option>
            {safeTargets.map(t => (
              <option key={t.name} value={t.name} disabled={t.name === targetB}>{t.name}</option>
            ))}
          </select>
        </GlassCard>

        <GlassCard hoverable={false}>
          <label htmlFor="target-comparison-b" className="block text-xs font-semibold uppercase tracking-wider text-accent mb-2">Target B</label>
          <select
            id="target-comparison-b"
            className={selectClass}
            value={targetB}
            onChange={e => {
              const val = e.target.value;
              setTargetB(val);
              if (targetA && val) {
                setCompareLoading(true);
                setCompareError(null);
              } else {
                setComparisonData(null);
                setCompareError(null);
                setCompareLoading(false);
              }
            }}
          >
            <option value="">Select target...</option>
            {safeTargets.map(t => (
              <option key={t.name} value={t.name} disabled={t.name === targetA}>{t.name}</option>
            ))}
          </select>
        </GlassCard>
      </motion.div>

      {/* ── Loading ────────────────────────────────────────────── */}
      {compareLoading && (
        <GlassCard className="flex flex-col justify-center items-center py-16" hoverable={false}>
          <div className="w-8 h-8 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin mb-4" />
          <p className="text-sm text-[var(--text-secondary)]">Comparing security postures...</p>
        </GlassCard>
      )}

      {/* ── Error ──────────────────────────────────────────────── */}
      {compareError && (
        <GlassCard variant="error" hoverable={false} className="text-center py-6">
          <p className="text-sm text-bad">{compareError}</p>
        </GlassCard>
      )}

      {/* ── Comparison Grid ────────────────────────────────────── */}
      {!compareLoading && !compareError && selectedA && selectedB ? (
        <motion.div
          className="grid grid-cols-1 md:grid-cols-2 gap-6"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
        >
          <ComparisonColumn
            target={selectedA}
            otherTarget={selectedB}
            severityTotal={severityTotals.a}
            otherSeverityTotal={severityTotals.b}
            highestSev={highestSeverity.a}
            delay={0}
          />
          <ComparisonColumn
            target={selectedB}
            otherTarget={selectedA}
            severityTotal={severityTotals.b}
            otherSeverityTotal={severityTotals.a}
            highestSev={highestSeverity.b}
            delay={0.15}
          />
        </motion.div>
      ) : null}

      {/* ── Empty State ────────────────────────────────────────── */}
      {!compareLoading && !compareError && (!selectedA || !selectedB) && (
        <GlassCard className="text-center py-16" hoverable={false}>
          <ArrowLeftRight size={48} className="mx-auto mb-4 text-[var(--text-tertiary)]" />
          <p className="text-[var(--text-secondary)]">Select two targets to compare their security posture side by side.</p>
        </GlassCard>
      )}
    </div>
  );
}
