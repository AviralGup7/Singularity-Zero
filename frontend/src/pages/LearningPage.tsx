import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Brain,
  Database,
  LineChart as LineChartIcon,
  RefreshCw,
  ShieldCheck,
  Target,
  Zap,
} from 'lucide-react';
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  getFPPatterns,
  getLearningKPIs,
  getThresholdHistory,
} from '@/api/client';
import type {
  FPPattern,
  LearningKPIs,
  ThresholdHistoryEntry,
} from '@/api/client';
import { Button } from '@/components/ui/Button';

export function LearningPage() {
  const [kpis, setKpis] = useState<LearningKPIs | null>(null);
  const [thresholds, setThresholds] = useState<ThresholdHistoryEntry[]>([]);
  const [fpPatterns, setFpPatterns] = useState<FPPattern[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async (signal?: AbortSignal) => {
    try {
      setLoading(true);
      const [kpiRes, thRes, fpRes] = await Promise.all([
        getLearningKPIs(undefined, signal),
        getThresholdHistory(signal),
        getFPPatterns(true, signal),
      ]);
      setKpis(kpiRes);
      setThresholds(thRes.reverse()); // Chronological for chart
      setFpPatterns(fpRes);
      setError(null);
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== 'AbortError') {
        setError(err.message || 'Failed to load learning data');
      } else if (!(err instanceof Error)) {
        setError('An unexpected error occurred');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const controller = new AbortController();
    fetchData(controller.signal);
    return () => controller.abort();
  }, []);

  const chartData = useMemo(() => {
    return thresholds.map((t) => ({
      name: t.recorded_at.slice(5, 16).replace('T', ' '),
      low: t.low_threshold,
      medium: t.medium_threshold,
      high: t.high_threshold,
      fp_rate: t.observed_fp_rate * 10, // Scale for visibility
    }));
  }, [thresholds]);

  if (loading && !kpis) {
    return <div className="p-8 text-[var(--muted)]">Consulting neural mesh...</div>;
  }

  return (
    <motion.div
      className="learning-page space-y-6"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <section className="page-header flex justify-between items-center">
        <div>
          <h2 className="flex items-center gap-2">
            <Brain className="text-[var(--accent)]" />
            Autonomous Learning
          </h2>
          <p className="page-subtitle">Closed-loop feedback and detection threshold auto-calibration.</p>
        </div>
        <Button variant="secondary" onClick={() => fetchData()}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          Sync Neural State
        </Button>
      </section>

      {error && (
        <div className="card border-red-500/30 bg-red-500/5 p-4 text-red-400 text-sm">
          {error}
        </div>
      )}

      {/* KPI Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card p-4 space-y-1">
          <div className="text-[var(--muted)] text-xs flex items-center gap-1">
            <Zap size={12} /> Efficiency Index
          </div>
          <div className="text-2xl font-bold">{(kpis?.learning_efficiency_index ?? 0).toFixed(2)}</div>
          <div className="text-[10px] text-[var(--success)]">Self-improving</div>
        </div>
        <div className="card p-4 space-y-1">
          <div className="text-[var(--muted)] text-xs flex items-center gap-1">
            <ShieldCheck size={12} /> Avg. Precision
          </div>
          <div className="text-2xl font-bold text-[var(--success)]">
            {((kpis?.average_precision ?? 0) * 100).toFixed(1)}%
          </div>
          <div className="text-[10px] text-[var(--muted)]">Across all modules</div>
        </div>
        <div className="card p-4 space-y-1">
          <div className="text-[var(--muted)] text-xs flex items-center gap-1">
            <Target size={12} /> Active FP Patterns
          </div>
          <div className="text-2xl font-bold">{kpis?.active_fp_patterns ?? 0}</div>
          <div className="text-[10px] text-[var(--muted)]">Suppression mesh active</div>
        </div>
        <div className="card p-4 space-y-1">
          <div className="text-[var(--muted)] text-xs flex items-center gap-1">
            <Database size={12} /> Feedback Loop
          </div>
          <div className="text-2xl font-bold">{kpis?.total_feedback_events ?? 0}</div>
          <div className="text-[10px] text-[var(--muted)]">Learning events ingested</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threshold Convergence Chart */}
        <div className="lg:col-span-2 card p-6 space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-bold flex items-center gap-2">
              <LineChartIcon size={16} /> Threshold Convergence (PI Controller)
            </h3>
            {kpis?.thresholds_converged && (
              <span className="status-pill status-success text-[9px]">Converged</span>
            )}
          </div>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2D5676" opacity={0.3} />
                <XAxis dataKey="name" tick={{ fontSize: 10 }} stroke="var(--muted)" />
                <YAxis domain={[0, 10]} tick={{ fontSize: 10 }} stroke="var(--muted)" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0B1728', border: '1px solid #2D5676', fontSize: 11 }}
                />
                <Legend iconType="circle" wrapperStyle={{ fontSize: 11 }} />
                <Line type="monotone" dataKey="high" stroke="#ff0055" strokeWidth={2} dot={false} name="High Mark" />
                <Line type="monotone" dataKey="medium" stroke="#f59e0b" strokeWidth={2} dot={false} name="Med Mark" />
                <Line type="monotone" dataKey="low" stroke="#10b981" strokeWidth={2} dot={false} name="Low Mark" />
                <Line type="step" dataKey="fp_rate" stroke="#2FD8F8" strokeWidth={1} strokeDasharray="5 5" name="FP Rate (x10)" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent FP Patterns */}
        <div className="card p-6 space-y-4 overflow-hidden">
          <h3 className="text-sm font-bold flex items-center gap-2">
            <ShieldCheck size={16} /> Top Suppression Patterns
          </h3>
          <div className="space-y-3 max-h-[340px] overflow-y-auto pr-2 custom-scrollbar">
            {fpPatterns.length === 0 ? (
              <div className="text-[var(--muted)] text-xs italic py-10 text-center">
                No active patterns suppressed.
              </div>
            ) : (
              fpPatterns.slice(0, 10).map((pattern) => (
                <div key={pattern.pattern_id} className="p-3 bg-[var(--surface-1)] rounded border border-[var(--border)] space-y-2">
                  <div className="flex justify-between items-start">
                    <span className="text-[10px] font-mono text-[var(--accent)]">{pattern.category}</span>
                    <span className="text-[9px] text-[var(--muted)]">{pattern.occurrence_count} hits</span>
                  </div>
                  <div className="text-[10px] font-mono truncate opacity-80 bg-black/30 p-1 rounded">
                    {pattern.body_pattern || pattern.status_code_pattern || 'Response Hash Match'}
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="h-1 flex-1 bg-[var(--surface-2)] rounded-full overflow-hidden">
                      <div
                        className="h-full bg-[var(--accent)]"
                        style={{ width: `${pattern.fp_probability * 100}%` }}
                      />
                    </div>
                    <span className="text-[9px] font-bold">{(pattern.fp_probability * 100).toFixed(0)}% FP</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </motion.div>
  );
}
