import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { scaleLinear } from 'd3-scale';
import { area, curveMonotoneX, line } from 'd3-shape';
import { Activity, Database, RefreshCw, RadioTower } from 'lucide-react';
import { forceBloomReconcile, getBloomHealth } from '@/api/bloom';
import { useAuth } from '@/hooks/useAuth';
import { useMotionPolicy } from '@/hooks/useMotionPolicy';
import type { BloomHealthResponse, BloomNodeHealth } from '@/types/api';

export function BloomMeshHealthPanel() {
   
  const [health, setHealth] = useState<BloomHealthResponse | null>(null);
   
  const [busy, setBusy] = useState(false);
   
  const [lastAction, setLastAction] = useState('');
  const { user } = useAuth();
  const { policy, strategy } = useMotionPolicy('graph');
  const isAdmin = user?.role === 'admin';

  useEffect(() => {
    const controller = new AbortController();
    const refresh = () => {
      getBloomHealth(controller.signal)
        .then(setHealth)
        .catch(() => {});
    };
    refresh();
    const interval = window.setInterval(refresh, 5000);
    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, []);

  const aggregate = useMemo(() => {
    const nodes = health?.nodes ?? [];
    const memory = nodes.reduce((sum, node) => sum + node.memory_mb, 0);
    const elements = nodes.reduce((sum, node) => sum + node.element_count, 0);
    const fp = nodes.length ? Math.max(...nodes.map((node) => node.false_positive_probability)) : 0;
    const fill = nodes.length ? Math.max(...nodes.map((node) => node.fill_ratio)) : 0;
    return { memory, elements, fp, fill, nodes };
   
  }, [health]);

  const chartData = useMemo(() => {
    return (health?.saturation_history ?? []).map((point) => ({
      time: point.time,
      saturation: Number((point.fill_ratio * 100).toFixed(2)),
      fp: Number((point.false_positive_probability * 100).toFixed(4)),
    }));
   
  }, [health]);

   
  const chartPath = useMemo(() => buildSaturationPath(chartData), [chartData]);

  async function reconcile() {
    setBusy(true);
    setLastAction('');
    try {
      const result = await forceBloomReconcile();
      setLastAction(result.status);
      const next = await getBloomHealth();
      setHealth(next);
    } catch {
      setLastAction('failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <motion.section
      className="glass-panel p-6 rounded-2xl overflow-hidden"
      initial={policy.allowFramer ? { opacity: 0, y: strategy.distance } : false}
      animate={policy.allowFramer ? { opacity: 1, y: 0 } : undefined}
      transition={{ duration: strategy.duration, ease: 'easeOut' }}
    >
      <div className="flex items-start justify-between gap-4 mb-5">
        <div>
          <h3 className="text-xs font-black text-muted uppercase tracking-widest flex items-center gap-2">
            <Database size={14} className="text-accent" /> Bloom Mesh Health
          </h3>
  // eslint-disable-next-line security/detect-object-injection
          <p className="mt-1 text-[10px] text-muted/70 uppercase tracking-widest">
            {health?.redis_enabled ? 'Redis sync online' : 'Local filter mode'}
          </p>
        </div>
        {isAdmin ? (
          <button
            type="button"
            onClick={reconcile}
            disabled={busy}
   
            className="btn-secondary flex items-center gap-2 text-[10px] disabled:opacity-50"
          >
            <RefreshCw size={13} className={busy ? 'animate-spin' : ''} />
            Reconcile
          </button>
        ) : null}
      </div>

      <div className="grid grid-cols-2 gap-3 mb-5">
        <Metric label="Nodes" value={String(aggregate.nodes.length || 1)} />
        <Metric label="Memory" value={`${aggregate.memory.toFixed(1)} MB`} />
        <Metric label="Elements" value={compactNumber(aggregate.elements)} />
        <Metric label="FP Prob" value={`${(aggregate.fp * 100).toFixed(3)}%`} tone={aggregate.fp > 0.001 ? 'bad' : 'ok'} />
      </div>

      <div className="h-32 rounded-xl border border-white/5 bg-black/10 p-2">
        <svg viewBox="0 0 320 112" role="img" aria-label="Bloom filter saturation over time" className="h-full w-full overflow-visible">
          <defs>
            <linearGradient id="bloomSaturation" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="var(--accent)" stopOpacity={0.5} />
              <stop offset="95%" stopColor="var(--accent)" stopOpacity={0.02} />
            </linearGradient>
          </defs>
  // eslint-disable-next-line security/detect-object-injection
          {[24, 56, 88].map((y) => (
            <line key={y} x1="0" x2="320" y1={y} y2={y} stroke="rgba(255,255,255,0.06)" />
          ))}
          {chartPath.fill ? <path d={chartPath.fill} fill="url(#bloomSaturation)" /> : null}
          {chartPath.line ? (
            <motion.path
              d={chartPath.line}
              fill="none"
              stroke="var(--accent)"
              strokeWidth="2.5"
              strokeLinecap="round"
              initial={policy.tier === 'full' ? { pathLength: 0 } : false}
              animate={policy.tier === 'full' ? { pathLength: 1 } : undefined}
              transition={{ duration: 0.8, ease: 'easeOut' }}
            />
          ) : null}
        </svg>
      </div>

      <div className="mt-5 space-y-2">
        {(health?.nodes ?? []).slice(0, 4).map((node) => (
          <NodeRow key={node.node_id} node={node} />
        ))}
      </div>

      {lastAction ? (
   
        <div className="mt-4 text-[10px] font-bold uppercase tracking-widest text-muted">
          Last reconcile: <span className="text-accent">{lastAction}</span>
        </div>
      ) : null}
    </motion.section>
  );
}

function Metric({ label, value, tone = 'text' }: { label: string; value: string; tone?: 'text' | 'ok' | 'bad' }) {
  const toneClass = tone === 'ok' ? 'text-ok' : tone === 'bad' ? 'text-bad' : 'text-white';
  return (
    <div className="p-3 bg-white/5 rounded-xl border border-white/5 min-w-0">
  // eslint-disable-next-line security/detect-object-injection
      <div className="text-[9px] text-muted font-bold uppercase mb-1">{label}</div>
      <div className={`text-lg font-black truncate ${toneClass}`}>{value}</div>
    </div>
  );
}

function NodeRow({ node }: { node: BloomNodeHealth }) {
  return (
   
    <div className="flex items-center justify-between gap-3 rounded-xl border border-white/5 bg-white/[0.03] px-3 py-2">
      <div className="flex items-center gap-2 min-w-0">
        {node.stale ? <RadioTower size={13} className="text-bad" /> : <Activity size={13} className="text-ok" />}
  // eslint-disable-next-line security/detect-object-injection
        <span className="text-[10px] font-black text-text font-mono truncate">{node.node_id}</span>
      </div>
  // eslint-disable-next-line security/detect-object-injection
      <div className="text-[10px] text-muted font-mono shrink-0">
        {(node.fill_ratio * 100).toFixed(1)}% / {timeAgo(node.last_sync_time)}
      </div>
    </div>
  );
}

function compactNumber(value: number): string {
  return Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 }).format(value);
}

function timeAgo(epochSeconds: number): string {
  if (!epochSeconds) return 'never';
  const age = Math.max(0, Date.now() / 1000 - epochSeconds);
  if (age < 60) return `${Math.round(age)}s`;
  if (age < 3600) return `${Math.round(age / 60)}m`;
  return `${Math.round(age / 3600)}h`;
}

function buildSaturationPath(points: { time: number; saturation: number }[]): { line: string; fill: string } {
  if (points.length < 2) return { line: '', fill: '' };
  const x = scaleLinear()
   
    .domain([0, points.length - 1])
   
    .range([6, 314]);
  const y = scaleLinear()
   
    .domain([0, Math.max(5, ...points.map((point) => point.saturation))])
   
    .range([104, 8]);
   
  const linePath = line<(typeof points)[number]>()
    .x((_, index) => x(index))
    .y((point) => y(point.saturation))
    .curve(curveMonotoneX)(points);
   
  const fillPath = area<(typeof points)[number]>()
    .x((_, index) => x(index))
    .y0(106)
    .y1((point) => y(point.saturation))
    .curve(curveMonotoneX)(points);
  return { line: linePath ?? '', fill: fillPath ?? '' };
}
