import { useCallback, useEffect, useMemo, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { motion } from 'motion/react';
import {
  Activity,
  Database,
  Gauge,
  HardDrive,
  KeyRound,
  RefreshCw,
  Search,
  Server,
  Trash2,
  Zap,
} from 'lucide-react';
import {
  clearAllCaches,
  deleteCacheKeys,
  getCacheKeys,
  getCachePerformanceHistory,
  getCacheStatus,
  triggerCacheCleanup,
} from '@/api/cacheMgmt';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Input } from '@/components/ui/Input';
import { Progress } from '@/components/ui/Progress';
import { useMotionPolicy } from '@/hooks/useMotionPolicy';
import type {
  CacheKeyInfo,
  CacheKeysResponse,
  CachePerformancePoint,
  CacheStatusResponse,
} from '@/types/extended';

function formatBytes(bytes?: number | null): string {
  const value = bytes ?? 0;
  if (value <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${(value / Math.pow(1024, index)).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function formatRatio(value?: number | null): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'N/A';
  return `${Math.round(value * 100)}%`;
}

function ttlLabel(ttl?: number | null): string {
  if (ttl === null || ttl === undefined) return 'No expiry';
  if (ttl <= 0) return 'Expired';
  if (ttl < 60) return `${ttl}s`;
  if (ttl < 3600) return `${Math.round(ttl / 60)}m`;
  return `${(ttl / 3600).toFixed(1)}h`;
}

function clampPercent(value: number): number {
  return Math.max(0, Math.min(100, value));
}

function StatusPill({ connected }: { connected: boolean }) {
  return (
    <span className={`inline-flex items-center gap-2 text-xs font-mono ${connected ? 'text-[var(--ok)]' : 'text-[var(--muted)]'}`}>
      <span className={`h-2 w-2 rounded-full ${connected ? 'bg-[var(--ok)]' : 'bg-[var(--muted)]'}`} />
      {connected ? 'Connected' : 'Not connected'}
    </span>
  );
}

function MetricCard({
  icon,
  label,
  value,
  helper,
  progress,
  tone = 'accent',
}: {
  icon: ReactNode;
  label: string;
  value: string;
  helper?: string;
  progress?: number;
  tone?: 'accent' | 'success' | 'warning';
}) {
  const variant = tone === 'success' ? 'completed' : tone === 'warning' ? 'running' : 'default';
  return (
    <section className="card p-4 min-h-[132px]">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs text-[var(--muted)] font-mono uppercase tracking-wider">{label}</p>
          <p className="mt-2 text-2xl font-bold text-[var(--text)]">{value}</p>
        </div>
        <div className="rounded border border-[var(--line)] p-2 text-[var(--accent)]" aria-hidden="true">
          {icon}
        </div>
      </div>
      {progress !== undefined && (
        <Progress className="mt-4" value={clampPercent(progress)} variant={variant} size="sm" />
      )}
      {helper && <p className="mt-3 text-xs text-[var(--muted)]">{helper}</p>}
    </section>
  );
}

function HitRateGauge({ value }: { value?: number | null }) {
  const percent = clampPercent((value ?? 0) * 100);
  return (
    <div className="flex items-center gap-4">
      <div
        className="grid h-24 w-24 place-items-center rounded-full border border-[var(--line)]"
        style={{
          background: `conic-gradient(var(--ok) ${percent * 3.6}deg, var(--panel) 0deg)`,
        }}
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

function PerformanceLineChart({
  data,
  animate,
}: {
  data: { time: string; hit: number; miss: number }[];
  animate: boolean;
}) {
  if (data.length === 0) {
    return <div className="grid h-full place-items-center text-sm text-[var(--muted)]">No samples yet</div>;
  }

  const width = 800;
  const height = 240;
  const padding = { top: 18, right: 22, bottom: 34, left: 42 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const xFor = (index: number) => padding.left + (data.length === 1 ? 0 : (index / (data.length - 1)) * chartWidth);
  const yFor = (value: number) => padding.top + (1 - clampPercent(value) / 100) * chartHeight;
  const pathFor = (key: 'hit' | 'miss') => data.map((point, index) => `${xFor(index)},${yFor(point[key])}`).join(' ');
  const xTicks = data.filter((_, index) => index === 0 || index === data.length - 1 || index % Math.max(1, Math.floor(data.length / 4)) === 0);

  return (
    <svg className="h-full w-full" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="Cache hit and miss rate history">
      <title>Cache performance history</title>
      {[0, 25, 50, 75, 100].map(tick => (
        <g key={tick}>
          <line x1={padding.left} x2={width - padding.right} y1={yFor(tick)} y2={yFor(tick)} stroke="var(--line)" strokeDasharray="4 4" />
          <text x={padding.left - 10} y={yFor(tick) + 4} textAnchor="end" fill="var(--muted)" fontSize="11">{tick}%</text>
        </g>
      ))}
      {xTicks.map(point => {
        const index = data.indexOf(point);
        return (
          <text key={`${point.time}-${index}`} x={xFor(index)} y={height - 10} textAnchor="middle" fill="var(--muted)" fontSize="11">
            {point.time}
          </text>
        );
      })}
      <polyline
        points={pathFor('hit')}
        fill="none"
        stroke="var(--ok)"
        strokeWidth="3"
        strokeLinecap="round"
        strokeLinejoin="round"
        className={animate ? 'transition-all duration-300' : undefined}
      />
      <polyline
        points={pathFor('miss')}
        fill="none"
        stroke="var(--warn)"
        strokeWidth="3"
        strokeLinecap="round"
        strokeLinejoin="round"
        className={animate ? 'transition-all duration-300' : undefined}
      />
      <g transform={`translate(${width - 160} 16)`}>
        <circle cx="0" cy="0" r="4" fill="var(--ok)" />
        <text x="10" y="4" fill="var(--text)" fontSize="12">Hit</text>
        <circle cx="58" cy="0" r="4" fill="var(--warn)" />
        <text x="68" y="4" fill="var(--text)" fontSize="12">Miss</text>
      </g>
    </svg>
  );
}

export function CacheManagementPage() {
  const { policy, strategy } = useMotionPolicy('graph');
  const [status, setStatus] = useState<CacheStatusResponse | null>(null);
  const [keys, setKeys] = useState<CacheKeysResponse | null>(null);
  const [history, setHistory] = useState<CachePerformancePoint[]>([]);
  const [pattern, setPattern] = useState('*');
  const [flushPattern, setFlushPattern] = useState('subdomain:*');
  const [loading, setLoading] = useState(true);
  const [keysLoading, setKeysLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const refreshOverview = useCallback(async (signal?: AbortSignal) => {
    const [statusRes, historyRes] = await Promise.all([
      getCacheStatus(signal),
      getCachePerformanceHistory(signal),
    ]);
    setStatus(statusRes);
    setHistory(historyRes.points);
  }, []);

  const refreshKeys = useCallback(async (nextPattern = pattern, signal?: AbortSignal) => {
    setKeysLoading(true);
    try {
      const keyRes = await getCacheKeys(nextPattern.trim() || '*', 100, signal);
      setKeys(keyRes);
    } finally {
      setKeysLoading(false);
    }
  }, [pattern]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    refreshOverview(controller.signal)
      .then(() => refreshKeys(pattern, controller.signal))
      .then(() => setError(null))
      .catch((err: { message?: string }) => setError(err.message || 'Failed to load cache telemetry'))
      .finally(() => setLoading(false));

    const interval = window.setInterval(() => {
      refreshOverview().catch((err: { message?: string }) => setError(err.message || 'Failed to refresh cache telemetry'));
    }, 10000);

    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, [pattern, refreshKeys, refreshOverview]);

  const chartData = useMemo(() => history.map(point => ({
    time: new Date(point.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    hit: Math.round((point.hit_rate ?? 0) * 100),
    miss: Math.round((point.miss_rate ?? 0) * 100),
  })), [history]);

  const redisMemoryPercent = useMemo(() => {
    const used = status?.redis.used_memory_bytes ?? 0;
    const max = status?.redis.max_memory_bytes || 512 * 1024 * 1024;
    return max ? (used / max) * 100 : 0;
  }, [status]);

  const sqliteDiskPercent = useMemo(() => {
    const size = status?.sqlite.file_size_mb ?? 0;
    return (size / 256) * 100;
  }, [status]);

  const simulator = useMemo(() => {
    const firstKey: CacheKeyInfo | undefined = keys?.keys[0];
    const sizeFactor = Math.min(90, Math.round((firstKey?.size ?? 4096) / 2048));
    const warm = status?.redis.connected ? 8 : 22;
    const cold = warm + 95 + sizeFactor;
    return {
      key: firstKey?.key ?? pattern,
      warm,
      cold,
      delta: cold - warm,
    };
  }, [keys, pattern, status]);

  async function handleSearch(event: FormEvent) {
    event.preventDefault();
    await refreshKeys(pattern);
  }

  async function handleDeletePattern(nextPattern: string) {
    if (!nextPattern.trim()) return;
    setActionLoading(true);
    try {
      const res = await deleteCacheKeys(nextPattern.trim());
      setMessage(`Deleted ${res.deleted} of ${res.matched} matching Redis keys.`);
      await Promise.all([refreshOverview(), refreshKeys(pattern)]);
    } catch (err: unknown) {
      setMessage(err instanceof Error ? err.message : 'Pattern flush failed.');
    } finally {
      setActionLoading(false);
    }
  }

  async function handleClearAll() {
    setActionLoading(true);
    try {
      const res = await clearAllCaches();
      setMessage(`Cleared ${res.cleared} cache entries.`);
      await Promise.all([refreshOverview(), refreshKeys(pattern)]);
    } catch (err: unknown) {
      setMessage(err instanceof Error ? err.message : 'Clear all failed.');
    } finally {
      setConfirmClear(false);
      setActionLoading(false);
    }
  }

  async function handleCleanup() {
    setActionLoading(true);
    try {
      const res = await triggerCacheCleanup();
      setMessage(`Cleaned ${res.cleaned} expired entries in ${res.duration_seconds.toFixed(2)}s.`);
      await Promise.all([refreshOverview(), refreshKeys(pattern)]);
    } catch (err: unknown) {
      setMessage(err instanceof Error ? err.message : 'Cleanup failed.');
    } finally {
      setActionLoading(false);
    }
  }

  if (loading && !status) {
    return <div className="p-8 text-[var(--muted)]">Loading cache telemetry...</div>;
  }

  return (
    <motion.div
      className="cache-management-page p-6 space-y-6"
      initial={policy.allowFramer ? { opacity: 0, y: strategy.distance } : false}
      animate={policy.allowFramer ? { opacity: 1, y: 0 } : undefined}
      transition={{ duration: strategy.duration || 0.2, ease: 'easeOut' }}
    >
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text)]">Cache Management</h1>
          <p className="text-sm text-[var(--muted)]">Redis, SQLite, key exploration, and rolling cache performance.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" onClick={() => refreshOverview()} disabled={actionLoading}>
            <RefreshCw size={15} aria-hidden="true" />
            Refresh
          </Button>
          <Button variant="secondary" onClick={handleCleanup} loading={actionLoading}>
            <Zap size={15} aria-hidden="true" />
            Cleanup
          </Button>
          <Button variant="danger" onClick={() => setConfirmClear(true)} disabled={actionLoading}>
            <Trash2 size={15} aria-hidden="true" />
            Clear All
          </Button>
        </div>
      </div>

      {(error || message) && (
        <div className="banner" role="status">
          <span>{error || message}</span>
          <button className="ml-3 text-xs text-[var(--muted)] hover:text-[var(--text)]" onClick={() => { setError(null); setMessage(null); }}>
            Dismiss
          </button>
        </div>
      )}

      <section className="grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-mono text-sm uppercase tracking-wider text-[var(--muted)]">Redis Overview</h2>
            <StatusPill connected={!!status?.redis.connected} />
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            <MetricCard
              icon={<Database size={19} />}
              label="Memory"
              value={status?.redis.connected ? status.redis.used_memory_human : 'Not connected'}
              helper={status?.redis.connected ? `${formatBytes(status.redis.used_memory_bytes)} allocated` : status?.redis.error || 'Redis unavailable'}
              progress={status?.redis.connected ? redisMemoryPercent : 0}
            />
            <MetricCard
              icon={<KeyRound size={19} />}
              label="Keys"
              value={status?.redis.connected ? status.redis.keys_count.toLocaleString() : 'N/A'}
              helper={`${status?.redis.connected_clients ?? 0} clients connected`}
              tone="success"
            />
            <section className="card p-4 min-h-[132px]">
              <HitRateGauge value={status?.redis.hit_rate} />
            </section>
          </div>
        </div>

        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-mono text-sm uppercase tracking-wider text-[var(--muted)]">SQLite Overview</h2>
            <StatusPill connected={!!status?.sqlite.connected} />
          </div>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-1">
            <MetricCard
              icon={<HardDrive size={19} />}
              label="Disk Cache"
              value={status?.sqlite.connected ? `${status.sqlite.file_size_mb.toFixed(2)} MB` : 'Not connected'}
              helper={status?.sqlite.connected ? `${status.sqlite.entry_count.toLocaleString()} entries` : status?.sqlite.error || 'SQLite unavailable'}
              progress={status?.sqlite.connected ? sqliteDiskPercent : 0}
              tone="warning"
            />
            <MetricCard
              icon={<Gauge size={19} />}
              label="Hit Ratio"
              value={formatRatio(status?.sqlite.cache_hit_ratio)}
              helper={`${(status?.sqlite.query_count ?? 0).toLocaleString()} approximate reads`}
              tone="success"
            />
          </div>
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[1fr_0.85fr]">
        <div className="card p-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
            <div>
              <h2 className="text-lg font-semibold text-[var(--text)]">Key Explorer</h2>
              <p className="text-sm text-[var(--muted)]">{keys?.connected ? `${keys.count} keys shown` : 'Not connected'}</p>
            </div>
            <form className="flex flex-col gap-2 sm:flex-row" onSubmit={handleSearch}>
              <Input id="cache-key-pattern" label="Pattern" value={pattern} onChange={event => setPattern(event.target.value)} />
              <Button className="self-end" type="submit" variant="secondary" loading={keysLoading}>
                <Search size={15} aria-hidden="true" />
                Search
              </Button>
            </form>
          </div>

          <div className="mt-4 overflow-hidden border border-[var(--line)]">
            <div className="grid grid-cols-[1fr_86px_92px_84px] gap-3 bg-[var(--panel)] px-3 py-2 text-xs font-mono uppercase tracking-wider text-[var(--muted)]">
              <span>Key</span>
              <span>TTL</span>
              <span>Size</span>
              <span className="text-right">Action</span>
            </div>
            <div className="max-h-[360px] overflow-auto">
              {!keys?.connected && (
                <div className="px-3 py-8 text-center text-sm text-[var(--muted)]">Not connected</div>
              )}
              {keys?.connected && keys.keys.length === 0 && (
                <div className="px-3 py-8 text-center text-sm text-[var(--muted)]">No matching keys</div>
              )}
              {keys?.keys.map(item => (
                <div key={item.key} className="grid grid-cols-[1fr_86px_92px_84px] items-center gap-3 border-t border-[var(--line)] px-3 py-2 text-sm">
                  <div className="min-w-0">
                    <p className="truncate font-mono text-[var(--text)]" title={item.key}>{item.key}</p>
                    <p className="text-xs text-[var(--muted)]">{item.type || 'unknown'}</p>
                  </div>
                  <span className="font-mono text-xs text-[var(--muted)]">{ttlLabel(item.ttl)}</span>
                  <span className="font-mono text-xs text-[var(--muted)]">{formatBytes(item.size)}</span>
                  <Button size="sm" variant="ghost" onClick={() => handleDeletePattern(item.key)} disabled={actionLoading}>
                    <Trash2 size={14} aria-hidden="true" />
                    Delete
                  </Button>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <section className="card p-4">
            <h2 className="text-lg font-semibold text-[var(--text)]">Actions</h2>
            <div className="mt-4 flex flex-col gap-3">
              <Input
                id="cache-flush-pattern"
                label="Flush Pattern"
                value={flushPattern}
                onChange={event => setFlushPattern(event.target.value)}
              />
              <Button variant="danger" onClick={() => handleDeletePattern(flushPattern)} disabled={!flushPattern.trim()} loading={actionLoading}>
                <Trash2 size={15} aria-hidden="true" />
                Flush Pattern
              </Button>
            </div>
          </section>

          <section className="card p-4">
            <div className="flex items-center justify-between gap-4">
              <div>
                <h2 className="text-lg font-semibold text-[var(--text)]">Cache Simulator</h2>
                <p className="truncate text-xs text-[var(--muted)]" title={simulator.key}>{simulator.key}</p>
              </div>
              <Server className="text-[var(--accent)]" size={20} aria-hidden="true" />
            </div>
            <div className="mt-4 space-y-3">
              <div>
                <div className="flex justify-between text-xs font-mono text-[var(--muted)]">
                  <span>Cached lookup</span>
                  <span>{simulator.warm}ms</span>
                </div>
                <Progress value={simulator.warm} max={simulator.cold} size="sm" variant="completed" />
              </div>
              <div>
                <div className="flex justify-between text-xs font-mono text-[var(--muted)]">
                  <span>After clear</span>
                  <span>{simulator.cold}ms</span>
                </div>
                <Progress value={simulator.cold} max={simulator.cold} size="sm" variant="failed" />
              </div>
              <p className="text-sm text-[var(--text)]">{simulator.delta}ms estimated lookup penalty on the next miss.</p>
              {policy.allowFramer && (
                <div className="relative h-8 overflow-hidden border border-[var(--line)] bg-[var(--panel)]" aria-hidden="true">
                  {[0, 1, 2].map(index => (
                    <motion.span
                      key={index}
                      className="absolute top-3 h-2 w-8 bg-[var(--accent)]"
                      initial={{ x: -40, opacity: 0.2 }}
                      animate={{ x: 360, opacity: [0.2, 0.9, 0.2] }}
                      transition={{ duration: 2.4, repeat: Infinity, delay: index * 0.45, ease: 'linear' }}
                    />
                  ))}
                </div>
              )}
            </div>
          </section>
        </div>
      </section>

      <section className="card p-4">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-[var(--text)]">Performance History</h2>
            <p className="text-sm text-[var(--muted)]">Last hour at one-minute resolution.</p>
          </div>
          <Activity className="text-[var(--accent)]" size={20} aria-hidden="true" />
        </div>
        <div className="h-[280px]">
          <PerformanceLineChart data={chartData} animate={policy.allowFramer} />
        </div>
      </section>

      <ConfirmDialog
        isOpen={confirmClear}
        title="Clear All Caches"
        message="This clears every configured cache tier and can make the next lookups slower until the cache warms again."
        confirmText="Clear All"
        cancelText="Cancel"
        variant="danger"
        onConfirm={handleClearAll}
        onCancel={() => setConfirmClear(false)}
      />
    </motion.div>
  );
}
