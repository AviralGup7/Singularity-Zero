import { Link } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  ShieldAlert,
  Target,
  Zap,
  Activity,
  Server,
  Clock
} from 'lucide-react';
import type { DashboardStats as StatsType, Job } from '../types/api';
import { useApi } from '../hooks/useApi';
import { DashboardStatsSchema } from '../api/schemas';
import { formatDistanceToNow } from '../utils/time';
import FindingsOverview from '@/features/findings/components/FindingsOverview';
import { DashboardSkeleton, GlassCard, AnimatedCounter, GlowProgress, PageHeader } from '../components/ui';

interface TelemetryCounts {
  [key: string]: number;
}

const STORAGE_KEY_STATS = 'dashboard:stats';
const STORAGE_KEY_JOBS = 'dashboard:jobs';
const STORAGE_KEY_TIMESTAMP = 'dashboard:timestamp';

function loadPersistedStats<T>(key: string): T | null {
  try {
    const raw = sessionStorage.getItem(key);
    if (!raw) return null;
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

function persistStats<T>(key: string, data: T): void {
  try {
    sessionStorage.setItem(key, JSON.stringify(data));
    sessionStorage.setItem(STORAGE_KEY_TIMESTAMP, String(Date.now()));
  } catch {
    // sessionStorage full or unavailable — silently degrade
  }
}



export function DashboardPage() {
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [tick, setTick] = useState(0);

  // Re-render every 30 seconds so the relative timestamp stays fresh
  useEffect(() => {
    const timer = setInterval(() => setTick(t => t + 1), 30_000);
    return () => clearInterval(timer);
  }, []);
  const [isStaleData, setIsStaleData] = useState(false);

  const { data: stats, loading: statsLoading, error: statsError } = useApi<StatsType>('/api/dashboard', { 
    refetchInterval: 10000,
    schema: DashboardStatsSchema,
    onSuccess: (data) => {
      setLastUpdated(new Date());
      persistStats(STORAGE_KEY_STATS, data);
      setIsStaleData(false);
    },
    onError: () => {
      setIsStaleData(true);
    }
  });
  
  const { data: jobsResponse, loading: jobsLoading, error: jobsError } = useApi<{ jobs: Job[]; total: number }>('/api/jobs', {
    refetchInterval: 5000,
    onSuccess: (data) => {
      setLastUpdated(new Date());
      persistStats(STORAGE_KEY_JOBS, data);
      setIsStaleData(false);
    },
    onError: () => {
      setIsStaleData(true);
    }
  });

  const persistedStats = (stats ?? loadPersistedStats<StatsType>(STORAGE_KEY_STATS)) ?? null;
  const persistedJobs = (jobsResponse ?? loadPersistedStats<{ jobs: Job[]; total: number }>(STORAGE_KEY_JOBS)) ?? null;

  const effectiveStats = stats ?? persistedStats;
  const effectiveJobs = jobsResponse ?? persistedJobs;
  const offlineFallback = !stats && !jobsResponse && (persistedStats || persistedJobs);
  const showStaleBanner = isStaleData && (effectiveStats || effectiveJobs);

  // Show skeleton only on initial load (no data yet). If one source
  // loads first, render the partial UI rather than blocking on both.
  if ((statsLoading && !effectiveStats) || (jobsLoading && !effectiveJobs)) {
    return <DashboardSkeleton />;
  }

  if ((statsError || jobsError) && !effectiveStats && !effectiveJobs) {
    return (
      <div className="space-y-6">
        <PageHeader
          icon={<ShieldAlert size={20} />}
          title="Dashboard"
          subtitle="Security Operations Overview"
        />
        <div className="card error" role="alert">
          <p>Failed to load dashboard data. {(statsError || jobsError)?.message}</p>
        </div>
      </div>
    );
  }

  const recentJobs = (effectiveJobs?.jobs ?? []).slice(0, 5);
  const telemetryTotals = (effectiveJobs?.jobs ?? []).reduce<Map<string, number>>((acc, job) => {
    const counts: TelemetryCounts = job.progress_telemetry?.event_counts ?? {};
    for (const [key, value] of Object.entries(counts)) {
      if (key === '__proto__' || key === 'constructor') continue;
      acc.set(key, (acc.get(key) ?? 0) + Number(value ?? 0));
    }
    return acc;
  }, new Map<string, number>());
  const telemetryEntries = Array.from(telemetryTotals.entries()).sort((a, b) => b[1] - a[1]).slice(0, 6);

  const activeJobsCount = (effectiveJobs?.jobs ?? []).filter(j => j.status === 'running').length || 0;
  const criticalFindings = effectiveStats?.findings_summary?.severity_totals?.critical || 0;
  const totalFindings = effectiveStats?.findings_summary?.total_findings || 0;
  const totalTargets = effectiveStats?.total_targets || 0;

  return (
    <div className="space-y-6">
      {showStaleBanner && (
        <div className="flex items-center gap-3 px-5 py-3 rounded-xl border border-[var(--warn)]/30 bg-[var(--warn)]/10 text-[var(--warn)] text-sm" role="alert">
          <CloudOff size={16} />
          <span className="font-medium">Backend unreachable</span>
          <span className="opacity-80">— showing last-known data</span>
          <span className="ml-auto text-xs opacity-60">cached {lastUpdated.toLocaleTimeString()}</span>
        </div>
      )}
      <PageHeader
        icon={<ShieldAlert size={20} />}
        title="Dashboard"
        subtitle={offlineFallback ? 'Security Operations Overview (offline mode)' : 'Security Operations Overview'}
        actions={
          <Link to={ROUTES.TARGETS} className="btn btn-primary cyber-gradient-btn rounded-lg px-4 py-2 text-sm font-semibold flex items-center gap-2">
            <Zap size={16} aria-hidden="true" /> New Scan
          </Link>
        }
      />

      {/* ── KPI Row ────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <GlassCard variant="accent-top" delay={0} hoverable>
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-muted">Total Targets</span>
            <Target size={16} className="text-muted" />
          </div>
          <div className="flex items-end gap-2">
            <AnimatedCounter value={totalTargets} className="text-2xl font-semibold text-[var(--text-primary)]" />
            <span className="text-xs text-muted mb-1">assets</span>
          </div>
        </GlassCard>
        
        <GlassCard variant="glow" delay={0.1} hoverable>
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-muted">Active Scans</span>
            <Activity size={16} className="text-accent" />
          </div>
          <div className="flex items-end gap-2">
            <AnimatedCounter value={activeJobsCount} className="text-2xl font-semibold text-[var(--text-primary)]" />
            {activeJobsCount > 0 && <span className="text-xs text-accent mb-1">in progress</span>}
          </div>
        </GlassCard>

        <GlassCard variant={criticalFindings > 0 ? 'error' : 'glow'} delay={0.2} hoverable>
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-muted">Open Findings</span>
            <ShieldAlert size={16} className={criticalFindings > 0 ? 'text-bad' : 'text-muted'} />
          </div>
          <div className="flex items-end gap-3">
            <AnimatedCounter value={totalFindings} className="text-2xl font-semibold text-[var(--text-primary)]" />
            {criticalFindings > 0 && (
              <span className="text-xs font-medium text-bad mb-1">{criticalFindings} Critical</span>
            )}
          </div>
        </GlassCard>

        <GlassCard variant="success" delay={0.3} hoverable>
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-muted">System Health</span>
            <Server size={16} className="text-ok" />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-2xl font-semibold text-ok">Optimal</span>
            <span
              className="w-2.5 h-2.5 rounded-full bg-ok"
              style={{ boxShadow: 'var(--glow-ok)', animation: 'glow-pulse 2s ease-in-out infinite' }}
            />
          </div>
          <div className="flex items-center gap-1 mt-2">
            <Clock size={10} className="text-muted" />
            <span className="text-xs text-muted">{formatDistanceToNow(lastUpdated)}</span>
          </div>
        </GlassCard>
      </div>

      {/* ── Severity Breakdown & Score ──────────────────────────── */}
      <FindingsOverview />

      <motion.section
        className="card card--accent-top"
        custom={0}
        initial="hidden"
        animate="visible"
        variants={sectionVariants}
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="card-title">Pipeline Telemetry Ledger</h3>
          <Link to={ROUTES.FINDINGS_TIMELINE} className="text-xs font-medium text-accent hover:text-accent-2 transition-colors">Inspect Timeline</Link>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {(telemetryEntries.length ? telemetryEntries : [['stage.progress', 0], ['artifact.discovered', 0], ['finding.discovered', 0]]).map(([name, count], idx) => (
            <GlassCard key={name} delay={0.05 * idx} hoverable padding>
              <div className="text-[10px] uppercase tracking-wide text-muted truncate">{name}</div>
              <div className="mt-2 flex items-end gap-2">
                <AnimatedCounter value={count as number} className="text-xl font-semibold text-[var(--text-primary)]" />
                <span className="text-xs text-muted mb-0.5">events</span>
              </div>
            </GlassCard>
          ))}
        </div>
      </motion.section>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Recent Activity Timeline */}
        <motion.div
          className="lg:col-span-2"
          custom={1}
          initial="hidden"
          animate="visible"
          variants={sectionVariants}
        >
          <section className="card">
            <div className="flex items-center justify-between mb-6">
              <h3 className="card-title">Recent Pipeline Jobs</h3>
              <Link to={ROUTES.JOBS} className="text-xs font-medium text-accent hover:text-accent-2 transition-colors">View All</Link>
            </div>
            
            <div className="space-y-4">
              {recentJobs.length === 0 ? (
                <div className="py-8 text-center text-muted text-sm">No recent jobs found</div>
              ) : recentJobs.map((job, idx) => (
                <motion.div
                  key={job.id}
                  initial={{ opacity: 0, x: -12 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.05 * idx, duration: 0.3 }}
                >
                  <Link 
                    to={`${ROUTES.JOBS}/${job.id}`}
                    className="flex items-center gap-4 p-3 rounded-lg border border-transparent hover:border-[var(--border)] transition-all duration-200 group hover:-translate-y-0.5 hover:bg-white/5 card--interactive"
                  >
                    <div className={`w-2.5 h-2.5 rounded-full ${
                      job.status === 'running' ? 'bg-accent shadow-[0_0_8px_rgba(59,130,246,0.5)]' :
                      job.status === 'completed' ? 'bg-ok' : 'bg-bad'
                    }`} />
                    
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm font-medium text-text group-hover:text-accent transition-colors">{job.id.slice(0, 8)}</span>
                        <span className="text-xs text-muted truncate">{job.target_name}</span>
                      </div>
                      <div className="text-[11px] text-muted uppercase tracking-wide">{job.stage_label || job.stage}</div>
                    </div>

                    <div className="w-24 md:w-32 shrink-0">
                      <GlowProgress
                        value={job.progress_percent}
                        variant={job.status === 'failed' ? 'danger' : job.status === 'completed' ? 'success' : 'cyber'}
                        size="sm"
                      />
                    </div>
                  </Link>
                </motion.div>
              ))}
            </div>
          </section>
        </motion.div>

        {/* Right Column: Alerts & Actions */}
        <motion.div
          className="space-y-6"
          custom={2}
          initial="hidden"
          animate="visible"
          variants={sectionVariants}
        >
          <GlassCard
            variant={criticalFindings > 0 ? 'error' : 'default'}
            hoverable={false}
            className={criticalFindings > 0 ? 'border-[var(--bad)]/30' : ''}
            style={criticalFindings > 0 ? { animation: 'glow-pulse 3s ease-in-out infinite', color: 'var(--bad)' } : undefined}
          >
            <h3 className={`text-sm font-semibold mb-4 flex items-center gap-2 ${criticalFindings > 0 ? 'text-bad' : 'text-text'}`}>
              <ShieldAlert size={16} /> Critical Alerts
            </h3>
            <div className="space-y-4">
              {criticalFindings > 0 ? (
                <div>
                   <p className="text-sm text-text leading-relaxed">Multiple critical findings detected. Immediate review required.</p>
                   <Link to={`${ROUTES.FINDINGS}?severity=critical`} className="inline-block mt-3 text-xs font-medium text-bad hover:underline">Review Findings →</Link>
                </div>
              ) : (
                <div className="py-4 text-center text-sm text-muted">
                  No critical alerts at this time.
                </div>
              )}
            </div>
          </GlassCard>

          <GlassCard hoverable={false}>
            <h3 className="text-sm font-semibold text-text mb-4">Quick Actions</h3>
            <div className="space-y-2">
              {[
                { label: 'Review Findings', icon: ShieldAlert, href: ROUTES.FINDINGS },
                { label: 'View Pipeline Overview', icon: Activity, href: ROUTES.PIPELINE },
              ].map(action => (
                <Link 
                  key={action.label} 
                  to={action.href}
                  className="flex items-center justify-between p-3 rounded-lg border border-[var(--border)] hover:border-[var(--accent)] hover:bg-white/5 transition-all duration-200 group hover:-translate-y-0.5"
                >
                  <div className="flex items-center gap-3">
                    <action.icon size={16} className="text-muted group-hover:text-accent transition-colors" />
                    <span className="text-sm font-medium text-text transition-colors">{action.label}</span>
                  </div>
                </Link>
              ))}
            </div>
          </GlassCard>
        </motion.div>

      </div>
    </div>
  );
}
