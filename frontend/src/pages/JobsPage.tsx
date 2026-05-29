import type { CSSProperties } from 'react';
import { motion } from 'framer-motion';
import { Briefcase, Search } from 'lucide-react';
import JobList from '../components/JobList';
import { SkeletonCard, SkeletonText } from '../components/ui/Skeleton';
import { PageHeader } from '../components/ui';
import { useJobs, usePersistedState } from '../hooks';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

export function JobsPage() {
  const { data: jobs, loading, error, refetch } = useJobs({ refetchInterval: 5000 });
   
  const [statusFilter, setStatusFilter] = usePersistedState<string>('jobs-status-filter', 'all');
   
  const [searchQuery, setSearchQuery] = usePersistedState<string>('jobs-search-query', '');

  if (loading) {
    return (
      <div className="jobs-page">
        <div className="page-header">
          <SkeletonText lines={1} />
          <div className="flex gap-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="skeleton skeleton-line" style={{ '--skel-width': '60px', '--skel-height': '1em' } as CSSProperties} />
            ))}
          </div>
        </div>
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
      </div>
    );
  }

  if (error) {
    return (
      <div className="card error jobs-page-error">
        <h2>Error loading jobs</h2>
        <p>{error.message}</p>
        <button onClick={() => { void refetch(); }} className="btn btn-primary">Retry</button>
      </div>
    );
  }

  const filtered = (jobs ?? [])
    .filter(j => statusFilter === 'all' || j?.status === statusFilter)
    .filter(j => {
      if (!searchQuery) return true;
      const q = searchQuery.toLowerCase();
      return (
        (j?.base_url ?? '').toLowerCase().includes(q) ||
        (j?.status ?? '').toLowerCase().includes(q) ||
        (j?.mode ?? '').toLowerCase().includes(q) ||
        (j?.failed_stage ?? '').toLowerCase().includes(q) ||
        (j?.failure_reason_code ?? '').toLowerCase().includes(q)
      );
    });

  const runningCount = filtered.filter(j => j?.status === 'running').length;
  const failedCount = filtered.filter(j => j?.status === 'failed').length;

  const statusFilters = ['all', 'running', 'completed', 'failed', 'stopped'] as const;

  return (
    <div className="jobs-page space-y-6">
      <PageHeader
        icon={<Briefcase size={20} />}
        title="Pipeline Jobs"
        subtitle={
          <span className="flex items-center gap-2">
            <span
              className="status-pill status-running"
              style={runningCount > 0 ? { animation: 'glow-pulse 2s ease-in-out infinite', color: 'var(--accent)' } : undefined}
            >
              {runningCount} running
            </span>
            <span className="status-pill status-failed">{failedCount} failed</span>
            <span className="status-pill">{filtered.length} total</span>
          </span>
        }
      />

      <motion.div
        className="jobs-toolbar"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, ease: EASE_OUT }}
      >
        <div className="search-wrapper relative">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted pointer-events-none" />
          <label htmlFor="jobs-search" className="sr-only">Search jobs</label>
          <input
            type="search"
            id="jobs-search"
            placeholder="Search URL, status, mode, stage, reason code"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="search-input pl-9"
            aria-label="Search jobs by URL, status, mode, stage, or reason"
          />
        </div>
        <div className="filter-buttons" role="group" aria-label="Filter by status">
          {statusFilters.map((status) => (
            <button
              key={status}
              className={`filter-btn transition-all duration-200 ${
                statusFilter === status
                  ? 'bg-[var(--accent-soft)] text-accent border-[var(--accent)]/30'
                  : 'hover:bg-white/5'
              }`}
              onClick={() => setStatusFilter(status)}
              aria-pressed={statusFilter === status}
            >
              {status === 'all' ? 'All' : status.charAt(0).toUpperCase() + status.slice(1)}
            </button>
          ))}
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.1, ease: EASE_OUT }}
      >
        <JobList jobs={filtered} onRefresh={() => { void refetch(); }} />
      </motion.div>

      <div aria-live="polite" aria-atomic="true" className="sr-only" id="job-progress-announcer-page">
        {`${filtered.length} jobs loaded. ${runningCount} running.`}
      </div>
    </div>
  );
}
