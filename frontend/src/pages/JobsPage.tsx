import type { CSSProperties } from 'react';
import { useState, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Briefcase, Search } from 'lucide-react';
import JobList from '../components/jobs/JobList';
import StartJobForm from '../components/jobs/StartJobForm';
import { SkeletonCard, SkeletonText } from '../components/ui/Skeleton';
import { PageHeader, EmptyState, Pagination, ErrorCard } from '../components/ui';
import { useJobsContext } from '../context/JobsContext';
import { usePersistedState } from '../hooks';
import { JOB_STATUS_FILTERS, normalizeJobStatusFilter } from './jobsFilters';
import { pickPreferredFilter } from '../stores/settingsHydrate';
import { clampFindingsPage } from '../features/findings/findingsViewMode';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const PAGE_SIZE = 20;
const STATUS_FILTERS = JOB_STATUS_FILTERS;

export function JobsPage() {
  const navigate = useNavigate();
  const { jobs, loading, error, refetch } = useJobsContext();
  const [searchParams, setSearchParams] = useSearchParams();
   
  const [statusFilter, setStatusFilter] = usePersistedState<string>('jobs-status-filter', searchParams.get('status') || 'all');
  const safeStatusFilter = normalizeJobStatusFilter(pickPreferredFilter(searchParams.get('status'), statusFilter));
   
  const [searchQuery, setSearchQuery] = usePersistedState<string>('jobs-search-query', searchParams.get('q') || '');
  const [currentPage, setCurrentPage] = useState(1);

  const updateUrlParams = useCallback((status: string, q: string) => {
    setSearchParams(prev => {
      const params = new URLSearchParams(prev);
      if (status && status !== 'all') {
        params.set('status', status);
      } else {
        params.delete('status');
      }
      if (q) {
        params.set('q', q);
      } else {
        params.delete('q');
      }
      return params;
    }, { replace: true });
  }, [setSearchParams]);

  const handleStatusChange = useCallback((status: string) => {
    setStatusFilter(status);
    setCurrentPage(1);
    updateUrlParams(normalizeJobStatusFilter(status), searchQuery);
  }, [setStatusFilter, searchQuery, updateUrlParams]);

  const handleSearchChange = useCallback((q: string) => {
    setSearchQuery(q);
    setCurrentPage(1);
    updateUrlParams(safeStatusFilter, q);
  }, [setSearchQuery, safeStatusFilter, updateUrlParams]);

  const filtered = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return (jobs ?? [])
      .filter(j => safeStatusFilter === 'all' || j?.status === safeStatusFilter)
      .filter(j => !query || [
        j?.base_url,
        j?.status,
        j?.mode,
        j?.failed_stage,
        j?.failure_reason_code,
      ].some(value => value?.toLowerCase().includes(query)));
  }, [jobs, searchQuery, statusFilter]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);

  const safePage = Math.min(currentPage, Math.max(1, totalPages));
  const paginatedJobs = useMemo(() => {
    const start = (safePage - 1) * PAGE_SIZE;
    return filtered.slice(start, start + PAGE_SIZE);
  }, [filtered, safePage]);

  const runningCount = filtered.filter(j => j?.status === 'running').length;
  const failedCount = filtered.filter(j => j?.status === 'failed').length;

  return (
    <div className="jobs-page space-y-6">
      <PageHeader
        icon={<Briefcase size={20} />}
        title="Pipeline Jobs"
        subtitle={
          loading ? (
            'Manage and monitor scan jobs'
          ) : (
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
          )
        }
      />

      <StartJobForm
        onJobStarted={(jobId) => {
          void refetch();
          navigate(`/jobs/${jobId}`);
        }}
      />

      {loading && (
        <div className="space-y-4">
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
      )}

      {!loading && error && (
        <ErrorCard
          title="Error loading jobs"
          message={error.message}
          onRetry={() => { void refetch(); }}
        />
      )}

      {!loading && !error && (
      <>
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
            onChange={e => handleSearchChange(e.target.value)}
            className="search-input pl-9"
            aria-label="Search jobs by URL, status, mode, stage, or reason"
          />
        </div>
        <div className="filter-buttons" role="group" aria-label="Filter by status">
          {STATUS_FILTERS.map((status) => (
            <button
              key={status}
              className={`filter-btn transition-all duration-200 ${
                safeStatusFilter === status
                  ? 'bg-accent-dim text-accent border-accent/30'
                  : 'hover:bg-surface-hover'
              }`}
              onClick={() => handleStatusChange(status)}
              aria-pressed={safeStatusFilter === status}
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
        {filtered.length === 0 ? (
          <EmptyState
            title="No jobs found"
            description={safeStatusFilter !== 'all' || searchQuery 
              ? "No jobs match your current filters. Try adjusting the status filter or search query."
              : "No pipeline jobs have been run yet. Expand Start New Scan above, or launch from Targets / Cockpit."}
            icon="zap"
          />
        ) : (
          <>
            <JobList jobs={paginatedJobs} onRefresh={() => { void refetch(); }} />
            {totalPages > 1 && (
              <Pagination
                page={safePage}
                pageSize={PAGE_SIZE}
                total={filtered.length}
                onPageChange={setCurrentPage}
              />
            )}
          </>
        )}
      </motion.div>

      <div aria-live="polite" aria-atomic="true" className="sr-only" id="job-progress-announcer-page">
        {`${filtered.length} jobs loaded. ${runningCount} running.`}
      </div>
      </>
      )}
    </div>
  );
}
