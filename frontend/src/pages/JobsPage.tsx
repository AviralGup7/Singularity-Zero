import type { CSSProperties } from 'react';
import JobList from '../components/JobList';
import { SkeletonCard, SkeletonText } from '../components/ui/Skeleton';
import { useJobs, usePersistedState } from '../hooks';

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

  return (
    <div className="jobs-page">
      <div className="page-header">
        <h2 data-focus-heading className="section-title">Pipeline Jobs</h2>
        <div className="jobs-page-summary">
          <span className="status-pill status-running">{runningCount} running</span>
          <span className="status-pill status-failed">{failedCount} failed</span>
          <span className="status-pill">{filtered.length} total</span>
        </div>
      </div>

      <div className="jobs-toolbar">
        <div className="search-wrapper">
          <label htmlFor="jobs-search" className="sr-only">Search jobs</label>
          <input
            type="search"
            id="jobs-search"
            placeholder="Search URL, status, mode, stage, reason code"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="search-input"
            aria-label="Search jobs by URL, status, mode, stage, or reason"
          />
        </div>
        <div className="filter-buttons" role="group" aria-label="Filter by status">
  // eslint-disable-next-line security/detect-object-injection
          {['all', 'running', 'completed', 'failed', 'stopped'].map((status) => (
            <button
              key={status}
              className={`filter-btn ${statusFilter === status ? 'active' : ''}`}
              onClick={() => setStatusFilter(status)}
              aria-pressed={statusFilter === status}
            >
              {status === 'all' ? 'All' : status.charAt(0).toUpperCase() + status.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <JobList jobs={filtered} onRefresh={() => { void refetch(); }} />

      <div aria-live="polite" aria-atomic="true" className="sr-only" id="job-progress-announcer-page">
        {`${filtered.length} jobs loaded. ${runningCount} running.`}
      </div>
    </div>
  );
}
