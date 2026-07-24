import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ROUTES } from '@/config/paths';
import { getJobs } from '@/api/client';
import type { Job } from '@/types/api';

export function LiveJobIndicator() {
   
  const [runningJobs, setRunningJobs] = useState<Job[]>([]);
   
  const [error, setError] = useState(false);

  async function fetchRunningJobs() {
    try {
      const allJobs = await getJobs();
      const running = allJobs.filter(j => j.status === 'running');
      setRunningJobs(running);
      setError(false);
    } catch {
      setError(true);
    }
  }

  useEffect(() => {
    let mounted = true;
    Promise.resolve().then(() => {
      if (mounted) fetchRunningJobs();
    });
    const interval = setInterval(fetchRunningJobs, 5000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  if (error || runningJobs.length === 0) return null;

  const tooltip = runningJobs.map(j => j.target_name || j.id.slice(0, 8)).join(', ');

  return (
    <Link
      to={ROUTES.JOBS}
      className="live-job-indicator group relative focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:outline-none rounded-full"
      aria-label={`${runningJobs.length} ${runningJobs.length === 1 ? 'job' : 'jobs'} running`}
      aria-live="polite"
      title={`Active Scans: ${tooltip}`}
    >
      <span className="pulse-dot" aria-hidden="true" />
      <span className="running-count">{runningJobs.length}</span>
      
      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-zinc-900 border border-line rounded text-[9px] text-text-primary whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
        {runningJobs.length} ACTIVE {runningJobs.length === 1 ? 'SCAN' : 'SCANS'}
      </div>
    </Link>
  );
}
