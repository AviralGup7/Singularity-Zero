import { useState, useEffect, useCallback } from 'react';
import type { JobTimelineEntry } from '@/types/extended';
import { getJobTimeline } from '@/api/analysis';
import { getJob } from '@/api/jobs';
import type { Job } from '@/types/api';

const STAGE_COLORS: Record<string, string> = {
  discovery: 'bg-blue-500',
  collection: 'bg-purple-500',
  analysis: 'bg-yellow-500',
  validation: 'bg-orange-500',
  reporting: 'bg-green-500',
  default: 'bg-gray-500',
};

export function JobTimelineComponent({ jobId }: { jobId: string }) {
   
  const [timeline, setTimeline] = useState<JobTimelineEntry[]>([]);
   
  const [job, setJob] = useState<Job | null>(null);
   
  const [loading, setLoading] = useState(true);
   
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
   
      const [timelineRes, jobRes] = await Promise.allSettled([
        getJobTimeline(jobId),
        getJob(jobId),
      ]);
      if (timelineRes.status === 'fulfilled') {
        setTimeline(timelineRes.value.timeline?.map((e: Partial<JobTimelineEntry> & { module?: string; title?: string }) => ({
          timestamp: e.timestamp || '',
          stage: e.stage || e.module || 'unknown',
          stage_label: e.stage_label || e.title || '',
          event: e.title || e.event || '',
        })) || []);
      }
      if (jobRes.status === 'fulfilled' && jobRes.value) setJob(jobRes.value);
      if (timelineRes.status === 'rejected') setError((timelineRes.reason as Error).message);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
   
  }, [jobId]);

   
  useEffect(() => { fetchData(); }, [fetchData]);

  if (loading) return <div className="p-4 text-muted">Loading timeline...</div>;
  if (error) return <div className="card error"><p>Error: {error}</p><button className="btn btn-sm btn-primary mt-2" onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLElement).click()} onClick={fetchData}>Retry</button></div>;
  if (timeline.length === 0) return <div className="card empty"><p>No timeline data available for this job.</p></div>;

  return (
    <div className="job-timeline">
      {job && (
        <div className="flex items-center gap-4 mb-4">
          <h3 className="font-semibold">Job: {job.base_url}</h3>
          <span className={`text-xs px-2 py-1 rounded ${job.status === 'completed' ? 'bg-green-900/30 text-green-400' : job.status === 'failed' ? 'bg-red-900/30 text-red-400' : job.status === 'running' ? 'bg-blue-900/30 text-blue-400' : 'bg-gray-900/30 text-gray-400'}`}>
            {job.status}
          </span>
        </div>
      )}
      <div className="relative pl-8 space-y-3">
  // eslint-disable-next-line security/detect-object-injection
        <div className="absolute left-3 top-0 bottom-0 w-0.5 bg-[#1f2937]" />
        {timeline.map((entry, i) => {
          const colorKey = entry.stage?.toLowerCase() || 'default';
  // eslint-disable-next-line security/detect-object-injection
          const color = STAGE_COLORS[colorKey] || STAGE_COLORS.default;
          return (
            <div key={i} className="relative">
  // eslint-disable-next-line security/detect-object-injection
              <div className={`absolute left-[-20px] top-1.5 w-2.5 h-2.5 rounded-full ${color}`} />
  // eslint-disable-next-line security/detect-object-injection
              <div className="card p-3 border border-[#1f2937]">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-sm font-medium">{entry.event || entry.stage_label}</span>
                    {entry.stage && <span className="ml-2 text-xs text-muted capitalize">({entry.stage})</span>}
                  </div>
                  <span className="text-xs text-muted">{entry.timestamp}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
