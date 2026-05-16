import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  Target,
  Zap,
  Activity,
  Server
} from 'lucide-react';
import type { DashboardStats as StatsType, Job } from '../types/api';
import { useApi } from '../hooks/useApi';
import { DashboardStatsSchema } from '../api/schemas';
import FindingsOverview from '../components/FindingsOverview';

export function DashboardPage() {
  const { data: stats } = useApi<StatsType>('/api/dashboard', { 
    refetchInterval: 10000,
    schema: DashboardStatsSchema
  });
  
  const { data: jobsResponse } = useApi<{ jobs: Job[]; total: number }>('/api/jobs', {
    refetchInterval: 5000,
  });

  const recentJobs = (jobsResponse?.jobs ?? []).slice(0, 5);

  const activeJobsCount = (jobsResponse?.jobs ?? []).filter(j => j.status === 'running').length || 0;
  const criticalFindings = stats?.findings_summary?.severity_totals?.critical || 0;
  const totalFindings = stats?.findings_summary?.total_findings || 0;
  const totalTargets = stats?.total_targets || 0;

  return (
    <div className="space-y-6">
      <div className="page-header">
        <div>
          <h2 className="section-title mb-1">Dashboard</h2>
          <p className="page-subtitle">Security Operations Overview</p>
        </div>
        <div className="flex gap-3">
           <Link to="/targets" className="btn btn-primary">
              <Zap size={16} /> New Scan
           </Link>
        </div>
      </div>

      {/* ── KPI Row ────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-muted">Total Targets</span>
            <Target size={16} className="text-muted" />
          </div>
          <div className="text-2xl font-semibold text-text">{totalTargets}</div>
        </div>
        
        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-muted">Active Scans</span>
            <Activity size={16} className="text-accent" />
          </div>
          <div className="text-2xl font-semibold text-text">{activeJobsCount}</div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-muted">Open Findings</span>
            <ShieldAlert size={16} className={criticalFindings > 0 ? 'text-bad' : 'text-muted'} />
          </div>
          <div className="flex items-end gap-3">
            <span className="text-2xl font-semibold text-text">{totalFindings}</span>
            {criticalFindings > 0 && (
              <span className="text-xs font-medium text-bad mb-1">{criticalFindings} Critical</span>
            )}
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-muted">System Health</span>
            <Server size={16} className="text-ok" />
          </div>
          <div className="text-2xl font-semibold text-ok">Optimal</div>
        </div>
      </div>

      {/* ── Severity Breakdown & Score ──────────────────────────── */}
      <FindingsOverview />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Recent Activity Timeline */}
        <div className="lg:col-span-2">
          <section className="card">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-sm font-semibold text-text">Recent Pipeline Jobs</h3>
              <Link to="/jobs" className="text-xs font-medium text-accent hover:text-accent-2 transition-colors">View All</Link>
            </div>
            
            <div className="space-y-4">
              {recentJobs.length === 0 ? (
                <div className="py-8 text-center text-muted text-sm">No recent jobs found</div>
              ) : recentJobs.map(job => (
                <Link 
                  key={job.id} 
                  to={`/jobs/${job.id}`}
                  className="flex items-center gap-4 p-3 hover:bg-surface-2 rounded-lg border border-transparent hover:border-border transition-colors group"
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
  // eslint-disable-next-line security/detect-object-injection
                    <div className="text-[11px] text-muted uppercase tracking-wide">{job.stage_label || job.stage}</div>
                  </div>

                  <div className="w-24 md:w-32 h-1.5 bg-surface-3 rounded-full overflow-hidden shrink-0">
                    <div 
                      className={`h-full transition-all ${job.status === 'failed' ? 'bg-bad' : job.status === 'completed' ? 'bg-ok' : 'bg-accent'}`} 
                      style={{ width: `${job.progress_percent}%` }} 
                    />
                  </div>
                </Link>
              ))}
            </div>
          </section>
        </div>

        {/* Right Column: Alerts & Actions */}
        <div className="space-y-6">
          <section className={`card ${criticalFindings > 0 ? 'border-bad bg-bad/5' : ''}`}>
            <h3 className={`text-sm font-semibold mb-4 flex items-center gap-2 ${criticalFindings > 0 ? 'text-bad' : 'text-text'}`}>
              <ShieldAlert size={16} /> Critical Alerts
            </h3>
            <div className="space-y-4">
              {criticalFindings > 0 ? (
                <div>
                   <p className="text-sm text-text leading-relaxed">Multiple critical findings detected. Immediate review required.</p>
                   <Link to="/findings?severity=critical" className="inline-block mt-3 text-xs font-medium text-bad hover:underline">Review Findings →</Link>
                </div>
              ) : (
                <div className="py-4 text-center text-sm text-muted">
                  No critical alerts at this time.
                </div>
              )}
            </div>
          </section>

          <section className="card">
            <h3 className="text-sm font-semibold text-text mb-4">Quick Actions</h3>
            <div className="space-y-2">
              {[
                { label: 'Review Findings', icon: ShieldAlert, href: '/findings' },
                { label: 'View Pipeline Overview', icon: Activity, href: '/pipeline' },
              ].map(action => (
                <Link 
                  key={action.label} 
                  to={action.href}
                  className="flex items-center justify-between p-3 rounded-lg border border-border hover:border-accent hover:bg-surface-2 transition-all group"
                >
                  <div className="flex items-center gap-3">
                    <action.icon size={16} className="text-muted group-hover:text-accent transition-colors" />
                    <span className="text-sm font-medium text-text transition-colors">{action.label}</span>
                  </div>
                </Link>
              ))}
            </div>
          </section>
        </div>

      </div>
    </div>
  );
}
