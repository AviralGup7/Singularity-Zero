import { useState, useMemo } from 'react';

interface RemediationEntry {
  id: string;
  findingType: string;
  severity: string;
  target: string;
  detectedAt: string;
  remediatedAt?: string;
  status: 'open' | 'in-progress' | 'remediated' | 'accepted';
  timeToRemediate?: number;
}

interface RemediationTrackerProps {
  entries: RemediationEntry[];
}

export function RemediationTracker({ entries }: RemediationTrackerProps) {
   
  const [filter, setFilter] = useState<string>('all');
   
  const [sortBy, setSortBy] = useState<'date' | 'severity' | 'time'>('date');

  const filtered = useMemo(() => {
    let result = entries;
    if (filter !== 'all') {
      result = entries.filter(e => e.status === filter);
    }
    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
   
    return [...result].sort((a, b) => {
   
      if (sortBy === 'severity') return (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5);
      if (sortBy === 'time') return (b.timeToRemediate || Infinity) - (a.timeToRemediate || Infinity);
      return new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime();
    });
   
  }, [entries, filter, sortBy]);

  const stats = useMemo(() => {
    const total = entries.length;
    const remediated = entries.filter(e => e.status === 'remediated').length;
    const open = entries.filter(e => e.status === 'open').length;
    const inProgress = entries.filter(e => e.status === 'in-progress').length;
    const accepted = entries.filter(e => e.status === 'accepted').length;
    const remediationTimes = entries.filter(e => e.timeToRemediate).map(e => e.timeToRemediate!);
    const avgTime = remediationTimes.length > 0
      ? Math.round(remediationTimes.reduce((a, b) => a + b, 0) / remediationTimes.length)
      : 0;
    const rate = total > 0 ? Math.round((remediated / total) * 100) : 0;
    return { total, remediated, open, inProgress, accepted, avgTime, rate };
   
  }, [entries]);


  return (
    <div className="remediation-tracker">
      <h3 className="remediation-title" data-focus-heading>🔧 Remediation Tracker</h3>

      <div className="remediation-stats">
        <div className="rem-stat">
          <span className="rem-stat-value">{stats.total}</span>
          <span className="rem-stat-label">Total</span>
        </div>
        <div className="rem-stat rem-stat-open">
          <span className="rem-stat-value">{stats.open}</span>
          <span className="rem-stat-label">Open</span>
        </div>
        <div className="rem-stat rem-stat-progress">
          <span className="rem-stat-value">{stats.inProgress}</span>
          <span className="rem-stat-label">In Progress</span>
        </div>
        <div className="rem-stat rem-stat-remediated">
          <span className="rem-stat-value">{stats.remediated}</span>
          <span className="rem-stat-label">Remediated</span>
        </div>
        <div className="rem-stat rem-stat-rate">
          <span className="rem-stat-value">{stats.rate}%</span>
          <span className="rem-stat-label">Remediation Rate</span>
        </div>
        <div className="rem-stat rem-stat-time">
          <span className="rem-stat-value">{stats.avgTime}d</span>
          <span className="rem-stat-label">Avg Time to Remediate</span>
        </div>
      </div>

      <div className="remediation-rate-bar">
        <div className="remediation-rate-fill" style={{ width: `${stats.rate}%` }} />
        <span className="remediation-rate-label">{stats.rate}% Remediated</span>
      </div>

      <div className="remediation-filters">
        <div className="rem-filter-group">
          <label>Status:</label>
  // eslint-disable-next-line security/detect-object-injection
          {['all', 'open', 'in-progress', 'remediated', 'accepted'].map(s => (
            <button
              key={s}
              className={`rem-filter-btn ${filter === s ? 'active' : ''}`}
              onClick={() => setFilter(s)}
            >
              {s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1).replace('-', ' ')}
            </button>
          ))}
        </div>
        <div className="rem-filter-group">
          <label>Sort:</label>
          <select
            className="form-select rem-sort-select"
            value={sortBy}
            onChange={e => setSortBy(e.target.value as 'date' | 'severity' | 'time')}
          >
            <option value="date">Date Detected</option>
            <option value="severity">Severity</option>
            <option value="time">Time to Remediate</option>
          </select>
        </div>
      </div>

      <div className="remediation-timeline">
        {filtered.length === 0 ? (
          <div className="rem-empty">No entries matching the current filter.</div>
        ) : (
          filtered.map(entry => (
            <div key={entry.id} className={`rem-timeline-item rem-status-${entry.status}`}>
              <div className="rem-timeline-dot" />
              <div className="rem-timeline-content">
                <div className="rem-timeline-header">
                  <span className={`severity-badge sev-${entry.severity}`}>{entry.severity}</span>
                  <span className="rem-timeline-type">{entry.findingType}</span>
                  <span className={`rem-status-badge rem-status-${entry.status}`}>{entry.status}</span>
                </div>
                <div className="rem-timeline-target">{entry.target}</div>
                <div className="rem-timeline-dates">
                  <span className="rem-date">Detected: {entry.detectedAt}</span>
                  {entry.remediatedAt && (
                    <span className="rem-date rem-date-resolved">Resolved: {entry.remediatedAt}</span>
                  )}
                  {entry.timeToRemediate && (
                    <span className="rem-time-remediate">Time: {entry.timeToRemediate} days</span>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
