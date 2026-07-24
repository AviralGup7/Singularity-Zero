import { useState, useCallback } from 'react';
import { listAccessLogs  } from '@/api/accessLogs';
import { getComplianceLogs, exportComplianceReport  } from '@/utils/complianceLogger';
import { Button } from '@/components/ui/Button';
import { useLogFetcher, LogTableShell } from '@/components/common/TelemetryLogTable';

export function ComplianceLogViewer() {
  const [filter, setFilter] = useState<'all' | 'success' | 'failure' | 'denied'>('all');

  const { data: logs, loading } = useLogFetcher(
    useCallback(async () => {
      try {
        return await listAccessLogs({ limit: 200 });
      } catch {
        return getComplianceLogs();
      }
    }, [])
  );

  const filteredLogs = filter === 'all' ? logs : logs.filter((l) => l.outcome === filter);

  const handleExport = (format: 'json' | 'csv') => {
    const data = exportComplianceReport(format);
   
    const blob = new Blob([data], { type: format === 'csv' ? 'text/csv' : 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `compliance-report.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  };



  return (
    <div className="compliance-log-viewer">
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-mono text-accent text-sm font-bold uppercase tracking-wider">
          Compliance Log ({filteredLogs.length})
        </h3>
        <div className="flex gap-1">
          <Button variant="ghost" onClick={() => handleExport('json')} className="text-xs">
            Export JSON
          </Button>
          <Button variant="ghost" onClick={() => handleExport('csv')} className="text-xs">
            Export CSV
          </Button>
        </div>
      </div>

      <div className="flex gap-2 mb-3" role="tablist" aria-label="Compliance log filters">
        {(['all', 'success', 'failure', 'denied'] as const).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            role="tab"
            aria-selected={filter === f}
            className={`px-2 py-0.5 text-xs font-mono border transition-colors ${
              filter === f
                ? 'border-accent text-accent bg-accent/10'
                : 'border-line text-muted hover:text-text'
            }`}
          >
            {f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
      </div>

      <LogTableShell loading={loading} isEmpty={filteredLogs.length === 0} loadingLabel="Loading access logs..." emptyLabel="No compliance entries.">
        <div className="max-h-96 overflow-y-auto space-y-2 pr-2 scrollbar-cyber" role="list" aria-label="Compliance log entries">
          {filteredLogs.map((entry) => (
            <div key={entry.id} className="p-3 bg-surface-hover border border-line rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-2" role="listitem">
              <div className="flex items-start gap-3">
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider ${
                  entry.outcome === 'success' ? 'bg-green-500/20 text-green-400' :
                  entry.outcome === 'denied' ? 'bg-red-500/20 text-red-400' : 'bg-yellow-500/20 text-yellow-400'
                }`} aria-label={`Outcome: ${entry.outcome}`}>
                  {entry.outcome}
                </span>
                <div>
                  <div className="text-text text-xs">
                    <span className="font-bold">{entry.action}</span>
                    {' '}on{' '}
                    <span className="text-accent">{entry.resource}</span>
                  </div>
                  <div className="text-muted text-[10px] mt-1">
                    {entry.reason} — by <span className="text-text/60 font-mono">{entry.user}</span>
                  </div>
                </div>
              </div>
              <time className="text-muted text-[9px] font-mono whitespace-nowrap" dateTime={entry.timestamp}>
                {new Date(entry.timestamp).toLocaleString()}
              </time>
            </div>
          ))}
        </div>
      </LogTableShell>
    </div>
  );
}
